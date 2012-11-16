/*
 * Get/set/delete fdb table with netlink
 *
 * TODO: merge/replace this with ip neighbour
 *
 * Authors:	Stephen Hemminger <shemminger@vyatta.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include <linux/neighbour.h>
#include <string.h>

#include "libnetlink.h"
#include "br_common.h"
#include "rt_names.h"
#include "utils.h"

int filter_index;

static void usage(void)
{
	fprintf(stderr, "Usage: bridge fdb { add | del } ADDR dev DEV {self|master} [ temp ] [ dst IPADDR]\n");
	fprintf(stderr, "       bridge fdb {show} [ dev DEV ]\n");
	exit(-1);
}

static void bridge_usage(void)
{
	fprintf(stderr, "Usage: bridge bridge mode {veb | vepa} dev DEV\n");
	fprintf(stderr, "	bridge bridge {show} [ dev DEV] \n");
	exit(-1);
}

static const char *state_n2a(unsigned s)
{
	static char buf[32];

	if (s & NUD_PERMANENT)
		return "permanent";

	if (s & NUD_NOARP)
		return "static";

	if (s & NUD_STALE)
		return "stale";

	if (s & NUD_REACHABLE)
		return "";

	sprintf(buf, "state=%#x", s);
	return buf;
}

int print_fdb(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	FILE *fp = arg;
	struct ndmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr * tb[NDA_MAX+1];

	if (n->nlmsg_type != RTM_NEWNEIGH && n->nlmsg_type != RTM_DELNEIGH) {
		fprintf(stderr, "Not RTM_NEWNEIGH: %08x %08x %08x\n",
			n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);

		return 0;
	}

	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	if (r->ndm_family != AF_BRIDGE)
		return 0;

	if (filter_index && filter_index != r->ndm_ifindex)
		return 0;

	parse_rtattr(tb, NDA_MAX, NDA_RTA(r),
		     n->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	if (n->nlmsg_type == RTM_DELNEIGH)
		fprintf(fp, "Deleted ");

	if (tb[NDA_LLADDR]) {
		SPRINT_BUF(b1);
		fprintf(fp, "%s ",
			ll_addr_n2a(RTA_DATA(tb[NDA_LLADDR]),
				    RTA_PAYLOAD(tb[NDA_LLADDR]),
				    ll_index_to_type(r->ndm_ifindex),
				    b1, sizeof(b1)));
	}

	if (!filter_index && r->ndm_ifindex)
		fprintf(fp, "dev %s ", ll_index_to_name(r->ndm_ifindex));

	if (tb[NDA_DST]) {
		SPRINT_BUF(abuf);
		fprintf(fp, "dst %s ",
			format_host(AF_INET,
				    RTA_PAYLOAD(tb[NDA_DST]),
				    RTA_DATA(tb[NDA_DST]),
				    abuf, sizeof(abuf)));
	}

	if (show_stats && tb[NDA_CACHEINFO]) {
		struct nda_cacheinfo *ci = RTA_DATA(tb[NDA_CACHEINFO]);
		int hz = get_user_hz();

		fprintf(fp, " used %d/%d", ci->ndm_used/hz,
		       ci->ndm_updated/hz);
	}
	if (r->ndm_flags & NTF_SELF)
		fprintf(fp, "self ");
	if (r->ndm_flags & NTF_MASTER)
		fprintf(fp, "master ");

	fprintf(fp, "%s\n", state_n2a(r->ndm_state));
	return 0;
}

static int fdb_show(int argc, char **argv)
{
	char *filter_dev = NULL;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			if (filter_dev)
				duparg("dev", *argv);
			filter_dev = *argv;
		}
		argc--; argv++;
	}

	if (filter_dev) {
		filter_index = if_nametoindex(filter_dev);
		if (filter_index == 0) {
			fprintf(stderr, "Cannot find device \"%s\"\n",
				filter_dev);
			return -1;
		}
	}

	if (rtnl_wilddump_request(&rth, PF_BRIDGE, RTM_GETNEIGH) < 0) {
		perror("Cannot send dump request");
		exit(1);
	}

	if (rtnl_dump_filter(&rth, print_fdb, stdout) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(1);
	}

	return 0;
}

static int fdb_modify(int cmd, int flags, int argc, char **argv)
{
	struct {
		struct nlmsghdr 	n;
		struct ndmsg 		ndm;
		char   			buf[256];
	} req;
	char *addr = NULL;
	char *d = NULL;
	char abuf[ETH_ALEN];
	int dst_ok = 0;
	inet_prefix dst;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST|flags;
	req.n.nlmsg_type = cmd;
	req.ndm.ndm_family = PF_BRIDGE;
	req.ndm.ndm_state = NUD_NOARP;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			d = *argv;
		} else if (strcmp(*argv, "dst") == 0) {
			NEXT_ARG();
			if (dst_ok)
				duparg2("dst", *argv);
			get_addr(&dst, *argv, preferred_family);
			dst_ok = 1;
		} else if (strcmp(*argv, "self") == 0) {
			req.ndm.ndm_flags |= NTF_SELF;
		} else if (matches(*argv, "master") == 0) {
			req.ndm.ndm_flags |= NTF_MASTER;
		} else if (matches(*argv, "local") == 0||
			   matches(*argv, "permanent") == 0) {
			req.ndm.ndm_state |= NUD_PERMANENT;
		} else if (matches(*argv, "temp") == 0) {
			req.ndm.ndm_state |= NUD_REACHABLE;
		} else {
			if (strcmp(*argv, "to") == 0) {
				NEXT_ARG();
			}
			if (matches(*argv, "help") == 0)
				usage();
			if (addr)
				duparg2("to", *argv);
			addr = *argv;
		}
		argc--; argv++;
	}

	if (d == NULL || addr == NULL) {
		fprintf(stderr, "Device and address are required arguments.\n");
		exit(-1);
	}

	/* Assume self */
	if (!(req.ndm.ndm_flags&(NTF_SELF|NTF_MASTER)))
		req.ndm.ndm_flags |= NTF_SELF;

	/* Assume permanent */
	if (!(req.ndm.ndm_state&(NUD_PERMANENT|NUD_REACHABLE)))
		req.ndm.ndm_state |= NUD_PERMANENT;

	if (sscanf(addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   abuf, abuf+1, abuf+2,
		   abuf+3, abuf+4, abuf+5) != 6) {
		fprintf(stderr, "Invalid mac address %s\n", addr);
		exit(-1);
	}

	addattr_l(&req.n, sizeof(req), NDA_LLADDR, abuf, ETH_ALEN);
	if (dst_ok)
		addattr_l(&req.n, sizeof(req), NDA_DST, &dst.data, dst.bytelen);

	req.ndm.ndm_ifindex = ll_name_to_index(d);
	if (req.ndm.ndm_ifindex == 0) {
		fprintf(stderr, "Cannot find device \"%s\"\n", d);
		return -1;
	}

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL) < 0)
		exit(2);

	return 0;
}

int do_fdb(int argc, char **argv)
{
	ll_init_map(&rth);

	if (argc > 0) {
		if (matches(*argv, "add") == 0)
			return fdb_modify(RTM_NEWNEIGH, NLM_F_CREATE|NLM_F_EXCL, argc-1, argv+1);
		if (matches(*argv, "delete") == 0)
			return fdb_modify(RTM_DELNEIGH, 0, argc-1, argv+1);
		if (matches(*argv, "show") == 0 ||
		    matches(*argv, "lst") == 0 ||
		    matches(*argv, "list") == 0)
			return fdb_show(argc-1, argv+1);
		if (matches(*argv, "help") == 0)
			usage();
	} else
		return fdb_show(0, NULL);

	fprintf(stderr, "Command \"%s\" is unknown, try \"bridge fdb help\".\n", *argv);
	exit(-1);
}

int print_bridge(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	FILE *fp = arg;
	struct ifinfomsg *ifm = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr * tb[IFLA_MAX+1];
       
	len -= NLMSG_LENGTH(sizeof(*ifm));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	if (ifm->ifi_family != AF_BRIDGE) {
		fprintf(stderr, "hmm: Not PF_BRIDGE is %i\n", ifm->ifi_family);
	}

	if (filter_index && filter_index != ifm->ifi_index)
		return 0;

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifm), len);

	if (!tb[IFLA_IFNAME]) {
		fprintf(stderr, "%s: missing ifname using ifi_index %u name %s\n",
			__func__, ifm->ifi_index,
			ll_index_to_name(ifm->ifi_index));
	}
	if (tb[IFLA_AF_SPEC]) {
		struct rtattr *bridge[IFLA_BRIDGE_MAX+1];
		__u16 mode = 0, flags = 0;

		parse_rtattr_nested(bridge, IFLA_BRIDGE_MAX, tb[IFLA_AF_SPEC]);
		if (bridge[IFLA_BRIDGE_MODE])
			mode =*(__u16*)RTA_DATA(bridge[IFLA_BRIDGE_MODE]);
		if (bridge[IFLA_BRIDGE_FLAGS])
			flags =*(__u16*)RTA_DATA(bridge[IFLA_BRIDGE_FLAGS]);

		fprintf(stderr, "%s: mode %s bridge_flags: %s %s\n",
			ll_index_to_name(ifm->ifi_index),
			mode ? "VEPA" : "VEB",
			flags & BRIDGE_FLAGS_SELF ? "self" : "",
			flags & BRIDGE_FLAGS_MASTER ? "master" : "");
	}

	if (tb[IFLA_PROTINFO]) {
		__u8 state = *(__u8*)RTA_DATA(tb[IFLA_PROTINFO]);
		char *sstate;

		switch (state) {
		case 0:
			sstate = "DISABLED";
			break;
		case 1:
			sstate = "LISTENING";
			break;
		case 2:
			sstate = "LEARNING";
			break;
		case 3:
			sstate = "FORWARDING";
			break;
		case 4:
			sstate = "BLOCKING";
			break;
		default:
			sstate = "UNKNOWN";
			break;
		}
	

		fprintf(stderr, "%s: %s: ifla_protinfo: %s\n",
			ll_index_to_name(ifm->ifi_index),
			__func__, sstate);
	}

	fflush(fp);
	return 0;
}

static int bridge_show(int argc, char **argv)
{
	char *filter_dev = NULL;

       
	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			if (filter_dev)
				duparg("dev", *argv);
                       
			filter_dev = *argv;
		}
		argc--; argv++;
	}

	if (filter_dev) {
		if ((filter_index = if_nametoindex(filter_dev)) == 0) {
			fprintf(stderr, "Cannot find device \"%s\"\n", filter_dev);
			return -1;
		}
	}

	if (rtnl_wilddump_request(&rth, PF_BRIDGE, RTM_GETLINK) < 0) {
		perror("Cannot send dump request");
		exit(1);
	}

	if (rtnl_dump_filter(&rth, print_bridge, stdout) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(1);
	}

	return 0;
}

static int bridge_state_set(int argc, char **argv)
{
	struct {
		struct nlmsghdr		n;
		struct ifinfomsg	ifm;
		char			buf[1024];
	} req;
	struct {
		struct nlmsghdr		hdr;
		struct nlmsgerr		err;
		struct nlmsghdr		rhdr;
		struct ifinfomsg	ifm;
		char			buf[1024];
	} reply;
	char *d = NULL;
	__u8 state = -1; //BRIDGE_MODE_VEB;
	__u16 mode = 0, flags = 0; //BRIDGE_MODE_VEB;
	
	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_ACK;
	req.n.nlmsg_type = RTM_SETLINK;
	req.ifm.ifi_family = PF_BRIDGE;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			d = *argv;	
		} else if (matches(*argv, "state") == 0) {
			NEXT_ARG();
			printf("%s: arg matched state: %s\n", __func__, *argv);
			if (matches(*argv, "DISABLED") == 0)
				state = 0;
			else if (matches(*argv, "LISTENING") == 0)
				 state = 1;
			else if (matches(*argv, "LEARNING") == 0)
				 state = 2;
			else if (matches(*argv, "FORWARDING") == 0)
				 state = 3;
			else if (matches(*argv, "BLOCKING") == 0)
				 state = 4;
			else
				invarg("Invalid state value\n", *argv);

		} else if (matches(*argv, "mode") == 0) {
			NEXT_ARG();
			if (matches(*argv, "veb") == 0)
				mode = BRIDGE_MODE_VEB;
			else if (matches(*argv, "vepa") == 0)
				 mode = BRIDGE_MODE_VEPA;
			else
				invarg("Invalid mode value\n", *argv);

		} else if (matches(*argv, "master") == 0) {
			flags |= BRIDGE_FLAGS_MASTER;
		} else if (matches(*argv, "self") == 0) {
			flags |= BRIDGE_FLAGS_SELF;
		}

		argc--; argv++;
	}

	if (!d) {
		fprintf(stderr, "Device required.\n");
		exit(-1);
	}

       req.ifm.ifi_index = ll_name_to_index(d);
       if (req.ifm.ifi_index == 0) {
               fprintf(stderr, "Cannot find device \"%s\"\n", d);
               return -1;
       }

	if (state < 4)
		addattr8(&req.n, sizeof(req.buf), IFLA_PROTINFO, state);
       
	if (mode < 3 || flags) {
		struct rtattr *binfo;
		int err = 0;

		binfo = addattr_nest(&req.n, sizeof(req), IFLA_AF_SPEC);
		if (flags)
			err = addattr16(&req.n, sizeof(req), IFLA_BRIDGE_FLAGS, flags);
		if (mode < 3)
			err = addattr16(&req.n, sizeof(req), IFLA_BRIDGE_MODE, mode);
		if (err < 0)
			fprintf(stderr, "addattr16 failes\n");
		addattr_nest_end(&req.n, binfo);
       
		printf("%s %s(%u): type %i family %i mode %s\n", __func__, d, req.ifm.ifi_index,
			req.n.nlmsg_type, req.ifm.ifi_family,
			mode ? "VEPA" : "VEB");
	}

	printf("%s: %s(%u): rtnl_talk length %u\n", __func__, d, req.ifm.ifi_index, req.n.nlmsg_len);
	if (rtnl_talk(&rth, &req.n, 0, 0, &reply.hdr) < 0) {
		printf("\nREPLY: error %i\n", reply.err.error);
		print_bridge(NULL, &reply.err.msg, stderr);
		exit(2);
	}

	return 0;
}

int do_bridge(int argc, char **argv)
{
	ll_init_map(&rth);

	if (argc > 0) {
		if (matches(*argv, "show") == 0)
			return bridge_show(argc-1, argv+1);
		else if (matches(*argv, "state") == 0)
			return bridge_state_set(argc-1, argv+1);
		else if (matches(*argv, "help") == 0)
			bridge_usage();
	}

	exit(0);
}
