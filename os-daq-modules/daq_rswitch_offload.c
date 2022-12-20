/* SPDX-License-Identifier: GPL-2.0 */
/* DAQ module for offloading blacklist functionality
 * based on TC u32 offload for R-Switch device.
 *
 * Copyright (C) 2022 Renesas Electronics Corporation
 * Copyright (C) 2022 EPAM Systems
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/unistd.h>

#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/gen_stats.h>

#include <netinet/ip.h>
#include <pcap.h>

#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif

#include "daq_api.h"
#include "sfbpf.h"

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#include <linux/neighbour.h>
#include <linux/netconf.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <time.h>
#include <sys/uio.h>
#include <linux/fib_rules.h>
#include <linux/if_addrlabel.h>
#include <linux/if_bridge.h>
#include <linux/nexthop.h>
#include <stddef.h>
#include <ctype.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <linux/sockios.h>

#define DAQ_MOD_VERSION  (1)
#define DAQ_TYPE (DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_INLINE_CAPABLE | \
				  DAQ_TYPE_MULTI_INSTANCE | DAQ_TYPE_NO_UNPRIV)
#define IDXMAP_SIZE	(1024)
#define RTNL_HANDLE_F_SUPPRESS_NLERR (2)
#define MAX_MSG (16384)
#define TCA_GACT_PARMS (2)
#define IFLA_PROP_LIST (52)
#define IFLA_ALT_IFNAME (53)
#define IDXMAP_SIZE	(1024)
#define RTNL_SUPPRESS_NLMSG_ERROR_NLERR	(4)
#define RTNL_SUPPRESS_NLMSG_DONE_NLERR (2)
#define MAX_PREFS (1024)

#define MONDEV_NAME	"rmon"
#ifndef __aligned
#define __aligned(x)		__attribute__((aligned(x)))
#endif

#define L fprintf(stderr, "%s:%d\n", __func__, __LINE__)

#define hlist_for_each(pos, head) \
	for (pos = (head)->first; pos ; pos = pos->next)

#ifndef container_of
#define container_of(ptr, type, member) \
	(type *)((char *)(ptr) - (char *) &((type *)0)->member)
#endif

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, __typeof__(*(pos)), member)

#define list_for_each_entry(pos, head, member)						\
	for (pos = list_first_entry(head, __typeof__(*pos), member);	\
		 &pos->member != (head);									\
		 pos = list_next_entry(pos, member))

#define list_for_each_entry_safe(pos, n, head, member)				\
	for (pos = list_first_entry(head, __typeof__(*pos), member),	\
		n = list_next_entry(pos, member);							\
		 &pos->member != (head);									\
		 pos = n, n = list_next_entry(n, member))

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#define rtnl_dump_filter(rth, filter, arg) \
	rtnl_dump_filter_nc(rth, filter, arg, 0)

#define RTA_LENGTH(len)	(RTA_ALIGN(sizeof(struct rtattr)) + (len))

typedef int (*rtnl_filter_t)(struct nlmsghdr *n, void *);
typedef int (*rtnl_err_hndlr_t)(struct nlmsghdr *n, void *);
typedef int (*nl_ext_ack_fn_t)(const char *errmsg, uint32_t off,
				   const struct nlmsghdr *inner_nlh);

/*
 * Ethernet header
 */
struct __attribute__((__packed__)) ether_hdr {
	uint8_t ether_dst[6];
	uint8_t ether_src[6];
	uint16_t ether_type;
};

struct __attribute__((__packed__)) ip_v4_hdr {
	struct ether_hdr ether_hdr; /* ether header */
	uint8_t ip_verhl;	  /* version & header length */
	uint8_t ip_tos;		/* type of service */
	uint16_t ip_len;	   /* datagram length */
	uint16_t ip_id;		/* identification  */
	uint16_t ip_off;	   /* fragment offset */
	uint8_t ip_ttl;		/* time to live field */
	uint8_t ip_proto;	  /* datagram protocol */
	uint16_t ip_csum;	  /* checksum */
	uint32_t ip_src;  /* source IP */
	uint32_t ip_dst;  /* dest IP */
};

struct list_head;

struct list_head {
	struct list_head *next, *prev;
};

struct blacklist_data {
	uint32_t dst_ip;
	uint32_t src_ip;
	uint32_t pref;
	uint8_t proto;
	struct list_head list;
};

struct rswitch_context {
	unsigned snaplen;
	char error[DAQ_ERRBUF_SIZE];
	int cnt;

	DAQ_State state;
	DAQ_Stats_t stats;
	DAQ_Analysis_Func_t analysis_func;

	pcap_handler callback;
	pcap_t *handle;
	int packets;
	char *device;
	int promisc_flag;
	int timeout;
	int buffer_size;
	u_char *user_data;
	uint32_t netmask;
	struct list_head blacklist;
	pthread_t thread;
	atomic_int stop;
	uint8_t ether_addr[6];
};

#define TSN_NUM 3
struct rswitch_handle {

	struct rswitch_context contexts[TSN_NUM];
	struct rswitch_context mon_context;
};

struct rtnl_handle {
	int			fd;
	struct sockaddr_nl	local;
	struct sockaddr_nl	peer;
	__u32			seq;
	__u32		dump;
	int			proto;
	FILE		*dump_fp;
	int			flags;
};

struct hlist_node {
	struct hlist_node *next, **pprev;
};

struct hlist_head {
	struct hlist_node *first;
};

struct ll_cache {
	struct hlist_node idx_hash;
	struct hlist_node name_hash;
	unsigned	flags;
	unsigned 	index;
	unsigned short	type;
	struct list_head altnames_list;
	char		name[];
};

struct rtnl_dump_filter_arg {
	rtnl_filter_t filter;
	void *arg1;
	rtnl_err_hndlr_t errhndlr;
	void *arg2;
	__u16 nc_flags;
};

struct tc_gact {
	uint32_t	index;
	uint32_t	capab;
	int			action;
	int			refcnt;
	int			bindcnt
};
struct filter_prefs {
	int num;
	uint32_t prefs[MAX_PREFS];
};

static struct hlist_head idx_head[IDXMAP_SIZE];
static struct hlist_head name_head[IDXMAP_SIZE];
static int rcvbuf = 1024 * 1024;
static struct rtnl_handle rth;
static struct filter_prefs prefs_before, prefs_after;

static void blacklist_traffic(struct ip_v4_hdr *ip_hdr, struct rswitch_context *context);

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __list_add(struct list_head *new,
				  struct list_head *prev,
				  struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

static unsigned namehash(const char *str)
{
	unsigned hash = 5381;

	while (*str)
		hash = ((hash << 5) + hash) + *str++; /* hash * 33 + c */

	return hash;
}

static inline const char *rta_getattr_str(const struct rtattr *rta)
{
	return (const char *)RTA_DATA(rta);
}

/* No extended error ack without libmnl */
static int nl_dump_ext_ack(const struct nlmsghdr *nlh, nl_ext_ack_fn_t errfn)
{
	return 0;
}

static void rtnl_talk_error(struct nlmsghdr *h, struct nlmsgerr *err,
				nl_ext_ack_fn_t errfn)
{
	if (nl_dump_ext_ack(h, errfn))
		return;

	fprintf(stderr, "RTNETLINK answers: %s\n",
		strerror(-err->error));
}

static int __rtnl_recvmsg(int fd, struct msghdr *msg, int flags)
{
	int len;

	do {
		len = recvmsg(fd, msg, flags);
	} while (len < 0 && (errno == EINTR || errno == EAGAIN));

	if (len < 0) {
		fprintf(stderr, "netlink receive error %s (%d)\n",
			strerror(errno), errno);
		return -errno;
	}

	if (len == 0) {
		fprintf(stderr, "EOF on netlink\n");
		return -ENODATA;
	}

	return len;
}

static int rtnl_recvmsg(int fd, struct msghdr *msg, char **answer)
{
	struct iovec *iov = msg->msg_iov;
	char *buf;
	int len;

	iov->iov_base = NULL;
	iov->iov_len = 0;

	len = __rtnl_recvmsg(fd, msg, MSG_PEEK | MSG_TRUNC);
	if (len < 0)
		return len;

	if (len < 32768)
		len = 32768;
	buf = malloc(len);
	if (!buf) {
		fprintf(stderr, "malloc error: not enough buffer\n");
		return -ENOMEM;
	}

	iov->iov_base = buf;
	iov->iov_len = len;

	len = __rtnl_recvmsg(fd, msg, 0);
	if (len < 0) {
		free(buf);
		return len;
	}

	if (answer)
		*answer = buf;
	else
		free(buf);

	return len;
}

static int __rtnl_talk_iov(struct rtnl_handle *rtnl, struct iovec *iov,
			   size_t iovlen, struct nlmsghdr **answer,
			   bool show_rtnl_err, nl_ext_ack_fn_t errfn)
{
	struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
	struct iovec riov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = iov,
		.msg_iovlen = iovlen,
	};
	unsigned int seq = 0;
	struct nlmsghdr *h;
	int i, status;
	char *buf;

	for (i = 0; i < iovlen; i++) {
		h = iov[i].iov_base;
		h->nlmsg_seq = seq = ++rtnl->seq;
		if (answer == NULL)
			h->nlmsg_flags |= NLM_F_ACK;
	}

	status = sendmsg(rtnl->fd, &msg, 0);
	if (status < 0) {
		fprintf(stderr, "Cannot talk to rtnetlink\n");
		return -1;
	}

	/* change msg to use the response iov */
	msg.msg_iov = &riov;
	msg.msg_iovlen = 1;
	i = 0;
	while (1) {
next:
		status = rtnl_recvmsg(rtnl->fd, &msg, &buf);
		++i;

		if (status < 0)
			return status;

		if (msg.msg_namelen != sizeof(nladdr)) {
			fprintf(stderr,
				"sender address length == %d\n",
				msg.msg_namelen);
			exit(1);
		}
		for (h = (struct nlmsghdr *)buf; status >= sizeof(*h); ) {
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);

			if (l < 0 || len > status) {
				if (msg.msg_flags & MSG_TRUNC) {
					fprintf(stderr, "Truncated message\n");
					free(buf);
					return -1;
				}
				fprintf(stderr,
					"!!!malformed message: len=%d\n",
					len);
				exit(1);
			}

			if (nladdr.nl_pid != 0 ||
				h->nlmsg_pid != rtnl->local.nl_pid ||
				h->nlmsg_seq > seq || h->nlmsg_seq < seq - iovlen) {
				/* Don't forget to skip that message. */
				status -= NLMSG_ALIGN(len);
				h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
				continue;
			}

			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);
				int error = err->error;

				if (l < sizeof(struct nlmsgerr)) {
					fprintf(stderr, "ERROR truncated\n");
					free(buf);
					return -1;
				}

				if (!error) {
					/* check messages from kernel */
					nl_dump_ext_ack(h, errfn);
				} else {
					errno = -error;

					if (rtnl->proto != NETLINK_SOCK_DIAG &&
						show_rtnl_err)
						rtnl_talk_error(h, err, errfn);
				}

				if (answer)
					*answer = (struct nlmsghdr *)buf;
				else
					free(buf);

				if (i < iovlen)
					goto next;
				return error ? -i : 0;
			}

			if (answer) {
				*answer = (struct nlmsghdr *)buf;
				return 0;
			}

			fprintf(stderr, "Unexpected reply!!!\n");

			status -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
		}
		free(buf);

		if (msg.msg_flags & MSG_TRUNC) {
			fprintf(stderr, "Message truncated\n");
			continue;
		}

		if (status) {
			fprintf(stderr, "!!!Remnant of size %d\n", status);
			exit(1);
		}
	}
}


static int __rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n,
			   struct nlmsghdr **answer,
			   bool show_rtnl_err, nl_ext_ack_fn_t errfn)
{
	struct iovec iov = {
		.iov_base = n,
		.iov_len = n->nlmsg_len
	};

	return __rtnl_talk_iov(rtnl, &iov, 1, answer, show_rtnl_err, errfn);
}


static int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n,
		  struct nlmsghdr **answer)
{
	return __rtnl_talk(rtnl, n, answer, true, NULL);
}

static void rtnl_close(struct rtnl_handle *rth)
{
	if (rth->fd >= 0) {
		close(rth->fd);
		rth->fd = -1;
	}
}

static int rtnl_open_byproto(struct rtnl_handle *rth, unsigned int subscriptions,
			  int protocol)
{
	socklen_t addr_len;
	int sndbuf = 32768;
	int one = 1;

	memset(rth, 0, sizeof(*rth));

	rth->proto = protocol;
	rth->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol);
	if (rth->fd < 0) {
		fprintf(stderr, "Cannot open netlink socket\n");
		return -1;
	}

	if (setsockopt(rth->fd, SOL_SOCKET, SO_SNDBUF,
			   &sndbuf, sizeof(sndbuf)) < 0) {
		fprintf(stderr, "SO_SNDBUF\n");
		goto err;
	}

	if (setsockopt(rth->fd, SOL_SOCKET, SO_RCVBUF,
			   &rcvbuf, sizeof(rcvbuf)) < 0) {
		fprintf(stderr, "SO_RCVBUF\n");
		goto err;
	}

	/* Older kernels may no support extended ACK reporting */
	setsockopt(rth->fd, SOL_NETLINK, NETLINK_EXT_ACK,
		   &one, sizeof(one));

	memset(&rth->local, 0, sizeof(rth->local));
	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = subscriptions;

	if (bind(rth->fd, (struct sockaddr *)&rth->local,
		 sizeof(rth->local)) < 0) {
		fprintf(stderr, "Cannot bind netlink socket\n");
		goto err;
	}
	addr_len = sizeof(rth->local);
	if (getsockname(rth->fd, (struct sockaddr *)&rth->local,
			&addr_len) < 0) {
		fprintf(stderr, "Cannot getsockname\n");
		goto err;
	}
	if (addr_len != sizeof(rth->local)) {
		fprintf(stderr, "Wrong address length %d\n", addr_len);
		goto err;
	}
	if (rth->local.nl_family != AF_NETLINK) {
		fprintf(stderr, "Wrong address family %d\n",
			rth->local.nl_family);
		goto err;
	}
	rth->seq = time(NULL);
	return 0;
err:
	rtnl_close(rth);
	return -1;
}

static int rtnl_open(struct rtnl_handle *rth, unsigned int subscriptions)
{
	return rtnl_open_byproto(rth, subscriptions, NETLINK_ROUTE);
}

static int addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
	nest->rta_len = (void *)NLMSG_TAIL(n) - (void *)nest;
	return n->nlmsg_len;
}

int get_eth_addr(char *ifname, char eth_addr[6]) {

  struct ifreq ifr;
  int sock;


  sock=socket(AF_INET,SOCK_DGRAM,0);
  strcpy( ifr.ifr_name, ifname );
  ifr.ifr_addr.sa_family = AF_INET;

  if (ioctl( sock, SIOCGIFHWADDR, &ifr ) < 0) {
    return -1;
  }

  memcpy(eth_addr, ifr.ifr_hwaddr.sa_data, 6);
  close(sock);

  return 0;

}

static int pack_key(struct tc_u32_sel *sel, uint32_t key, uint32_t mask,
			int off, int offmask)
{
	int i;
	int hwm = sel->nkeys;

	key &= mask;

	for (i = 0; i < hwm; i++) {
		if (sel->keys[i].off == off && sel->keys[i].offmask == offmask) {
			uint32_t intersect = mask & sel->keys[i].mask;

			if ((key ^ sel->keys[i].val) & intersect)
				return -1;
			sel->keys[i].val |= key;
			sel->keys[i].mask |= mask;

			return 0;
		}
	}

	if (hwm >= 128)
		return -1;

	if (off % 4)
		return -1;

	sel->keys[hwm].val = key;
	sel->keys[hwm].mask = mask;
	sel->keys[hwm].off = off;
	sel->keys[hwm].offmask = offmask;
	sel->nkeys++;

	return 0;
}

static int pack_key32(struct tc_u32_sel *sel, uint32_t key, uint32_t mask,
			  int off, int offmask)
{
	return pack_key(sel, key, mask, off, offmask);
}

static int pack_key8(struct tc_u32_sel *sel, uint32_t key, uint32_t mask, int off,
			 int offmask)
{
	if (key > 0xFF || mask > 0xFF)
		return -1;

	if ((off & 3) == 0) {
		key <<= 24;
		mask <<= 24;
	} else if ((off & 3) == 1) {
		key <<= 16;
		mask <<= 16;
	} else if ((off & 3) == 2) {
		key <<= 8;
		mask <<= 8;
	}
	off &= ~3;
	key = htonl(key);
	mask = htonl(mask);

	return pack_key(sel, key, mask, off, offmask);
}

static int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
		  int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		fprintf(stderr,
			"addattr_l ERROR: message exceeded bound of %d\n",
			maxlen);
		return -1;
	}
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	if (alen)
		memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}

static int rtnl_linkdump_req_filter(struct rtnl_handle *rth, int family,
				__u32 filt_mask)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
		/* attribute has to be NLMSG aligned */
		struct rtattr ext_req __aligned(NLMSG_ALIGNTO);
		__u32 ext_filter_mask;
	} req = {
		.nlh.nlmsg_len = sizeof(req),
		.nlh.nlmsg_type = RTM_GETLINK,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_seq = rth->dump = ++rth->seq,
		.ifm.ifi_family = family,
		.ext_req.rta_type = IFLA_EXT_MASK,
		.ext_req.rta_len = RTA_LENGTH(sizeof(__u32)),
		.ext_filter_mask = filt_mask,
	};

	return send(rth->fd, &req, sizeof(req), 0);
}

static int rtnl_linkdump_req(struct rtnl_handle *rth, int family)
{
	return rtnl_linkdump_req_filter(rth, family, RTEXT_FILTER_VF);
}

static int nl_dump_ext_ack_done(const struct nlmsghdr *nlh, int error)
{
	return 0;
}

static int rtnl_dump_done(struct nlmsghdr *h,
			  const struct rtnl_dump_filter_arg *a)
{
	int len = *(int *)NLMSG_DATA(h);

	if (h->nlmsg_len < NLMSG_LENGTH(sizeof(int))) {
		fprintf(stderr, "DONE truncated\n");
		return -1;
	}

	if (len < 0) {
		errno = -len;

		if (a->errhndlr && (a->errhndlr(h, a->arg2) & RTNL_SUPPRESS_NLMSG_DONE_NLERR))
			return 0;

		/* check for any messages returned from kernel */
		if (nl_dump_ext_ack_done(h, len))
			return len;

		switch (errno) {
		case ENOENT:
		case EOPNOTSUPP:
			return -1;
		case EMSGSIZE:
			fprintf(stderr, "Error: Buffer too small for object.\n");
			break;
		default:
			fprintf(stderr, "RTNETLINK answers\n");
		}
		return len;
	}

	/* check for any messages returned from kernel */
	nl_dump_ext_ack(h, NULL);

	return 0;
}

static int rtnl_dump_error(const struct rtnl_handle *rth,
				struct nlmsghdr *h,
				const struct rtnl_dump_filter_arg *a)
{

	if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
		fprintf(stderr, "ERROR truncated\n");
	} else {
		const struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);

		errno = -err->error;
		if (rth->proto == NETLINK_SOCK_DIAG &&
			(errno == ENOENT ||
			 errno == EOPNOTSUPP))
			return -1;

		if (a->errhndlr && (a->errhndlr(h, a->arg2) & RTNL_SUPPRESS_NLMSG_ERROR_NLERR))
			return 0;

		if (!(rth->flags & RTNL_HANDLE_F_SUPPRESS_NLERR))
			fprintf(stderr, "RTNETLINK answers\n");
	}

	return -1;
}

static int rtnl_dump_filter_l(struct rtnl_handle *rth,
				  const struct rtnl_dump_filter_arg *arg)
{
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char *buf;
	int dump_intr = 0;

	while (1) {
		int status;
		const struct rtnl_dump_filter_arg *a;
		int found_done = 0;
		int msglen = 0;

		status = rtnl_recvmsg(rth->fd, &msg, &buf);
		if (status < 0)
			return status;

		if (rth->dump_fp)
			fwrite(buf, 1, NLMSG_ALIGN(status), rth->dump_fp);

		for (a = arg; a->filter; a++) {
			struct nlmsghdr *h = (struct nlmsghdr *)buf;

			msglen = status;

			while (NLMSG_OK(h, msglen)) {
				int err = 0;

				h->nlmsg_flags &= ~a->nc_flags;

				if (nladdr.nl_pid != 0 ||
					h->nlmsg_pid != rth->local.nl_pid ||
					h->nlmsg_seq != rth->dump)
					goto skip_it;

				if (h->nlmsg_flags & NLM_F_DUMP_INTR)
					dump_intr = 1;

				if (h->nlmsg_type == NLMSG_DONE) {
					err = rtnl_dump_done(h, a);
					if (err < 0) {
						free(buf);
						return -1;
					}

					found_done = 1;
					break; /* process next filter */
				}

				if (h->nlmsg_type == NLMSG_ERROR) {
					err = rtnl_dump_error(rth, h, a);
					if (err < 0) {
						free(buf);
						return -1;
					}

					goto skip_it;
				}

				if (!rth->dump_fp) {
					err = a->filter(h, a->arg1);
					if (err < 0) {
						free(buf);
						return err;
					}
				}

skip_it:
				h = NLMSG_NEXT(h, msglen);
			}
		}
		free(buf);

		if (found_done) {
			if (dump_intr)
				fprintf(stderr, "Dump was interrupted and may be inconsistent.\n");
			return 0;
		}

		if (msg.msg_flags & MSG_TRUNC) {
			fprintf(stderr, "Message truncated\n");
			continue;
		}
		if (msglen) {
			fprintf(stderr, "!!!Remnant of size %d\n", msglen);
			exit(1);
		}
	}
}

static int rtnl_dump_filter_nc(struct rtnl_handle *rth,
			rtnl_filter_t filter,
			void *arg1, __u16 nc_flags)
{
	const struct rtnl_dump_filter_arg a[] = {
		{
			.filter = filter, .arg1 = arg1,
			.nc_flags = nc_flags,
		},
		{ },
	};

	return rtnl_dump_filter_l(rth, a);
}

static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node *first = h->first;
	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}

static struct ll_cache *ll_entry_create(struct ifinfomsg *ifi,
					const char *ifname,
					struct ll_cache *parent_im)
{
	struct ll_cache *im;
	unsigned int h;

	im = malloc(sizeof(*im) + strlen(ifname) + 1);
	if (!im)
		return NULL;
	im->index = ifi->ifi_index;
	strcpy(im->name, ifname);
	im->type = ifi->ifi_type;
	im->flags = ifi->ifi_flags;

	if (parent_im) {
		list_add_tail(&im->altnames_list, &parent_im->altnames_list);
	} else {
		/* This is parent, insert to index hash. */
		h = ifi->ifi_index & (IDXMAP_SIZE - 1);
		hlist_add_head(&im->idx_hash, &idx_head[h]);
		INIT_LIST_HEAD(&im->altnames_list);
	}

	h = namehash(ifname) & (IDXMAP_SIZE - 1);
	hlist_add_head(&im->name_hash, &name_head[h]);
	return im;
}

static void ll_altname_entries_create(struct ll_cache *parent_im,
					  struct ifinfomsg *ifi, struct rtattr **tb)
{
	struct rtattr *i, *proplist = tb[IFLA_PROP_LIST];
	int rem;

	if (!proplist)
		return;
	rem = RTA_PAYLOAD(proplist);
	for (i = RTA_DATA(proplist); RTA_OK(i, rem);
		 i = RTA_NEXT(i, rem)) {
		if (i->rta_type != IFLA_ALT_IFNAME)
			continue;
		ll_entry_create(ifi, rta_getattr_str(i), parent_im);
	}
}

static inline void hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;
	*pprev = next;
	if (next)
		next->pprev = pprev;
}

static void ll_entry_destroy(struct ll_cache *im, bool im_is_parent)
{
	hlist_del(&im->name_hash);
	if (im_is_parent)
		hlist_del(&im->idx_hash);
	else
		list_del(&im->altnames_list);
	free(im);
}

static void ll_altname_entries_destroy(struct ll_cache *parent_im)
{
	struct ll_cache *im, *tmp;

	list_for_each_entry_safe(im, tmp, &parent_im->altnames_list,
				 altnames_list)
		ll_entry_destroy(im, false);
}

static void ll_entries_create(struct ifinfomsg *ifi, struct rtattr **tb)
{
	struct ll_cache *parent_im;

	if (!tb[IFLA_IFNAME])
		return;
	parent_im = ll_entry_create(ifi, rta_getattr_str(tb[IFLA_IFNAME]),
					NULL);
	if (!parent_im)
		return;
	ll_altname_entries_create(parent_im, ifi, tb);
}

static void ll_entries_destroy(struct ll_cache *parent_im)
{
	ll_altname_entries_destroy(parent_im);
	ll_entry_destroy(parent_im, true);
}

static void ll_entry_update(struct ll_cache *im, struct ifinfomsg *ifi,
				const char *ifname)
{
	unsigned int h;

	im->flags = ifi->ifi_flags;
	if (!strcmp(im->name, ifname))
		return;
	hlist_del(&im->name_hash);
	h = namehash(ifname) & (IDXMAP_SIZE - 1);
	hlist_add_head(&im->name_hash, &name_head[h]);
}

static void ll_altname_entries_update(struct ll_cache *parent_im,
					  struct ifinfomsg *ifi, struct rtattr **tb)
{
	struct rtattr *i, *proplist = tb[IFLA_PROP_LIST];
	struct ll_cache *im;
	int rem;

	if (!proplist) {
		ll_altname_entries_destroy(parent_im);
		return;
	}

	/* Simply compare the altname list with the cached one
	 * and if it does not fit 1:1, recreate the cached list
	 * from scratch.
	 */
	im = list_first_entry(&parent_im->altnames_list, __typeof__(*im),
				  altnames_list);
	rem = RTA_PAYLOAD(proplist);
	for (i = RTA_DATA(proplist); RTA_OK(i, rem);
		 i = RTA_NEXT(i, rem)) {
		if (i->rta_type != IFLA_ALT_IFNAME)
			continue;
		if (!im || strcmp(rta_getattr_str(i), im->name))
			goto recreate_altname_entries;
		im = list_next_entry(im, altnames_list);
	}
	if (list_next_entry(im, altnames_list))
		goto recreate_altname_entries;
	return;

recreate_altname_entries:
	ll_altname_entries_destroy(parent_im);
	ll_altname_entries_create(parent_im, ifi, tb);
}

static void ll_entries_update(struct ll_cache *parent_im,
				  struct ifinfomsg *ifi, struct rtattr **tb)
{
	if (tb[IFLA_IFNAME])
		ll_entry_update(parent_im, ifi,
				rta_getattr_str(tb[IFLA_IFNAME]));
	ll_altname_entries_update(parent_im, ifi, tb);
}

static int parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta,
			   int len, unsigned short flags)
{
	unsigned short type;

	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		type = rta->rta_type & ~flags;
		if ((type <= max) && (!tb[type]))
			tb[type] = rta;
		rta = RTA_NEXT(rta, len);
	}
	if (len)
		fprintf(stderr, "!!!Deficit %d, rta_len=%d\n",
			len, rta->rta_len);
	return 0;
}

static struct ll_cache *ll_get_by_index(unsigned index)
{
	struct hlist_node *n;
	unsigned h = index & (IDXMAP_SIZE - 1);

	hlist_for_each(n, &idx_head[h]) {
		struct ll_cache *im
			= container_of(n, struct ll_cache, idx_hash);
		if (im->index == index)
			return im;
	}

	return NULL;
}

static int ll_remember_index(struct nlmsghdr *n, void *arg)
{
	struct ifinfomsg *ifi = NLMSG_DATA(n);
	struct ll_cache *im;
	struct rtattr *tb[IFLA_MAX+1];

	if (n->nlmsg_type != RTM_NEWLINK && n->nlmsg_type != RTM_DELLINK)
		return 0;

	if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*ifi)))
		return -1;

	im = ll_get_by_index(ifi->ifi_index);
	if (n->nlmsg_type == RTM_DELLINK) {
		if (im)
			ll_entries_destroy(im);
		return 0;
	}

	parse_rtattr_flags(tb, IFLA_MAX, IFLA_RTA(ifi),
			   IFLA_PAYLOAD(n), NLA_F_NESTED);
	if (im)
		ll_entries_update(im, ifi, tb);
	else
		ll_entries_create(ifi, tb);
	return 0;
}

static void ll_init_map(struct rtnl_handle *rth)
{
	static int initialized;

	if (initialized)
		return;

	if (rtnl_linkdump_req(rth, AF_UNSPEC) < 0) {
		fprintf(stderr, "Cannot send dump request\n");
		exit(1);
	}

	if (rtnl_dump_filter(rth, ll_remember_index, NULL) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(1);
	}

	initialized = 1;
}

static struct rtattr *addattr_nest(struct nlmsghdr *n, int maxlen, int type)
{
	struct rtattr *nest = NLMSG_TAIL(n);

	addattr_l(n, maxlen, type, NULL, 0);
	return nest;
}

static int rtnl_talk_suppress_rtnl_errmsg(struct rtnl_handle *rtnl, struct nlmsghdr *n,
				   struct nlmsghdr **answer)
{
	return __rtnl_talk(rtnl, n, answer, false, NULL);
}

static int addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data)
{
	return addattr_l(n, maxlen, type, &data, sizeof(__u32));
}

static int __check_ifname(const char *name)
{
	if (*name == '\0')
		return -1;
	while (*name) {
		if (*name == '/' || isspace(*name))
			return -1;
		++name;
	}
	return 0;
}

static int check_ifname(const char *name)
{
	/* These checks mimic kernel checks in dev_valid_name */
	if (strlen(name) >= IFNAMSIZ)
		return -1;
	return __check_ifname(name);
}

static int ll_link_get(const char *name, int index)
{
	struct {
		struct nlmsghdr		n;
		struct ifinfomsg	ifm;
		char				buf[1024];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = RTM_GETLINK,
		.ifm.ifi_index = index,
	};
	__u32 filt_mask = RTEXT_FILTER_VF | RTEXT_FILTER_SKIP_STATS;
	struct rtnl_handle rth = {};
	struct nlmsghdr *answer;
	int rc = 0;

	if (rtnl_open(&rth, 0) < 0)
		return 0;

	addattr32(&req.n, sizeof(req), IFLA_EXT_MASK, filt_mask);
	if (name)
		addattr_l(&req.n, sizeof(req),
			  !check_ifname(name) ? IFLA_IFNAME : IFLA_ALT_IFNAME,
			  name, strlen(name) + 1);

	if (rtnl_talk_suppress_rtnl_errmsg(&rth, &req.n, &answer) < 0)
		goto out;

	/* add entry to cache */
	rc  = ll_remember_index(answer, NULL);
	if (!rc) {
		struct ifinfomsg *ifm = NLMSG_DATA(answer);

		rc = ifm->ifi_index;
	}

	free(answer);
out:
	rtnl_close(&rth);
	return rc;
}

static struct ll_cache *ll_get_by_name(const char *name)
{
	struct hlist_node *n;
	unsigned h = namehash(name) & (IDXMAP_SIZE - 1);

	hlist_for_each(n, &name_head[h]) {
		struct ll_cache *im
			= container_of(n, struct ll_cache, name_hash);

		if (strcmp(im->name, name) == 0)
			return im;
	}

	return NULL;
}

static unsigned int ll_idx_a2n(const char *name)
{
	unsigned int idx;

	if (sscanf(name, "if%u", &idx) != 1)
		return 0;
	return idx;
}

static unsigned ll_name_to_index(const char *name)
{
	const struct ll_cache *im;
	unsigned idx;

	if (name == NULL)
		return 0;

	im = ll_get_by_name(name);
	if (im)
		return im->index;

	idx = ll_link_get(name, 0);
	if (idx == 0)
		idx = if_nametoindex(name);
	if (idx == 0)
		idx = ll_idx_a2n(name);
	return idx;
}

static int pcap_daq_open(struct rswitch_context *context, const char *device)
{
	uint32_t localnet, netmask;
	uint32_t defaultnet = 0xFFFFFF00;
#ifndef PCAP_OLDSTYLE
	int status;
#endif /* PCAP_OLDSTYLE */

	if (context->handle)
		return DAQ_SUCCESS;

	if (context->device) {
#ifndef PCAP_OLDSTYLE
		fprintf(stderr, "pcap_daq_open: device = %s context %x\n", device, context);
		context->handle = pcap_create(device, context->error);
		if (!context->handle)
			return DAQ_ERROR;
		if ((status = pcap_set_snaplen(context->handle, context->snaplen)) < 0)
			goto fail;
		if ((status = pcap_set_promisc(context->handle, context->promisc_flag ? 1 : 0)) < 0)
			goto fail;
		if ((status = pcap_set_timeout(context->handle, context->timeout)) < 0)
			goto fail;
		if ((status = pcap_set_buffer_size(context->handle, context->buffer_size)) < 0)
			goto fail;
		if ((status = pcap_activate(context->handle)) < 0)
			goto fail;
#else
		context->handle = pcap_open_live(device, context->snaplen,
										 context->promisc_flag ? 1 : 0, context->timeout, context->error);
		if (!context->handle)
			return DAQ_ERROR;
#endif /* PCAP_OLDSTYLE */
		if (pcap_lookupnet(device, &localnet, &netmask, context->error) < 0)
			netmask = htonl(defaultnet);
	}
	context->netmask = htonl(defaultnet);

	return DAQ_SUCCESS;

#ifndef PCAP_OLDSTYLE
fail:
	if (status == PCAP_ERROR || status == PCAP_ERROR_NO_SUCH_DEVICE || status == PCAP_ERROR_PERM_DENIED)
		DPE(context->error, "%s", pcap_geterr(context->handle));
	else
		DPE(context->error, "%s: %s", context->device, pcap_statustostr(status));
	pcap_close(context->handle);
	context->handle = NULL;
	return DAQ_ERROR;
#endif /* PCAP_OLDSTYLE */
}

static void pcap_process_mon_loop(u_char *user, const struct pcap_pkthdr *pkth, const u_char *data)
{
	struct rswitch_context *context = (struct rswitch_context *) user;
	struct rswitch_handle *handle = container_of(context, struct rswitch_handle, mon_context);
	struct ip_v4_hdr *ip_hdr;

	ip_hdr = (struct ip_v4_hdr *)data;

	fprintf(stderr, "MON LOOP MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
		ip_hdr->ether_hdr.ether_dst[0], ip_hdr->ether_hdr.ether_dst[1], ip_hdr->ether_hdr.ether_dst[2],
		ip_hdr->ether_hdr.ether_dst[3], ip_hdr->ether_hdr.ether_dst[4], ip_hdr->ether_hdr.ether_dst[5]);

	// print mac

}
static void pcap_process_loop(u_char *user, const struct pcap_pkthdr *pkth, const u_char *data)
{
	struct rswitch_context *context = (struct rswitch_context *) user;
	DAQ_PktHdr_t hdr = { 0 };
	DAQ_Verdict verdict;
	struct ip_v4_hdr *ip_hdr;

	hdr.caplen = pkth->caplen;
	hdr.pktlen = pkth->len;
	hdr.ts = pkth->ts;
	hdr.ingress_index = -1;
	hdr.egress_index = -1;
	hdr.ingress_group = -1;
	hdr.egress_group = -1;
	hdr.flags = 0;
	hdr.address_space_id = 0;
	ip_hdr = (struct ip_v4_hdr *)data;

	/* Increment the current acquire loop's packet counter. */
	context->packets++;
	/* ...and then the module instance's packet counter. */
	context->stats.packets_received++;
	verdict = context->analysis_func(context->user_data, &hdr, data);

	if (verdict >= MAX_DAQ_VERDICT)
		verdict = DAQ_VERDICT_PASS;
	if (verdict == DAQ_VERDICT_BLACKLIST)
		blacklist_traffic(ip_hdr, context);
	context->stats.verdicts[verdict]++;
}

void* acquire_loop(void *data)
{
	struct rswitch_context *context = (struct rswitch_context *)data;
	int cnt;
	int ret;

	fprintf(stderr, "Thread initialized... %s\n", context->device);
	//wait for start
	while(context->stop == 1)
	{}
	cnt = context->cnt;
	fprintf(stderr, "Thread started... %s cnt %d\n", context->device, cnt);

	while ((context->stop == 0) && (context->packets < cnt || cnt <= 0)) {
		fprintf(stderr, "Dispatching... %s\n", context->device);

		ret = pcap_dispatch(
			context->handle, (cnt <= 0) ? -1 : cnt - context->packets, context->callback, (void *)context);
		fprintf(stderr, "pcap_dispatch returned %d dev %s\n", ret, context->device);
		if (ret == -1) {
			DPE(context->error, "%s", pcap_geterr(context->handle));
			return ret;
		}
		/* If we hit a breakloop call or timed out without reading any packets, break out. */
		else if (ret == -2 || ret == 0)
			break;
	}
	fprintf(stderr, "Thread finished...(INSIDE) %s\n", context->device);
	L;

	return 0;
}

static int rswitch_daq_initialize(
	const DAQ_Config_t* cfg, void** handle, char* errBuf, size_t errMax)
{
	struct rswitch_handle* rswitch_handle = calloc(1, sizeof(*rswitch_handle));
	struct rswitch_context* context;
	char *devname;
	int i = 0;

	L;
	fprintf(stderr, "INITIALIZE!!!!!!!! \n");
	if (!rswitch_handle) {
		snprintf(errBuf, errMax, "%s: failed to allocate the R-Switch context!",
			__func__);
		return DAQ_ERROR_NOMEM;
	}


	fprintf(stderr, "OPEN1!!!!!!!!!!!!!\n");
	fprintf(stderr, "CONFIG %s\n", cfg->name);
	rswitch_handle->mon_context.stop = 1;
	rswitch_handle->mon_context.device = strdup(MONDEV_NAME);
	rswitch_handle->mon_context.snaplen = cfg->snaplen;
	rswitch_handle->mon_context.promisc_flag = (cfg->flags & DAQ_CFG_PROMISC);
	rswitch_handle->mon_context.timeout = cfg->timeout;
	rswitch_handle->mon_context.state = DAQ_STATE_INITIALIZED;
	rswitch_handle->mon_context.callback = pcap_process_mon_loop;
	pthread_create(&rswitch_handle->mon_context.thread, NULL, acquire_loop, &rswitch_handle->mon_context);
	if (pcap_daq_open(&rswitch_handle->mon_context, MONDEV_NAME) != DAQ_SUCCESS) {
		snprintf(errBuf, errMax, "%s", context->error);
		free(rswitch_handle);
		return DAQ_ERROR;
	}

	fprintf(stderr, "OPEN1!!!!!!!!!!!!!\n");
	devname = strtok(cfg->name, ":");
	while (devname) {
		fprintf(stderr, "OPENING %s\n",devname);
		context = &rswitch_handle->contexts[i];
		context->stop = 1;
		pthread_create(&context->thread, NULL, acquire_loop, context);
		context->device = strdup(devname);
		if (!context->device) {
			snprintf(errBuf, errMax, "%s: Couldn't allocate memory for the device string!", __func__);
			free(context);
			return DAQ_ERROR_NOMEM;
		}

		context->snaplen = cfg->snaplen;
		context->promisc_flag = (cfg->flags & DAQ_CFG_PROMISC);
		context->timeout = cfg->timeout;
		INIT_LIST_HEAD(&context->blacklist);

		if (pcap_daq_open(context, context->device) != DAQ_SUCCESS) {
			snprintf(errBuf, errMax, "%s", context->error);
			free(context);
			return DAQ_ERROR;
		}
		context->callback = pcap_process_loop;
		context->state = DAQ_STATE_INITIALIZED;
		get_eth_addr(context->device, context->ether_addr);
		// print mac address
		fprintf(stderr, "MAC %s %02x:%02x:%02x:%02x:%02x:%02x\n", context->device,
			context->ether_addr[0], context->ether_addr[1], context->ether_addr[2],
			context->ether_addr[3], context->ether_addr[4], context->ether_addr[5]);

		i++;
		devname = strtok(NULL, ":");
	}


	if (rtnl_open(&rth, 0) < 0) {
		fprintf(stderr, "Cannot open rtnetlink\n");
		free(context);
		return DAQ_ERROR;
	}


	*handle = rswitch_handle;

	return DAQ_SUCCESS;
}

static void remove_drop_action(struct rswitch_context *context, uint32_t pref)
{
	struct {
		struct nlmsghdr	n;
		struct tcmsg	t;
		char			buf[MAX_MSG];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = RTM_DELTFILTER,
		.t.tcm_family = AF_UNSPEC,
		.t.tcm_parent = 0xfffffff2,
	};

	req.t.tcm_info = ((pref) << 16);
	req.t.tcm_ifindex = ll_name_to_index(context->device);

	if (rtnl_talk(&rth, &req.n, NULL) < 0) {
		fprintf(stderr, "We have an error talking to the kernel\n");
		return;
	}
}

static void rswitch_daq_shutdown(void *handle)
{
	struct rswitch_handle *rswitch_handle = (struct rswitch_handle *)handle;
	struct blacklist_data *pos, *tmp;
	int i;
	L;

	fprintf(stderr, "SHUTDOWN!!!!!!!! \n");
	for (i = 0; i < TSN_NUM; i++) {
		struct rswitch_context *context = &rswitch_handle->contexts[i];
		if (!context->handle)
			continue;
		list_for_each_entry_safe(pos, tmp, &context->blacklist, list)
			remove_drop_action(context, pos->pref);
	}
}

static void add_drop_action(struct nlmsghdr	*n)
{
	struct rtattr *u32_act_tail, *prio_tail, *act_opt_tail;
	struct tc_gact p = { .action = TC_ACT_SHOT, };

	u32_act_tail = addattr_nest(n, MAX_MSG, TCA_U32_ACT);

	prio_tail = addattr_nest(n, MAX_MSG, 1);
	addattr_l(n, MAX_MSG, TCA_ACT_KIND, "gact", strlen("gact") + 1);

	act_opt_tail = addattr_nest(n, MAX_MSG, TCA_ACT_OPTIONS | NLA_F_NESTED);
	addattr_l(n, MAX_MSG, TCA_GACT_PARMS, &p, sizeof(p));

	addattr_nest_end(n, act_opt_tail);
	addattr_nest_end(n, prio_tail);
	addattr_nest_end(n, u32_act_tail);
}

static bool is_already_blacklisted(struct ip_v4_hdr *ip_hdr, struct rswitch_context *context)
{
	struct blacklist_data *pos;

	list_for_each_entry(pos, &context->blacklist, list) {
		if (pos->dst_ip == ip_hdr->ip_dst &&
			pos->src_ip == ip_hdr->ip_src &&
			pos->proto == ip_hdr->ip_proto) {
				return true;
			}
	}

	return false;
}

static int rtnl_dump_request_n(struct rtnl_handle *rth, struct nlmsghdr *n)
{
	struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
	struct iovec iov = {
		.iov_base = n,
		.iov_len = n->nlmsg_len
	};
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	n->nlmsg_flags = NLM_F_DUMP|NLM_F_REQUEST;
	n->nlmsg_pid = 0;
	n->nlmsg_seq = rth->dump = ++rth->seq;

	return sendmsg(rth->fd, &msg, 0);
}

static bool is_pref_present(struct filter_prefs *prefs, uint32_t new_pref)
{
	int i;

	if (!prefs || !prefs->num)
		return false;

	for (i = 0; i < prefs->num; i++) {
		if (prefs->prefs[i] == new_pref)
			return true;
	}

	return false;
}

static int save_pref_callback(struct nlmsghdr *n, struct filter_prefs *prefs)
{
	struct tcmsg *t = NLMSG_DATA(n);
	uint32_t new_pref = TC_H_MAJ(t->tcm_info) >> 16;

	if (is_pref_present(prefs, new_pref))
		return 0;

	if (prefs->num >= MAX_PREFS - 1)
		return -1;

	prefs->prefs[prefs->num] = new_pref;
	prefs->num++;

	return 0;
}

static int save_pref_before(struct nlmsghdr *n, void *arg)
{
	return save_pref_callback(n, &prefs_before);
}

static int save_pref_after(struct nlmsghdr *n, void *arg)
{
	return save_pref_callback(n, &prefs_after);
}

static int get_new_pref(void)
{
	int i, j;

	for (i = 0; i < prefs_after.num; i++) {
		for (j = 0; j < prefs_before.num; j++) {
			if (prefs_after.prefs[i] == prefs_before.prefs[j]) {
				prefs_after.prefs[i] = 0;
				break;
			}
		}
	}

	for (i = 0; i < prefs_after.num; i++) {
		if (prefs_after.prefs[i])
			return prefs_after.prefs[i];
	}

	return -1;
}

static int get_filters(struct rswitch_context *context, bool before)
{
	struct {
		struct nlmsghdr	n;
		struct tcmsg	t;
		char			buf[MAX_MSG];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
		.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ECHO,
		.n.nlmsg_type = RTM_GETTFILTER,
		.t.tcm_parent = 0xfffffff2,
		.t.tcm_family = AF_UNSPEC,
	};

	req.t.tcm_ifindex = ll_name_to_index(context->device);
	if (req.t.tcm_ifindex == 0) {
		fprintf(stderr, "Cannot find device \"%s\"\n", context->device);
		return -1;
	}

	req.t.tcm_info = 0;

	if (rtnl_dump_request_n(&rth, &req.n) < 0) {
		fprintf(stderr, "Cannot send dump request\n");
		return -1;
	}

	if (before) {
		if (rtnl_dump_filter(&rth, save_pref_before, stdout) < 0) {
			fprintf(stderr, "Dump terminated\n");
			return -1;
		}
	} else {
		if (rtnl_dump_filter(&rth, save_pref_after, stdout) < 0) {
			fprintf(stderr, "Dump terminated\n");
			return -1;
		}
	}

	return 0;
}

static void blacklist_traffic(struct ip_v4_hdr *ip_hdr, struct rswitch_context *context)
{
	struct rtattr *tail;
	struct {
		struct nlmsghdr	n;
		struct tcmsg	t;
		char			buf[MAX_MSG];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
		.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE,
		.n.nlmsg_type = RTM_NEWTFILTER,
		.t.tcm_family = AF_UNSPEC,
	};
	struct {
		struct tc_u32_sel sel;
		struct tc_u32_key keys[128];
	} sel = {};
	uint32_t flags = TCA_CLS_FLAGS_SKIP_SW;
	struct blacklist_data *blacklist_entry;

	prefs_after.num = 0;
	prefs_before.num = 0;

	if (is_already_blacklisted(ip_hdr, context))
		return;

	ll_init_map(&rth);

	if (get_filters(context, true)) {
		fprintf(stderr, "Failed to get filter prefs before adding new filter\n");
		return;
	}

	blacklist_entry = calloc(1, sizeof(*blacklist_entry));
	if (!blacklist_entry) {
		fprintf(stderr, "Failed to allocate memory for blacklist entry\n");
		return;
	}

	req.t.tcm_ifindex = ll_name_to_index(context->device);
	if (req.t.tcm_ifindex == 0) {
		fprintf(stderr, "Cannot find device \"%s\"\n", context->device);
		free(blacklist_entry);
		return;
	}
	req.t.tcm_parent = 0xffff0000;
	req.t.tcm_info = TC_H_MAKE(0, 8);

	addattr_l(&req.n, sizeof(req), TCA_KIND, "u32", strlen("u32") + 1);
	tail = addattr_nest(&req.n, MAX_MSG, TCA_OPTIONS);

	add_drop_action(&req.n);

	sel.sel.flags = 1;
	pack_key8(&sel.sel, ip_hdr->ip_proto, 0xff, 9, 0);
	pack_key32(&sel.sel, ip_hdr->ip_src, 0xffffffff, 12, 0);
	pack_key32(&sel.sel, ip_hdr->ip_dst, 0xffffffff, 16, 0);

	addattr_l(&req.n, MAX_MSG, TCA_U32_SEL, &sel,
			  sizeof(sel.sel) +
			  sel.sel.nkeys * sizeof(struct tc_u32_key));
	addattr_l(&req.n, MAX_MSG, TCA_U32_FLAGS, &flags, 4);

	addattr_nest_end(&req.n, tail);

	if (rtnl_talk(&rth, &req.n, NULL) < 0) {
		fprintf(stderr, "We have an error talking to the kernel\n");
		free(blacklist_entry);
		return;
	}

	if (get_filters(context, false)) {
		fprintf(stderr, "Failed to get filter prefs after adding new filter\n");
		free(blacklist_entry);
		return;
	}

	blacklist_entry->pref = get_new_pref();
	blacklist_entry->dst_ip = ip_hdr->ip_dst;
	blacklist_entry->src_ip = ip_hdr->ip_src;
	blacklist_entry->proto = ip_hdr->ip_proto;
	list_add(&blacklist_entry->list, &context->blacklist);
}

static int rswitch_daq_acquire(
	void* handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t metaback, void* user)
{
	struct rswitch_handle *rswitch_handle = (struct rswitch_handle *)handle;
	struct rswitch_context *context;
	int ret;
	int i;

	L;
	rswitch_handle->mon_context.analysis_func = callback;
	rswitch_handle->mon_context.user_data = user;
	rswitch_handle->mon_context.packets = 0;
	rswitch_handle->mon_context.cnt = cnt;
	rswitch_handle->mon_context.stop = 0;
	for (i = 0; i < TSN_NUM; i++) {
		context = &rswitch_handle->contexts[i];

		if (!context->handle) {
			continue;
		}

		context->analysis_func = callback;
		context->user_data = user;
		context->packets = 0;
		context->cnt = cnt;
		context->stop = 0;
	}

	L;
	for (i = 0; i < TSN_NUM; i++) {
		context = &rswitch_handle->contexts[i];
		if (!context->handle) {
			continue;
		}

		fprintf(stderr, "Join %s\n", context->device);
		pthread_join(context->thread, NULL);
	L;
	}

	L;
	fprintf(stderr, "Join %s\n", rswitch_handle->mon_context.device);
	pthread_join(rswitch_handle->mon_context.thread, NULL);
	L;

	return 0;
}

static int rswitch_daq_inject(
	void* handle, const DAQ_PktHdr_t* hdr, const uint8_t* buf, uint32_t len,
	int reverse)
{
	L;
	return DAQ_SUCCESS;
}

static int rswitch_daq_set_filter(void* handle, const char* filter)
{
	L;
	return DAQ_SUCCESS;
}

static int rswitch_daq_start(void* handle)
{
	struct rswitch_handle *rswitch_handle = (struct rswitch_handle *)handle;

	L;
	rswitch_handle->contexts[0].state = DAQ_STATE_STARTED;
	return DAQ_SUCCESS;
}

static int rswitch_daq_breakloop(void* handle)
{
	L;
	return DAQ_SUCCESS;
}

static int rswitch_daq_stop(void* handle)
{
	struct rswitch_handle *rswitch_handle = (struct rswitch_handle *)handle;
	struct rswitch_context *context;
	int i;

	L;
	fprintf(stderr, "Stopping all contexts\n");
	for (i = 0; i < TSN_NUM; i++) {
		context = &rswitch_handle->contexts[i];
		if (!context->handle)
			continue;
		fprintf(stderr, "Stopping context %s\n", context->device);
		context->stop = 1;
		pcap_breakloop(context->handle);
		pcap_close(context->handle);
		pcap_breakloop(context->handle);
		fprintf(stderr, "Canceling  context %s\n", context->device);
		//pthread_cancel(context->thread);
		context->state = DAQ_STATE_STOPPED;
	}
	fprintf(stderr, "Stopping context %s\n", rswitch_handle->mon_context.device);
	rswitch_handle->mon_context.stop = 1;
	pcap_breakloop(rswitch_handle->mon_context.handle);
	pcap_close(rswitch_handle->mon_context.handle);
	pcap_breakloop(rswitch_handle->mon_context.handle);
	fprintf(stderr, "Canceling  context %s\n", rswitch_handle->mon_context.device);
	//pthread_cancel(rswitch_handle->mon_context.thread);
	return DAQ_SUCCESS;
}

static DAQ_State rswitch_daq_check_status(void* handle)
{
	struct rswitch_handle *rswitch_handle = (struct rswitch_handle *)handle;
	L;
	return rswitch_handle->contexts[0].state;
}

static int rswitch_daq_get_stats(void* handle, DAQ_Stats_t* stats)
{
	L;
	return DAQ_SUCCESS;
}

static void rswitch_daq_reset_stats(void* handle) { }

static int rswitch_daq_get_snaplen (void* handle)
{
	L;
	return 0;
}

static uint32_t rswitch_daq_get_capabilities(void* handle)
{
	L;
	return DAQ_CAPA_BLOCK | DAQ_CAPA_BREAKLOOP |
		DAQ_CAPA_UNPRIV_START | DAQ_CAPA_BLACKLIST;
}

static int rswitch_daq_get_datalink_type(void *handle)
{
	L;
	return DLT_EN10MB;
}

static const char* rswitch_daq_get_errbuf(void* handle)
{
	struct rswitch_handle *rswitch_handle = (struct rswitch_handle *)handle;
	L;

	return rswitch_handle->contexts[0].error;
}

static void rswitch_daq_set_errbuf(void* handle, const char* s)
{
	struct rswitch_handle *rswitch_handle = (struct rswitch_handle *)handle;
	L;

	DPE(rswitch_handle->contexts[0].error, "%s", s ? s : "");
}

static int rswitch_daq_get_device_index(void* handle, const char* device)
{
	L;
	return DAQ_ERROR_NOTSUP;
}

//-------------------------------------------------------------------------

#ifdef BUILDING_SO
DAQ_SO_PUBLIC DAQ_Module_t DAQ_MODULE_DATA =
#else
DAQ_Module_t rswitch_offload_daq_module_data =
#endif
{
	.api_version = DAQ_API_VERSION,
	.module_version = DAQ_MOD_VERSION,
	.name = "rswitch_offload",
	.type = DAQ_TYPE,
	.initialize = rswitch_daq_initialize,
	.set_filter = rswitch_daq_set_filter,
	.start = rswitch_daq_start,
	.acquire = rswitch_daq_acquire,
	.inject = rswitch_daq_inject,
	.breakloop = rswitch_daq_breakloop,
	.stop = rswitch_daq_stop,
	.shutdown = rswitch_daq_shutdown,
	.check_status = rswitch_daq_check_status,
	.get_stats = rswitch_daq_get_stats,
	.reset_stats = rswitch_daq_reset_stats,
	.get_snaplen = rswitch_daq_get_snaplen,
	.get_capabilities = rswitch_daq_get_capabilities,
	.get_datalink_type = rswitch_daq_get_datalink_type,
	.get_errbuf = rswitch_daq_get_errbuf,
	.set_errbuf = rswitch_daq_set_errbuf,
	.get_device_index = rswitch_daq_get_device_index,
	.modify_flow = NULL,
	.hup_prep = NULL,
	.hup_apply = NULL,
	.hup_post = NULL,
};
