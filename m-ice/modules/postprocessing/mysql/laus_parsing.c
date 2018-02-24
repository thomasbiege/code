/*
 * Print netlink messages
 *
 * Copyright (C) 2003, SuSE Linux AG
 * Written by okir@suse.de
 *
 * modified by Thomas Biege
 */

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pwd.h>

#include <sys/socket.h>
#define __u32  u_int32_t
#define __s32  int32_t
#define __u16  u_int16_t
#define __s16  int16_t
#define __u8  unsigned char
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <laus.h>
#include <laussrv.h>
#include "syscall.h"
#include "laus_parsing.h"

#define NLMSG_ATTRS(m)    (const struct rtattr *)(((caddr_t) m) + sizeof(*(m)))
#define NLMSG_ATTRLEN(m, len)  ((len) - sizeof(*(m)))
#define NLMSG_TRUNCATED(len)  ((long)(len) > 0)

char *get_ifinfomsg(const struct nlmsghdr *, size_t);
char *get_ifaddrmsg(const struct nlmsghdr *, size_t);
char *get_rtmsg(const struct nlmsghdr *, size_t);
char *get_ndmsg(const struct nlmsghdr *, size_t);
char *get_tcmsg(const struct nlmsghdr *, size_t);
char *get_rtattr(int, unsigned int, unsigned int, const struct rtattr *, size_t);

static struct symbol  rtmsg_names[] = {
  defsym(RTM_NEWLINK),
  defsym(RTM_DELLINK),
  defsym(RTM_GETLINK),
  defsym(RTM_NEWADDR),
  defsym(RTM_DELADDR),
  defsym(RTM_GETADDR),
  defsym(RTM_NEWROUTE),
  defsym(RTM_DELROUTE),
  defsym(RTM_GETROUTE),
  defsym(RTM_NEWNEIGH),
  defsym(RTM_DELNEIGH),
  defsym(RTM_GETNEIGH),
  defsym(RTM_NEWRULE),
  defsym(RTM_DELRULE),
  defsym(RTM_GETRULE),
  defsym(RTM_NEWQDISC),
  defsym(RTM_DELQDISC),
  defsym(RTM_GETQDISC),
  defsym(RTM_NEWTCLASS),
  defsym(RTM_DELTCLASS),
  defsym(RTM_GETTCLASS),
  defsym(RTM_NEWTFILTER),
  defsym(RTM_DELTFILTER),
  defsym(RTM_GETTFILTER),
  { NULL }
};

static struct symbol  rtm_type_names[] = {
  { "unspec",  RTN_UNSPEC  },
  { "unicast",  RTN_UNICAST  },
  { "local",  RTN_LOCAL  },
  { "broadcast",  RTN_BROADCAST  },
  { "anycast",  RTN_ANYCAST  },
  { "multicast",  RTN_MULTICAST  },
  { "blackhole",  RTN_BLACKHOLE  },
  { "unreachable",RTN_UNREACHABLE  },
  { "prohibit",  RTN_PROHIBIT  },
  { "throw",  RTN_THROW  },
  { "nat",  RTN_NAT    },
  { "xresolve",  RTN_XRESOLVE  },
  { NULL }
};

static struct symbol  rtm_proto_names[] = {
  { "unspec",  RTPROT_UNSPEC  },
  { "redirect",  RTPROT_REDIRECT  },
  { "kernel",  RTPROT_KERNEL  },
  { "boot",  RTPROT_BOOT  },
  { "static",  RTPROT_STATIC  },
  { "gated",  RTPROT_GATED  },
  { "ra",    RTPROT_RA  },
  { "mrt",  RTPROT_MRT  },
  { "zebra",  RTPROT_ZEBRA  },
  { "bird",  RTPROT_BIRD  },
  { "dnrouted",  RTPROT_DNROUTED  },
  { NULL }
};

static struct symbol  rtm_scope_names[] = {
  { "universe",  RT_SCOPE_UNIVERSE  },
  { "site",  RT_SCOPE_SITE    },
  { "link",  RT_SCOPE_LINK    },
  { "host",  RT_SCOPE_HOST    },
  { "nowhere",  RT_SCOPE_NOWHERE  },
  { NULL }
};

struct
rtnetlink_get(const struct aud_msg_netlink *nlmsg, size_t len)
{
  const struct nlmsghdr *h;
  int    trunc = 0;

  /* Outer: audit message */
  if (nlmsg->length <= len) {
    len = nlmsg->length;
  } else {
    trunc = 1;
  }

  /* Inner: netlink message */
  if (len < sizeof(*h))
    return -1;
  h = (const struct nlmsghdr *) nlmsg->data;
  if (h->nlmsg_len <= len)
    len = h->nlmsg_len;
  else
    trunc = 1;
  len -= sizeof(*h);

  if (nlmsg->dst_groups)
    printf(" dst=0x%x,", nlmsg->dst_groups);

  printf(" msg=");
  __print_symbolic(h->nlmsg_type, rtmsg_names);

  /* XXX print flags */

  printf(":");
  switch (h->nlmsg_type) {
  case RTM_NEWLINK:
  case RTM_DELLINK:
  case RTM_GETLINK:
    trunc |= print_ifinfomsg(h, len);
    break;
  case RTM_NEWROUTE:
  case RTM_DELROUTE:
  case RTM_GETROUTE:
  case RTM_NEWRULE:
  case RTM_DELRULE:
  case RTM_GETRULE:
    trunc |= print_rtmsg(h, len);
    break;
  case RTM_NEWADDR:
  case RTM_DELADDR:
  case RTM_GETADDR:
    trunc |= print_ifaddrmsg(h, len);
    break;
  case RTM_NEWNEIGH:
  case RTM_DELNEIGH:
  case RTM_GETNEIGH:
    trunc |= print_ndmsg(h, len);
    break;
  case RTM_NEWQDISC:
  case RTM_DELQDISC:
  case RTM_GETQDISC:
  case RTM_NEWTCLASS:
  case RTM_DELTCLASS:
  case RTM_GETTCLASS:
  case RTM_NEWTFILTER:
  case RTM_DELTFILTER:
  case RTM_GETTFILTER:
    trunc |= print_tcmsg(h, len);
    break;
  default:
    printf(" [UNKNOWN NETLINK MESSAGE %u]", h->nlmsg_type);
  }

  if (trunc)
    printf(" (truncated)");

  __print_result(nlmsg->result);
  return 0;
}

int
print_ifinfomsg(const struct nlmsghdr *h, size_t len)
{
  const struct ifinfomsg *ifi;
  const struct rtattr *rta;
  size_t    orig_len = len;
  int    trunc = 0;

  if (len < sizeof(*ifi))
    return 1;

  ifi = (const struct ifinfomsg *) NLMSG_DATA(h);
  printf(" af=");
  __print_af(ifi->ifi_family);

  /* First print the name */
  rta = NLMSG_ATTRS(ifi);
  len = NLMSG_ATTRLEN(ifi, orig_len);
  while (RTA_OK(rta, len)) {
    if (rta->rta_type == IFLA_IFNAME) {
      printf(" name=%s", (const char *) RTA_DATA(rta));
    }
    rta = RTA_NEXT(rta, len);
  }

#if 0
  if (ifi->ifi_type != RTN_UNSPEC) {
    printf(", type=");
    __print_symbolic(ifi->ifi_type, dev_type_names);
  }
#endif
  if (ifi->ifi_index)
    printf(", index=%d", ifi->ifi_index);
  if (ifi->ifi_flags) {
    printf(", flags=");
    __print_ifc_flags(ifi->ifi_flags);
  }

  rta = NLMSG_ATTRS(ifi);
  len = NLMSG_ATTRLEN(ifi, orig_len);
  while (RTA_OK(rta, len)) {
    const unsigned char *data = RTA_DATA(rta);
    size_t payload = RTA_PAYLOAD(rta);

    switch (rta->rta_type) {
    case IFLA_IFNAME:
      break;
    case IFLA_ADDRESS:
      printf(", addr=");
      __print_netaddr(ifi->ifi_family, data, payload);
      break;
    case IFLA_BROADCAST:
      printf(", broadcast=");
      __print_netaddr(ifi->ifi_family, data, payload);
      break;
    case IFLA_MTU:
      __print_integer(", mtu=%llu", data, payload);
      break;
    case IFLA_LINK:
      __print_integer(", link=%lld", data, payload);
      break;
    case IFLA_MASTER:
      __print_integer(", master=%lld", data, payload);
      break;
    case IFLA_QDISC:
      printf(", qdisc=%s", data);
      break;
    case IFLA_STATS:
      /* ignore */
      break;
    default:
      printf(", [rta#%d, len=%d]",
        rta->rta_type, rta->rta_len);
    }
    rta = RTA_NEXT(rta, len);
  }

  /* find out whether message was truncated */
  if (len)
           trunc |= 1;
  return trunc;
}

int
print_ifaddrmsg(const struct nlmsghdr *h, size_t len)
{
  const struct ifaddrmsg *ifa;
  const unsigned char *data;
  int    trunc = 0;

  if (len < sizeof(*ifa))
    return 1;

  ifa = (const struct ifaddrmsg *) NLMSG_DATA(h);
  printf(" af=");
  __print_af(ifa->ifa_family);

  data = (const unsigned char *) ifa + NLMSG_ALIGN(sizeof(*ifa));
  trunc |= print_rtattr(ifa->ifa_family,
      ifa->ifa_prefixlen,
      ifa->ifa_prefixlen,
      NLMSG_ATTRS(ifa), NLMSG_ATTRLEN(ifa, len));

  return trunc;
}

int
print_rtmsg(const struct nlmsghdr *h, size_t len)
{
  const struct rtmsg *rtm;
  const unsigned char *data;
  int    trunc = 0;

  if (len < sizeof(*rtm))
    return 1;

  rtm = (const struct rtmsg *) NLMSG_DATA(h);
  printf(" af=");
  __print_af(rtm->rtm_family);
  if (rtm->rtm_type != RTN_UNSPEC) {
    printf(", type=");
    __print_symbolic(rtm->rtm_type, rtm_type_names);
  }
  if (rtm->rtm_tos) {
    printf(", tos=0x%x", rtm->rtm_tos);
  }
  if (rtm->rtm_protocol != RTPROT_UNSPEC) {
    printf(", rtproto=");
    __print_symbolic(rtm->rtm_protocol, rtm_proto_names);
  }
  if (rtm->rtm_scope) {
    printf(", scope=");
    __print_symbolic(rtm->rtm_scope, rtm_scope_names);
  }
  if (rtm->rtm_flags)
    printf(", flags=0x%x", rtm->rtm_flags);
  if (rtm->rtm_table != RT_TABLE_UNSPEC)
    printf(", table=%d", rtm->rtm_table);

  data = (const unsigned char *) rtm + NLMSG_ALIGN(sizeof(*rtm));
  trunc |= print_rtattr(rtm->rtm_family,
             rtm->rtm_src_len,
      rtm->rtm_dst_len,
      NLMSG_ATTRS(rtm), NLMSG_ATTRLEN(rtm, len));
  return trunc;
}

int
print_rtattr(int af, unsigned int src_len, unsigned int dst_len,
    const struct rtattr *rta, size_t len)
{
  while (RTA_OK(rta, len)) {
    const unsigned char *data = RTA_DATA(rta);
    size_t payload = RTA_PAYLOAD(rta);

    switch (rta->rta_type) {
    case RTA_UNSPEC:
      break;
    case RTA_DST:
      printf(", dst=");
      __print_netaddr(af, data, payload);
      if (dst_len)
        printf("/%u", dst_len);
      break;
    case RTA_SRC:
      printf(", src=");
      __print_netaddr(af, data, payload);
      if (src_len)
        printf("/%u", src_len);
      break;
    case RTA_GATEWAY:
      printf(", gw=");
      __print_netaddr(af, data, payload);
      break;
    case RTA_IIF:
      printf(", iif=%s", data);
      break;
    case RTA_OIF:
      printf(", oif=%s", data);
      break;
    case RTA_PRIORITY:
      __print_integer(", priority=%llu", data, payload);
      break;
    case RTA_PREFSRC:
    case RTA_METRICS:
    case RTA_MULTIPATH:
    case RTA_PROTOINFO:
    case RTA_FLOW:
    case RTA_CACHEINFO:
    default:
      printf(", [rta#%d, len=%d]",
        rta->rta_type, rta->rta_len);
    }
    rta = RTA_NEXT(rta, len);
  }

  return NLMSG_TRUNCATED(len);
}

int
print_ndmsg(const struct nlmsghdr *h, size_t len)
{
  const struct ndmsg *ndm;
  const struct rtattr *rta;

  if (len < sizeof(*ndm))
    return 1;

  ndm = (const struct ndmsg *) NLMSG_DATA(h);
  printf(" af=");
  __print_af(ndm->ndm_family);
  if (ndm->ndm_type)
    printf(", type=%d", ndm->ndm_type);
  if (ndm->ndm_flags)
    printf(", flags=0x%x", ndm->ndm_flags);

  rta = NLMSG_ATTRS(ndm);
  len = NLMSG_ATTRLEN(ndm, len);
  while (RTA_OK(rta, len)) {
    const unsigned char *data = RTA_DATA(rta);
    size_t i, payload = RTA_PAYLOAD(rta);

    switch (rta->rta_type) {
    case NDA_DST:
      printf(", dst=");
      __print_netaddr(ndm->ndm_family, data, payload);
      break;
    case NDA_LLADDR:
      printf(", lladdr=");
      for (i = 0; i < payload; i++)
        printf("%s%02x", i? ":" : "", data[i]);
      break;
    case NDA_CACHEINFO:
      break;
    default:
      printf(", [rta#%d, len=%d]", rta->rta_type, rta->rta_len);
    }

    rta = RTA_NEXT(rta, len);
  }

  return NLMSG_TRUNCATED(len);
}

int
print_tcmsg(const struct nlmsghdr *h, size_t len)
{
  const struct tcmsg *tcm;
  const struct rtattr *rta;
  const char *  sepa = " ";

  if (len < sizeof(*tcm))
    return 1;

  tcm = (const struct tcmsg *) NLMSG_DATA(h);
  if (tcm->tcm_family != AF_UNSPEC) {
    printf(" af=");
    __print_af(tcm->tcm_family);
    sepa = ", ";
  }
  if (tcm->tcm_ifindex) {
    printf("%sifindex=%d", sepa, tcm->tcm_ifindex);
    sepa = ", ";
  }

  rta = NLMSG_ATTRS(tcm);
  len = NLMSG_ATTRLEN(tcm, len);
  while (RTA_OK(rta, len)) {
    const unsigned char *data = RTA_DATA(rta);

    switch (rta->rta_type) {
    case TCA_KIND:
      printf("%skind=%s", sepa, data);
      break;
    case TCA_OPTIONS:
    case TCA_RATE:
    case TCA_STATS:
    case TCA_XSTATS:
      /* ignored silently */
      break;
    default:
      printf("%s[rta#%d, len=%d]",
        sepa, rta->rta_type, rta->rta_len);
    }

    rta = RTA_NEXT(rta, len);
    sepa = ", ";
  }

  return NLMSG_TRUNCATED(len);
}

