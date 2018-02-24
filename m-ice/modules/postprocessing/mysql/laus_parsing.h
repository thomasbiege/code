

struct laus_nlnk
{
  u_long  dst;
  int     type;   // -1 for unknown
  u_int   trunc;  // 0|1, truncate flag
  char    *af;
  char    *name
  u_long  index;
  u_long  flags;
  char    *addr;
  char    *broadcast;
  u_long  mtu;
  u_long  link;
  u_long  master;
  char    *qdisc;
  u_int   rta;
  u_int   len;
  u_int   tos;
  char    *rtproto;
  char    *scope;
  char    *table;
};
