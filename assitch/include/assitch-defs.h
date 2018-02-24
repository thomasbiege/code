#ifndef __ASSITCH_DEFS
#define __ASSITCH_DEFS

#define HDR(target) \
    fprintf(output, "AssItch Scan for %s\n\n", target);  \
    fprintf(output, "\t\t\t(*)     AssItch 2.6      (*)\n"); \
    fprintf(output, "\t\t\t(*) Author: Thomas Biege (*)\n"); \
    fprintf(output, "\t\t\t(*)    thomas@suse.de    (*)\n\n"); \
    fprintf(output, "+-------------------------------------------------------------------------------\n");

#define HTMLHDR(target) \
    fprintf(output, "<html><head><title>AssItch Scan for %s</title></head>\n", target);  \
    fprintf(output, "<body>\n"); \
    fprintf(output, "<h1 align=center><font color=#0000FF>AssItch V2.6</font></h1>\n" \
           "<h4 align=center>Author: Thomas Biege (thomas@suse.de)</h4>\n<br><br>\n");

#define TABLHDR  \
    fprintf(output, "<center>"); \
    fprintf(output, "<table border>\n"); \
    fprintf(output, "\t<tr>\n"); \
    fprintf(output, "\t\t<th>Extern\n"); \
    fprintf(output, "\t\t<th>Intern\n"); \
    fprintf(output, "\t\t<th>State/Action\n"); \
    fprintf(output, "\t</tr>\n");

#define TABLSPACE  \
  fprintf(output, "\t<tr><td><td><td></tr>\n");

#define TABLCLOSE \
  fprintf(output, "</table></center>\n\n</body></html>\n");

#define HTMLDENY  \
{ \
  fprintf(output, "\t<tr>\n"); \
  fprintf(output, "\t\t<td>%s:%hu\n" \
         , hostLookup(daddr)  \
         , (mode == ackscan) ? ntohs(port) : ntohs(defport));  \
  fprintf(output, "\t\t<td>%s:%hu\n" \
         , hostLookup(saddr)  \
         , (mode == ackscan) ? ntohs(defport) : ntohs(port));  \
  fprintf(output, "\t\t<td><font color=red>deny</font>\n");  \
  fprintf(output, "\t</tr>\n");  \
}

#define DENY  \
  fprintf(output, "|\tDENIED: %s:%hu => %s:%hu\n"  \
         , hostLookup((mode == ackscan) ? daddr : saddr) \
         , ntohs(defport) \
         , hostLookup((mode == ackscan) ? saddr : daddr) \
         , ntohs(port));

#define HTMLRESULT \
{ \
  fprintf(output, "\t<tr>\n"); \
  fprintf(output, "\t\t<td>%s:%hu\n" \
         , hostLookup(ip_recv->daddr)  \
         , ntohs(tcp_send->source));  \
  fprintf(output, "\t\t<td>%s:%hu\n" \
         , hostLookup(ip_recv->saddr)  \
         , ntohs(tcp_send->dest));  \
  if(rst_flag) \
    fprintf(output, "\t\t<td>%s\n", mode == ackscan ? "<font color=yellow>permit</font>" \
                                           : "<font color=orange>closed</font>"); \
  else if(syn_flag) \
    fprintf(output, "\t\t<td><font color=green>listen</font>\n");  \
  else if(finflag) \
    fprintf(output, "<\t\t<td>%s\n", !fin_rst_flag ? "<font color=green>listen</font>" : "<font color=orange>closed</font>"); \
  else  \
    fprintf(output, "\t\t<td>???\n");  \
  fprintf(output, "\t</tr>\n");  \
}

#define RESULT  \
{ \
  if(rst_flag)  \
    fprintf(output, "|\t%s: ", mode == ackscan ? "PERMIT" : "CLOSED");  \
  else if(syn_flag) \
    fprintf(output, "|\tLISTEN: ");  \
  else if(finflag) \
    fprintf(output, "|\t%s: ", !fin_rst_flag ? "LISTEN" : "CLOSED"); \
  fprintf(output, "%s:%hu => %s:%hu\n" \
         , hostLookup((mode == ackscan) ? ip_recv->saddr : ip_recv->daddr) \
         , ntohs((mode == ackscan) ? tcp_send->dest : tcp_send->source) \
         , hostLookup((mode == ackscan) ? ip_recv->daddr : ip_recv->saddr) \
         , ntohs((mode == ackscan) ? tcp_send->source : tcp_send->dest));  \
}

#define HTMLICMP  \
{ \
  fprintf(output, "\t<tr>\n"); \
  fprintf(output, "\t\t<td>%s:%hu\n" \
         , hostLookup(my_ip->daddr)  \
         , ntohs(my_tcp->dest));  \
  fprintf(output, "\t\t<td>%s:%hu\n" \
         , hostLookup(my_ip->saddr)  \
         , ntohs(my_tcp->source));  \
  fprintf(output, "\t\t<td><font color=red>%s packet causes ICMP\n%s message from host/router %s!</font>\n"  \
         , packets[mode] \
         , port_ur ? "Port unreachable\n" : "Communication prohibited by Filtering\n" \
         , hostLookup(ip_recv->saddr)); \
}

#define PRTICMP \
{ \
  fprintf(output, "|\t%s packet from %s:%hu\n|\tto %s:%hu\n|\tcauses ICMP \n|\t%s message\n|\tfrom host/router %s!\n|\n" \
         , packets[mode] \
         , hostLookup(my_ip->saddr) \
         , ntohs(my_tcp->source)  \
         , hostLookup(my_ip->daddr) \
         , ntohs(my_tcp->dest)  \
         , port_ur ? "Port unreachable" : "Communication prohibited by Filtering" \
         , hostLookup(ip_recv->saddr)); \
}

#define USAGE(prog)\
{\
  fprintf(stderr, "usage:\t%s -d <device> [-p <port>] [-u <port>] [-h] [-f] <src-ip> <dst-ip> <port range>\n", prog);  \
  fprintf(stderr, "\t\t-d <device>  network interface\n"  \
                  "\t\t-o <file>    write output to <file>\n"  \
                  "\t\t-p <port>    specify the privileged port\n" \
                  "\t\t             (dst port for ACK scan, src port for SYN scan)\n" \
                  "\t\t-u <port>    specify the un-privileged port\n" \
                  "\t\t             (dst port for ACK scan, src port for SYN scan)\n" \
                  "\t\t-h           HTMLized output\n" \
                  "\t\t-f           extra FIN scan\n" \
                  "\t\t-t           extra SYN PSH scan (T/TCP)\n" \
                  "\t\t<src-ip>     IP src addr\n" \
                  "\t\t<dst-ip>     IP dst addr\n" \
                  "\t\t<port range> port range (i.e. 20-25,79,80,110-120)\n\n"); \
  exit(-1); \
}

#define ICMP_FILTER	"icmp"
#define TCP_FILTER	"tcp"

#endif
