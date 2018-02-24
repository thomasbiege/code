/*
**                       <|A| |S| |S| |I| |T| |C| |H|>
**
** Purpose:       AssItch analyses Packet Filter Rules for incoming and
**                outgoing TCP Services
**
** Version:       3.0
**
** Last Update:   2005/07/11
**
** Author:        Thomas Biege <tom@electric-sheep.org>
**
** Tested on:     Mac OS X
**                Linux 2.6.x (SUSE LINUX 9.3)
**
** The GPL applies to this source code.
**
*/

#ifndef HAVE_CONFIG
	#error "Dont have a config.h"
#endif

#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

#include <config.h>
#include <assitch.h>
#include <assitch-defs.h>
#include <error.h>
#include <rtt.h>
#include <dns_lib.h>
#include <libnet.h>
#include <pcap.h>

extern int      errno;
FILE           *output;

u_short         ports[MAXPORTS] = {1020, 5999};

u_int	htmlflag = 0;
u_int	finflag = 0;
u_int	ttcpflag = 0;
char	*prog;

char	*packets[4] = {"STOP", "ACK", "SYN", "FIN", "TTCP"};

size_t	packet_sze;
u_char	*packet;
int	recv_sock;
int	send_sock;
int	icmp_sock;

struct rtt_struct	rttinfo;	/* RTT structure */
int			rttfirst = 1;

struct sockaddr_in	sockinfo;
u_int			sockinfolen;

char			chksum_buf[PTCPHDR];
struct pseudohdr	*p_hdr;


/*
**               M A I N
*/
int 
main(int argc, char **argv)
{
	char			*device;
	char			*outputfile;
	char			errbuf[PCAP_ERRBUF_SIZE];
	pcap_t			*icmp_sock, tcp_sock;
	struct bpf_program	filter;
	bpf_u_int32		mask;
	bpg_u_int32		net;
	u_long			saddr, daddr;
	u_short			priv_port = 0, upriv_port = 0, scan;
	u_short			*scnprts = NULL;
	u_int			port, opt;
	enum scans		scanmethod;	


	prog = argv[0];
	output = stderr;

	opterr = 0;
	while ((opt = getopt(argc, argv, "d:o:p:u:hft")) != EOF)
	{
		switch (opt)
		{
		case 'd':
			if (optarg == NULL || optarg[0] == '-')
				USAGE(prog)
			device = strdup(optarg);
			break;
		case 'o':
			if (optarg == NULL || optarg[0] == '-')
				USAGE(prog)
			outfile = strdup(optarg);
			if ((output = fopen(outputfile, "w")) == NULL)
				err_mesg(FATAL_SYS, "ERROR: fopen()\nSYSERR");
			break;
		case 'p':
			priv_port = (u_short) atoi(optarg);
			break;
		case 'u':
			upriv_port = (u_short) atoi(optarg);
			break;
		case 'h':
			htmlflag = 1;
			break;
		case 'f':
			finflag = 1;
			break;
		case 't':
			ttcpflag = 1
			break;
		default:
			USAGE(prog)
		}
	}
	
	argc -= optind;
	argv += optind;

	if (argc != 3)
		USAGE(prog)

	/* Set and check Parameters from Commandline */
	saddr = libnet_name_resolve(argv[0], LIBNET_RESOLVE);
	daddr = libnet_name_resolve(argv[1], LIBNET_RESOLVE);

	if (!isdigit(argv[2][0]))
		USAGE(prog)

	scnprts = getpts(argv[2]);

	if (priv_port)
		ports[0] = priv_port;
	if (upriv_port)
		ports[1] = upriv_port;

	if (set_signal(SIGALRM, rtt_alarm) < 0)
		err_mesg(FATAL_SYS, "ERROR: set_siganl()\nSYSERR");

	/*
        ** libnet
        */
	packet_size = LIBNET_IP_H + LIBNET_TCP_H;

	/* Step 1: Memory initialization (interchangable with step 2). */
	libnet_init_packet(packet_size, &packet);
	if(packet == NULL)
		libnet_error(LIBNET_ERR_FATAL, "libnet_init_packet failed\n");

	/* Step 2: Network initialization (interchangable with step 1). */
	send_sock = libnet_open_raw_sock(IPPROTO_RAW);
	if(send_sock == -1)
		libnet_error(LIBNET_ERR_FATAL, "Can't open network.\n");



	/* 
	** libpcap
	*/

	/* icmp packets */
	if(pcap_lookupnet(device, &net, &mask, errbuf) < 0)
		err_msg(FATAL_SYS, "ERROR: pcap: %s\n", errbug);
	if((icmp_sock = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) < 0)
		err_msg(FATAL_SYS, "ERROR: pcap: %s\n", errbug);
	if(pcap_compile(icmp_sock, &filter, ICMP_FILTER, 0, net) < 0)
		err_msg(FATAL_SYS, "ERROR: pcap filter invalid\n");
	if(pcap_setfilter(icmp_sock, &filter) < 0)
		err_msg(FATAL_SYS, "ERROR: pcap filter can't be set\n");

	/* tcp packets */
	if(pcap_lookupnet(device, &net, &mask, errbuf) < 0)
		err_msg(FATAL_SYS, "ERROR: pcap: %s\n", errbug);
	if((tcp_sock = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) < 0)
		err_msg(FATAL_SYS, "ERROR: pcap: %s\n", errbug);
	if(pcap_compile(tcp_sock, &filter, TCP_FILTER, 0, net) < 0)
		err_msg(FATAL_SYS, "ERROR: pcap filter invalid\n");
	if(pcap_setfilter(tcp_sock, &filter) < 0)
		err_msg(FATAL_SYS, "ERROR: pcap filter can't be set\n");


	if (htmlflag)
	{
		HTMLHDR(hostLookup(daddr))
			TABLHDR
	}
	else
	{
		HDR(hostLookup(daddr))
	}

	/*
        ** Let's start Scanning
        */
	for (scan = 0; scnprts[scan] != 0; scan++)
	{
		for (port = 0; port < MAXPORTS; port++)
		{
			for(	scanmethod = ttcpflag ? ttcpscan : finscan;
					scanmethod != stopscan;
				scanmethod--)
			{
				if (chi(saddr, daddr, htons(ports[port]),
					htons(scnprts[scan]), scanmethod) < 0)
				{
					err_mesg(WARN, "ERROR: chi()\n");
				}
			}
			
			if (htmlflag)
				TABLSPACE
					else
				fprintf(output, "|\n");
		}
		if (htmlflag)
			TABLSPACE
				else
			fprintf(output, "|-------------------------------------------------------------------------------\n");
	}

	if (htmlflag)
		TABLCLOSE
			else
		fprintf(output, "+-------------------------------------------------------------------------------\n");

	if (output != stderr)
		fclose(output);

	/* Shut down the interface. */
	if (libnet_close_raw_sock(send_sock) == -1)
		libnet_error(LN_ERR_WARNING, "libnet_close_raw_sock couldn't close the interface");


	/* Free packet memory. */
	libnet_destroy_packet(&packet);
	
	exit(0);
}

/*
** chi()
*/
int 
chi(u_long saddr, u_long daddr, u_short defport, u_short port, enum scans mode)
{
	if (mode != ackscan && mode != synscan && mode != finscan && mode !? ttcpscan)
		err_mesg(WARN, "chi(): mode invalid\n");


	if (rttfirst)
	{
		rtt_init(&rttinfo);	/* init. first time we are called */
		rttfirst = 0;
	}

	//sigemptyset(&newsigset);
	//sigaddset(&newsigset, SIGALRM);

	rtt_newpack(&rttinfo);	/* init. for new packet */

rexmit:
	switch(mode)
	{
		case ackscan:
			scan_ack(saddr, daddr, port, defport); // defport should be > 1024
			break;
		case synscan:
			scan_syn(saddr, daddr, defport, port);
			break;
		case finscan:
			scan_fin(saddr, daddr, defport, port);
			break;
		case ttcpscan:
			scan_ttcp(saddr, daddr, defport, port);
			break
	}
	
	delay(DELAY);

	/*
        ** Set RTT and select() Stuff.
        */
	errno = rtt_to = 0;	/* for signal handler */
	alarm(rtt_start(&rttinfo));	/* calc. timeout value & start timer */

	FD_ZERO(&readset);
	maxfd = (icmp_sock > recv_sock) ? (icmp_sock + 1) : (recv_sock + 1);

	while (1)
	{
		FD_SET(recv_sock, &readset);
		FD_SET(icmp_sock, &readset);

		if (select(maxfd, &readset, NULL, NULL, NULL) < 0)
		{
			if (rtt_to)
			{
				/*
			        ** The select() timed out.
			        ** If we have tried enough, then let's quit.
			        */
				if (rtt_timeout(&rttinfo) < 0)
				{
					rttfirst = 1;
					if (htmlflag)
						HTMLDENY
							else
						DENY

							return (1);
				}

				/*
			        ** We have to send the packet again.
			        */
#ifdef VERBOSE
				err_mesg(WARN, "Retransmission!\n");
#endif
				goto rexmit;
			}

#ifdef VERBOSE
			err_mesg(WARN_SYS, "ERROR: select()\nSYSERR");
#endif
			continue;
		}

		if (sigprocmask(SIG_BLOCK, &newsigset, &oldsigset) < 0)
			err_mesg(FATAL_SYS, "ERROR: sigprocmask(BLOCK)\nSYSERR");

		/*
	        ** Either we cought a TCP packet or a ICMP packet
	        */

		if (FD_ISSET(recv_sock, &readset))
		{
			/*
		        ** We cought a TCP pack, so let's read it and
		        ** pass it to check_tcp()
		        */

			if ((nread = read(recv_sock, recvpack, MAXPACK)) < 0)
				err_mesg(FATAL_SYS, "ERROR: read()\nSYSERR");

			if (check_tcp(sendpack, recvpack, nread, mode) > 0)
			{
				alarm(0);	/* stop signal timer */
				rtt_stop(&rttinfo);	/* stop RTT timer, calc
							 * & store new values */
				break;
			}
#ifdef VERBOSE
			else
				err_mesg(WARN, "ERROR: check_tcp()\n");
#endif

		}

		if (FD_ISSET(icmp_sock, &readset))
		{
			/*
		        ** We cought a ICMP pack, so let's read + check it and
		        ** pass it to check_icmp()
		        */
			if ((nread = read(icmp_sock, recvpack, MAXPACK)) < 0)
				err_mesg(FATAL_SYS, "ERROR: read()\nSYSERR");

			if (check_icmp(sendpack, recvpack, nread, mode) > 0)
			{
				alarm(0);	/* stop signal timer */
				rtt_stop(&rttinfo);	/* stop RTT timer, calc
							 * & store new values */
				break;
			}
#ifdef VERBOSE
			else
				err_mesg(WARN, "ERROR: check_icmp()\n");
#endif
		}

		memset(recvpack, 0, MAXPACK);

		if (sigprocmask(SIG_SETMASK, &oldsigset, NULL) < 0)
			err_mesg(FATAL_SYS, "ERROR: sigprocmask(SETMASK)\nSYSERR");

	}			/* while(1) */

	if (sigprocmask(SIG_SETMASK, &oldsigset, NULL) < 0)
		err_mesg(FATAL_SYS, "ERROR: sigprocmask(SETMASK)\nSYSERR");

	return (0);
}


int scan_ack(u_long saddr, u_long daddr, u_short sport, u_short dport)
{
	/* Step 3: Packet construction (IP header). */
	libnet_build_ip(LIBNET_TCP_H,   /* size of the packet sans IP header */
		IPTOS_LOWDELAY,         /* IP tos */
		242,                    /* IP ID */
		0,                      /* frag stuff */
		0xFF,                   /* TTL */
		IPPROTO_TCP,            /* transport protocol */
		saddr,                  /* source IP */
		daddr,                  /* destination IP */
		NULL,                   /* payload (none) */
		0,                      /* payload length */
		packet);                /* packet header memory */


	/* Step 3: Packet construction (TCP header). */
	libnet_build_tcp(sport,         /* source TCP port */
		dport,                  /* destination TCP port */
		31337,                  /* sequence number */
		0x01,                   /* acknowledgement number */
		TH_ACK,                 /* control flags */
		1024,                   /* window size */
		0,                      /* urgent pointer */
		NULL,                   /* payload (none) */
		0,                      /* payload length */
		packet + LIBNET_IP_H);  /* packet header memory */


	/* Step 4: Packet checksums (TCP header only). */
	if(libnet_do_checksum(packet, IPPROTO_TCP, LIBNET_TCP_H) == -1)
		libnet_error(LIBNET_ERR_FATAL, "%s: libnet_do_checksum failed\n", __FUNCTION__);


	/* Step 5: Packet injection. */
	if(libnet_write_ip(send_sock, packet, packet_size);
		libnet_error(LN_ERR_WARNING, "%s: libnet_write_ip only wrote %d bytes\n", __FUNCTION__, c);

	return 0;
}

int scan_fin(u_long saddr, u_long daddr, u_short sport, u_short dport)
{
	/* Step 3: Packet construction (IP header). */
	libnet_build_ip(LIBNET_TCP_H,   /* size of the packet sans IP header */
		IPTOS_LOWDELAY,         /* IP tos */
		242,                    /* IP ID */
		0,                      /* frag stuff */
		0xFF,                   /* TTL */
		IPPROTO_TCP,            /* transport protocol */
		saddr,                  /* source IP */
		daddr,                  /* destination IP */
		NULL,                   /* payload (none) */
		0,                      /* payload length */
		packet);                /* packet header memory */


	/* Step 3: Packet construction (TCP header). */
	libnet_build_tcp(sport,         /* source TCP port */
		dport,                  /* destination TCP port */
		31337,                  /* sequence number */
		0x01,                   /* acknowledgement number */
		TH_FIN,                 /* control flags */
		1024,                   /* window size */
		0,                      /* urgent pointer */
		NULL,                   /* payload (none) */
		0,                      /* payload length */
		packet + LIBNET_IP_H);  /* packet header memory */


	/* Step 4: Packet checksums (TCP header only). */
	if(libnet_do_checksum(packet, IPPROTO_TCP, LIBNET_TCP_H) == -1)
		libnet_error(LIBNET_ERR_FATAL, "%s: libnet_do_checksum failed\n", __FUNCTION__);


	/* Step 5: Packet injection. */
	if(libnet_write_ip(send_sock, packet, packet_size);
		libnet_error(LN_ERR_WARNING, "%s: libnet_write_ip only wrote %d bytes\n", __FUNCTION__, c);

	return 0;
}

int scan_syn(u_long saddr, u_long daddr, u_short sport, u_short dport)
{
	/* Step 3: Packet construction (IP header). */
	libnet_build_ip(LIBNET_TCP_H,   /* size of the packet sans IP header */
		IPTOS_LOWDELAY,         /* IP tos */
		242,                    /* IP ID */
		0,                      /* frag stuff */
		0xFF,                   /* TTL */
		IPPROTO_TCP,            /* transport protocol */
		saddr,                  /* source IP */
		daddr,                  /* destination IP */
		NULL,                   /* payload (none) */
		0,                      /* payload length */
		packet);                /* packet header memory */


	/* Step 3: Packet construction (TCP header). */
	libnet_build_tcp(sport,         /* source TCP port */
		dport,                  /* destination TCP port */
		31337,                  /* sequence number */
		0x01,                   /* acknowledgement number */
		TH_SYN,                 /* control flags */
		1024,                   /* window size */
		0,                      /* urgent pointer */
		NULL,                   /* payload (none) */
		0,                      /* payload length */
		packet + LIBNET_IP_H);  /* packet header memory */


	/* Step 4: Packet checksums (TCP header only). */
	if(libnet_do_checksum(packet, IPPROTO_TCP, LIBNET_TCP_H) == -1)
		libnet_error(LIBNET_ERR_FATAL, "%s: libnet_do_checksum failed\n", __FUNCTION__);


	/* Step 5: Packet injection. */
	if(libnet_write_ip(send_sock, packet, packet_size);
		libnet_error(LN_ERR_WARNING, "%s: libnet_write_ip only wrote %d bytes\n", __FUNCTION__, c);


	return 0;
}

int scan_ttcp(u_long saddr, u_long daddr, u_short sport, u_short dport)
{
	/* Step 3: Packet construction (IP header). */
	libnet_build_ip(LIBNET_TCP_H,   /* size of the packet sans IP header */
		IPTOS_LOWDELAY,         /* IP tos */
		242,                    /* IP ID */
		0,                      /* frag stuff */
		0xFF,                   /* TTL */
		IPPROTO_TCP,            /* transport protocol */
		saddr,                  /* source IP */
		daddr,                  /* destination IP */
		NULL,                   /* payload (none) */
		0,                      /* payload length */
		packet);                /* packet header memory */


	/* Step 3: Packet construction (TCP header). */
	libnet_build_tcp(sport,         /* source TCP port */
		dport,                  /* destination TCP port */
		31337,                  /* sequence number */
		0x01,                   /* acknowledgement number */
		TH_SYN | TH_PSH,        /* control flags */
		1024,                   /* window size */
		0,                      /* urgent pointer */
		NULL,                   /* payload (none) */
		0,                      /* payload length */
		packet + LIBNET_IP_H);  /* packet header memory */


	/* Step 4: Packet checksums (TCP header only). */
	if(libnet_do_checksum(packet, IPPROTO_TCP, LIBNET_TCP_H) == -1)
		libnet_error(LIBNET_ERR_FATAL, "%s: libnet_do_checksum failed\n", __FUNCTION__);


	/* Step 5: Packet injection. */
	if(libnet_write_ip(send_sock, packet, packet_size);
		libnet_error(LN_ERR_WARNING, "%s: libnet_write_ip only wrote %d bytes\n", __FUNCTION__, c);

	return 0;
}


/*
** check_tcp() checks TCP packets
** return values: -1  : error
**                 1  : everything is in order
**                 0  : something is wrong
*/
int 
check_tcp(char *sendpack, char *recvpack, int nread, u_int mode)
{
	struct iphdr   *ip_recv;
	struct iphdr   *ip_send;
	struct tcphdr  *tcp_recv;
	struct tcphdr  *tcp_send;
	u_int           iphdrlen;
	u_int           syn_flag = 0, rst_flag = 0, fin_rst_flag = 0;


	ip_recv = (struct iphdr *) recvpack;

	iphdrlen = ip_recv->ihl << 2;
	if (nread < (iphdrlen + TCPHDR))
	{
#ifdef VERBOSE
		err_mesg(WARN, "TCP packet is too short!\n");
		fflush(stdout);
#endif
		return (0);	/* packet too short */
	}

	tcp_recv = (struct tcphdr *) (recvpack + iphdrlen);
	ip_send = (struct iphdr *) sendpack;
	tcp_send = (struct tcphdr *) (sendpack + IPHDR);


	if (ip_recv->saddr != ip_send->daddr ||
	    tcp_recv->source != tcp_send->dest ||
	    tcp_recv->dest != tcp_send->source
		)
	{
#ifdef VERBOSE
		err_mesg(WARN, "TCP packet doesn't belong to us!\n");
		fflush(stdout);
#endif
		return (0);
	}


	switch (mode)
	{
	case ackscan:
		if ((tcp_recv->rst) && (tcp_recv->seq == tcp_send->ack_seq))
			rst_flag = 1;
		break;
	case synscan:
		if (tcp_recv->rst)
			rst_flag = 1;
		else if (tcp_recv->syn && tcp_recv->ack)
			syn_flag = 1;
		else
			return (-1);	/* change defport! */
		break;
	case finscan:
		if (tcp_recv->rst)
			fin_rst_flag = 1;
		break;
	default:
		return (-1);
		/* change defport!... hey, or we may hit the right seq# ;) */
	}

	if (htmlflag)
		HTMLRESULT
			else
		RESULT


		/*
	        ** We don't have to send a RST packet, because the TCP stack will
	        ** do it for us.
	        */

		/*
	        ** We should send an RST packet if we received an SYN|ACK packet
	        ** to avoid a DoS attack.
	        if(syn_flag)
	        {
	          tcp_send->seq     = tcp_recv->ack_seq;
	          tcp_send->ack_seq = htonl( (u_long) (ntohl(tcp_recv->seq) + 1) );
	          tcp_send->rst     = 1;
	      
	          bcopy(tcp_send, chksum_buf+PHDR, TCPHDR);
	          tcp_send->check   = in_chksum((u_short *) chksum_buf, (int) PTCPHDR);
	      
	          if(sendto(send_sock, sendpack, TCPIPHDR, 0, (struct sockaddr *) &sockinfo, sockinfolen) < 0)
	            err_mesg(FATAL_SYS, "ERROR: sendto()\nSYSERR");
	        }
	        */

			return (1);
}

/*
** check_icmp() checks ICMP packets
** return values: -1  : error
**                 1  : everything is in order
**                 0  : something is wrong
*/
int 
check_icmp(char *sendpack, char *recvpack, int nread, u_int mode)
{
	struct iphdr   *ip_send;
	struct iphdr   *ip_recv;
	struct iphdr   *my_ip;
	struct icmphdr *icmp;
	struct tcphdr  *tcp_send;
	struct tcphdr  *my_tcp;
	u_int           iphdrlen;
	u_int           port_ur = 0, prohib = 0;


	ip_send = (struct iphdr *) sendpack;
	ip_recv = (struct iphdr *) recvpack;

	iphdrlen = ip_recv->ihl << 2;
	if (nread < (iphdrlen + ICMPHDR))
	{
#ifdef VERBOSE
		err_mesg(WARN, "ICMP packet is too short!\n");
		fflush(stdout);
#endif
		return (0);	/* packet too short */
	}

	icmp = (struct icmphdr *) (recvpack + iphdrlen);
	my_ip = (struct iphdr *) (recvpack + iphdrlen + ICMPHDR);
	my_tcp = (struct tcphdr *) (recvpack + iphdrlen + ICMPHDR + IPHDR);
	tcp_send = (struct tcphdr *) (sendpack + IPHDR);

	if (my_ip->daddr != ip_send->daddr ||
	    my_tcp->source != tcp_send->source ||
	    my_tcp->dest != tcp_send->dest
		)
	{
#ifdef VERBOSE
		err_mesg(WARN, "ICMP packet doesn't belong to us!\n");
		fflush(stdout);
#endif
		return (0);
	}


	if (icmp->type == ICMP_DEST_UNREACH)
	{
		if (icmp->code == ICMP_PORT_UNREACH)
			port_ur = 1;
		else if (icmp->code == ICMP_PROHIBITED)
			prohib = 1;
		else
			return (1);
	}
	else
	{
#ifdef VERBOSE
		err_mesg(WARN, "Not a ICMP unreachable message!\n");
#endif
		return (0);
	}


	if (htmlflag)
		HTMLICMP
			else
		PRTICMP

			return (1);
}


u_short 
in_chksum(u_short * ptr, int nbytes)
{
	register long   sum;	/* assumes long == 32 bits */
	u_short         oddbyte;
	register u_short answer;/* assumes u_short == 16 bits */

	/*
        * Our algorithm is simple, using a 32-bit accumulator (sum),
        * we add sequential 16-bit words to it, and at the end, fold back
        * all the carry bits from the top 16 bits into the lower 16 bits.
        */

	sum = 0;
	while (nbytes > 1)
	{
		sum += *ptr++;
		nbytes -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nbytes == 1)
	{
		oddbyte = 0;	/* make sure top half is zero */
		*((unsigned char *) &oddbyte) = *(unsigned char *) ptr;	/* one byte only */
		sum += oddbyte;
	}

	/*
         * Add back carry outs from top 16 bits to low 16 bits.
         */

	sum = (sum >> 16) + (sum & 0xffff);	/* add high-16 to low-16 */
	sum += (sum >> 16);	/* add carry */
	answer = ~sum;		/* ones-complement, then truncate to 16 bits */

	return ((u_short) answer);
}

u_short        *
getpts(char *origexpr)
{
	int             exlen = strlen(origexpr);
	char           *p, *q;
	unsigned short *tmp, *ports;
	int             i = 0, j = 0, start, end;
	char           *expr = strdup(origexpr);
	char           *mem = expr;

	ports = (u_short *) malloc(65536 * sizeof(short));

	for (; j < exlen; j++)
		if (expr[j] != ' ')
			expr[i++] = expr[j];

	expr[i] = '\0';
	exlen = i;
	i = 0;

	while ((p = strchr(expr, ',')))
	{
		*p = '\0';
		if (*expr == '-')
		{
			start = 1;
			end = atoi(expr + 1);
		}
		else
		{
			start = end = atoi(expr);
			if ((q = strchr(expr, '-')) && *(q + 1))
				end = atoi(q + 1);
			else if (q && !*(q + 1))
				end = 65535;
		}

		if (start < 1 || start > end)
			err_mesg(FATAL, "Your port specifications are illegal!");

		for (j = start; j <= end; j++)
			ports[i++] = j;
		expr = p + 1;
	}

	if (*expr == '-')
	{
		start = 1;
		end = atoi(expr + 1);
	}
	else
	{
		start = end = atoi(expr);
		if ((q = strchr(expr, '-')) && *(q + 1))
			end = atoi(q + 1);
		else if (q && !*(q + 1))
			end = 65535;
	}

	if (start < 1 || start > end)
		err_mesg(FATAL, "Your port specifications are illegal!");

	for (j = start; j <= end; j++)
		ports[i++] = j;

	ports[i++] = 0;
	tmp = realloc(ports, i * sizeof(short));
	free(mem);

	return (tmp);
}
