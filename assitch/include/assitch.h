#ifndef __ASSITCH_HDR
#define __ASSITCH_HDR

#define TCPHDR          20
#define IPHDR           20
#define TCPIPHDR        IPHDR + TCPHDR
#define PHDR            12
#define PTCPHDR         PHDR + TCPHDR
#define ICMPHDR         8

#define ICMP_PROHIBITED 13	/* icmp code: comm. prohibited by filtering */

#define MAXPACK         100	/* i think enough for TCP or ICMP packets */

#define DELAY           2000000	/* microsec */

#define MAXPORTS        2

enum scans
{
	stopscan = 0,
	ackscan,
	synscan,
	finscan,
	ttcpscan
};

struct pseudohdr		/* for TCP checksum calculation */
{
	u_long          saddr;
	u_long          daddr;
	u_char          pad;
	u_char          proto;
	u_short         tcplen;
};


int	set_signal(int sig, void (*fkt_ptr) (int));
int	chi(u_long saddr, u_long daddr, u_short defport, u_short port, enum scans mode);
int	check_tcp(char *sendpack, char *recvpack, int nread, u_int mode);
int	check_icmp(char *sendpack, char *recvpack, int nread, u_int mode);
void	delay(u_long ms);
u_short	*getpts(char *origexpr);
u_short	in_chksum(unsigned short *ptr, int nbytes);

#endif
