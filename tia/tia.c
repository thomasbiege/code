/*
capture network traffic and print DNS transaction ID
*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <err.h>

#include "dns_lib.h"

#define USAGE(p) errx(-1, "usage: %s [<host to monitor>]", p)

char			*prog;

struct sockaddr_in	sockinfo;
u_int			sockinfolen;


struct dnshdr
{
	uint16_t	transaction_id;
	uint16_t	flags;
	// we are not interested in the rest
};



char* hex2str(uint8_t *hexval, size_t len);
void  write_to_file(char *saddr, uint16_t sport, char *daddr, uint16_t dport,
		    uint16_t dns_transid);
void stat_transid(uint16_t id);
void stat_portnum(uint16_t port);

/* array for trans id statistic */
struct id_cnt
{
	uint16_t id;
	uint16_t cnt;
};
struct id_cnt *transid_stat;
uint16_t       transid_cnt;

/* array for udp soure port statistic */
struct port_cnt
{
	uint16_t port;
	uint16_t cnt;
};
struct port_cnt *portnum_stat;
uint16_t	 portnum_cnt;



/*
**	       M A I N
*/
int main(int argc, char **argv)
{
	uint8_t			packet[4092];
	uint16_t		packet_size;
	int			sock, nread;
	u_int			opt;
	char			*ip_saddr, *ip_daddr;
	char			*host_to_monitor = NULL;
	uint16_t		ip_hdr_len, udp_hdr_len, dns_hdr_len,
				total_packet_len;
	uint16_t		udp_sport, udp_dport;
	struct ifreq		ifr;
	struct ethhdr		*eth_hdr;
	struct iphdr		*ip_hdr;
	struct udphdr		*udp_hdr;
	struct dnshdr		*dns_hdr;


	prog = argv[0];

	if(argc == 2)
	{
		if(!strcasecmp(argv[1], "-h"))
		{
			USAGE(prog);
		}
		else
		{
			host_to_monitor = argv[1];
			printf("will only monitor packets from host '%s'\n", host_to_monitor);
		}
	}

	/* packet socket for sniffing */
	if( (sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_IP))) < 0 )
		err(-1, "can't create packet socket.\nSYSERR");

	ioctl(sock, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sock, SIOCSIFFLAGS, &ifr);
	

	/* let's start */
	transid_cnt = 0;
	transid_stat = NULL;
	portnum_cnt = 0;
	portnum_stat = NULL;
	setbuf(stdout, NULL);
	while(1)
	{
		//putchar('-');

		// read ethernet packet
		memset(packet, 0, sizeof(packet));
		packet_size = sizeof(struct ethhdr) + sizeof(struct iphdr) +
			      sizeof(struct udphdr) + sizeof(struct dnshdr);
		if((nread = read(sock, packet, packet_size)) < packet_size)
			continue;
		//putchar('e');

		// parse ip header
		ip_hdr = (struct iphdr *) (packet + sizeof(struct ethhdr));
		if(ip_hdr->protocol != IPPROTO_UDP)
			continue;
		ip_hdr_len = ip_hdr->ihl << 2;
		total_packet_len = ntohs(ip_hdr->tot_len);
		ip_saddr = hostLookup(ip_hdr->saddr);
		ip_daddr = hostLookup(ip_hdr->daddr);
		//putchar('i');

		if(host_to_monitor != NULL && strcmp(ip_saddr, host_to_monitor) != 0)
			continue;


		// parse udp header
		udp_hdr = (struct udphdr *) ((char *) ip_hdr + ip_hdr_len);
		udp_sport = ntohs(udp_hdr->source);
		udp_dport = ntohs(udp_hdr->dest);
		udp_hdr_len = ntohs(udp_hdr->len);
		//putchar('u');

		// check if port number
		if(udp_dport != 53)
			continue;
		//else
		//	putchar('d');

		// parse possible dns headers
		dns_hdr_len = sizeof(struct dnshdr);
		dns_hdr = (struct dnshdr *) ((char *) udp_hdr + 8);
		if(dns_hdr->flags & 0xFF00) // not a dns query
		{
			if( (dns_hdr->flags & 0xF000) == 0x8000)
				putchar('R');
			continue;
		}
		//putchar('Q');
		
		write_to_file(ip_saddr, udp_sport, ip_daddr, udp_dport,
			      dns_hdr->transaction_id);
	}

	ifr.ifr_flags &=~ IFF_PROMISC;
	ioctl(sock, SIOCSIFFLAGS, &ifr);

	close(sock);

	exit(0);
}

void write_to_file(char *saddr, uint16_t sport, char *daddr, uint16_t dport, uint16_t dns_transid)
{
	printf("\t%s:%u -> %s:%u - transID = 0x%0.4x\n",
		saddr, sport, daddr, dport, dns_transid);

	stat_transid(dns_transid);
	stat_portnum(sport);

	// write stat struct array to file
	FILE *f = fopen("transid-stat.txt", "w+");
	uint16_t i;
	for(i = 0; i < transid_cnt; i++)
	{
		fprintf(f, "0x%0.4X %u\n", transid_stat[i].id, transid_stat[i].cnt);
	}
	fclose(f);

	// write stat struct array to file
	f = fopen("portnum-stat.txt", "w+");
	for(i = 0; i < portnum_cnt; i++)
	{
		fprintf(f, "%hu %u\n", portnum_stat[i].port, portnum_stat[i].cnt);
	}
	fclose(f);

	return;
}

void stat_transid(uint16_t id)
{
	uint16_t i;

	for(i = 0; i < transid_cnt; i++)
	{
		if(transid_stat[i].id == id)
		{
			transid_stat[i].cnt++;
			return;
		}
	}

	// new trans id
	if((transid_stat = realloc(transid_stat, (transid_cnt+1)*sizeof(struct id_cnt))) == NULL)
		err(-1, "unable to allocate memory");
	transid_stat[transid_cnt].id  = id;
	transid_stat[transid_cnt].cnt = 1;	
	transid_cnt++;

	return;
}

void stat_portnum(uint16_t port)
{
	uint16_t i;

	for(i = 0; i < portnum_cnt; i++)
	{
		if(portnum_stat[i].port == port)
		{
			portnum_stat[i].cnt++;
			return;
		}
	}

	// new trans id
	if((portnum_stat = realloc(portnum_stat, (portnum_cnt+1)*sizeof(struct port_cnt))) == NULL)
		err(-1, "unable to allocate memory");
	portnum_stat[portnum_cnt].port = port;
	portnum_stat[portnum_cnt].cnt  = 1;
	portnum_cnt++;

	return;
}

char* hex2str(uint8_t *hexval, size_t len)
{
	size_t		i;
	char		s[8129];
	char		*ptr;
	
	memset(s, 0, sizeof(s));

	//if(len > ((sizeof(s)-2)/2))
	//	return s;
		
	for(ptr = s, i = 0; i < len; i++, ptr = ptr + 2)
		sprintf(ptr, "%02x", hexval[i]);
	return strdup(s); // we never free them. Ouch!
}

// EOF

