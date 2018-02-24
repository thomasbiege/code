#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

unsigned 
nameResolve(char *hostname)
{
	struct in_addr  addr;
	struct hostent *hostEnt;

	if ((addr.s_addr = inet_addr(hostname)) == -1)
	{
		if (!(hostEnt = gethostbyname(hostname)))
		{
			fprintf(stderr, "Name lookup failure: `%s`\n", hostname);
			exit(0);
		}
		bcopy(hostEnt->h_addr, (char *) &addr.s_addr, hostEnt->h_length);
	}

	return addr.s_addr;
}


char           *
hostLookup(u_long in)
{
	char            hostname[1024];
	struct in_addr  addr;
	struct hostent *hostEnt;


	bzero(&hostname, sizeof(hostname));
	addr.s_addr = in;
	hostEnt = gethostbyaddr((char *) &addr, sizeof(struct in_addr), AF_INET);

	if (!hostEnt)
		strcpy(hostname, inet_ntoa(addr));
	else
		strcpy(hostname, hostEnt->h_name);

	return (strdup(hostname));
}
