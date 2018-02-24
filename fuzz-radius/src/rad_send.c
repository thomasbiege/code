#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <err.h>

#include <radius.h>
#include <rad_send.h>


uint8_t *calc_req_auth(char *secret)
{
	int		i;
	static uint8_t	auth[16];


	if(strlen(secret) < sizeof(auth))
		i = strlen(secret);
	else
		i = sizeof(auth);

	memset(auth, 0, sizeof(auth));
	memcpy(auth, secret, i);

	/* we dont care about good randim numbers */
	srand(time(NULL));
	for(i = 0; i < sizeof(auth); i++)
		auth[i] ^= ((uint8_t) (rand() & 0x000000FF));

	return auth;
}

/* XXX: we need a valid request package to calc this */
uint8_t *calc_resp_auth(char *secret)
{
	int		i;
	static uint8_t	auth[16];


	if(strlen(secret) < sizeof(auth))
		i = strlen(secret);
	else
		i = sizeof(auth);

	memset(auth, 0, sizeof(auth));
	memcpy(auth, secret, i);

	/* we dont care about good randim numbers */
	srand(time(NULL));
	for(i = 0; i < sizeof(auth); i++)
		auth[i] ^= ((uint8_t) (rand() & 0x000000FF));

	return auth;
}


int radsend(int sock, struct sockaddr sa, char *rp, size_t rp_length, char *secret)
{
	size_t		i;
	radpack_t	*rhdr = (radpack_t *) rp;

// 	printf("radsend: code = %d, id = %d, length = %u(%u), attr = %d, secret = '%s'\n", rhdr->code, rhdr->id, rhdr->length, rp_length, ntohs(rhdr->avp.type), secret);

	switch(rhdr->code)
	{
		/* calc request authenticator */
		case PW_AUTHENTICATION_REQUEST:
		case PW_ACCOUNTING_REQUEST:
			memcpy(rhdr->authenticator, calc_req_auth(secret), 16);
			break;

		/* calc response authenticator */
		default:
			memcpy(rhdr->authenticator, calc_resp_auth(secret), 16);
	}

	
	/* send the packet */
	if(sendto(sock, rp, rp_length, 0, &sa, sizeof(sa)) < 0)
	{
		warn("rad_send: error while sending packet - ");
		return -1;
	}

	return 0;
}
