#ifndef _RADSEND_H_
#define _RADSEND_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>


typedef struct
{
	uint8_t		type;
	uint8_t		length;
	uint8_t		value;
} avp_t __attribute__ ((packed));

typedef struct
{
	uint32_t	id;
	uint8_t		type;
	uint8_t		length;
	uint8_t		value;
} vsa_t __attribute__ ((packed));

typedef struct
{
	uint8_t		code;
	uint8_t		id;
	uint16_t	length;
	uint8_t		authenticator[16] __attribute__ ((packed));
	avp_t		avp;
} radpack_t __attribute__ ((packed));


int radsend(int sock, struct sockaddr sa, char *rp, size_t rp_length, char *secret);

#endif
