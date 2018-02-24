#ifndef _MAIN_H_
#define _MAIN_H_

#include <sys/types.h>
#include <stdint.h>

/* defines */
#define USAGE	errx(-1, "usage: %s\
			\n\t--all\
			\n\t[--code {all,server,client}]\
			\n\t--attrrange {all,a-b}\
			\n\t--fuzz {all,overflow,format,length,integer,shell,\
			\n\t        perl,html,sql,ldap,\
			\n\t        username=<name>,realm=<username@realm>}\
			\n\t--vsa=<all,a-b>\
			\n\t--secret <string>\
			\n\t--host <ip>\n", prog)


/* own types */
typedef enum _ctx
{
	none,
	ALL,
	server,
	client
} context_t;

struct cmdline_options
{
	u_int		all;
	context_t	code;
	uint32_t	attrrange_start,
			attrrange_end;
	uint32_t	vendor_start,
			vendor_end;
	u_int		fuzz;
	u_int		tunnel,
			eap,
			arap;
	char		*uname;
	char		*realm;
	char		*secret;
	char		*host;
	short		port;
};

#endif
