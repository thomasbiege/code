#ifndef _MODULES_H_
#define _MODULES_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <main.h>

#define MAX_SESSIONS	10
#define RAD_HDR_LENGTH	20
#define RAD_PACK_MIN	RAD_HDR_LENGTH
#define RAD_PACK_MAX	4096


#define I(lv, args...) \
{ \
        int i; \
\
        for(i = 0; i < lv; i++) \
                fprintf(stdout, "--"); \
        fprintf(stdout, "[ "); \
        fprintf(stdout, ##args); \
        fprintf(stdout, " ]\n"); \
}

/* own types */
typedef struct _session
{
	uint8_t			attr_start;
	uint8_t			attr_end;
	u_int			fuzz;
	u_int			tunnel, eap, arap;
	int			sock_auth,
				sock_acct;
	char			hostname[80];
	u_int			ip;
	short			port;
	char			secret[80];
	char			username[80]; // unused yet
	struct sockaddr		sa_auth,
				sa_acct;
	uint8_t			id;
	uint32_t		vid_start;
	uint32_t		vid_end;

} session_t;


int make_fuzz_session(struct cmdline_options opt);
int run_fuzzer(int sid, uint8_t code);
int run_username_fuzzer(int sid, char *uname);
int run_realm_fuzzer(int sid, char *realm);
int run_vsa_fuzzer(int sid, uint8_t code);

#endif

//EOF

