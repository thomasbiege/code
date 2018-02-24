#ifdef HAVE_CONFIG_H
	#include <config.h>
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <err.h>

#include <main.h>
#include <modules.h>
#include <fuzzer.h>
#include <radius.h>

// #define RANGE_DEBUG

/* globals */
char	*prog;

uint8_t code_client[256] = {
	PW_AUTHENTICATION_REQUEST,
	PW_ACCOUNTING_REQUEST,
	PW_PASSWORD_REQUEST,
	PW_ACCOUNTING_MESSAGE,
	PW_STATUS_SERVER,
	PW_DISCONNECT_ACK,
	PW_DISCONNECT_NAK,
	PW_COF_ACK,
	PW_COF_NAK,
	0
};

uint8_t code_server[256] = {
	PW_AUTHENTICATION_ACK,
	PW_AUTHENTICATION_REJECT,
	PW_ACCOUNTING_RESPONSE,
	PW_ACCOUNTING_STATUS,
	PW_PASSWORD_ACK,
	PW_PASSWORD_REJECT,
	PW_ACCESS_CHALLENGE,
	PW_STATUS_CLIENT,
	PW_DISCONNECT_REQUEST,
	PW_COF_REQUEST,
	0
};



/* sub functions */
int get_range(uint32_t *start, uint32_t *end, char *range, uint32_t limit);




/*
** M A I N
*/
int main(int argc, char **argv)
{
	char		*ptr;
	int		ret;
	uint32_t	i;
	int		sid = 0;
	int		opt_cmd = 0,
			opt_idx = 0;
	struct cmdline_options opt =
	{
		0, none, 0, 0, 0, 0, FO_NONE,
		0, 0, 0, NULL, NULL, NULL, NULL, 0
	};
	struct option long_opt[] =
	{
		{"all"		, 0, 0, 'a'},
		{"code"		, 1, 0, 'b'},
		{"attrrange"	, 1, 0, 'd'},
		{"fuzz"		, 1, 0, 'e'},
		{"tunnel"	, 0, 0, 'f'},
		{"eap"		, 0, 0, 'g'},
		{"arap"		, 0, 0, 'h'},
		{"vsa"		, 1, 0, 'i'},
		{"secret"	, 1, 0, 'x'},
		{"host"		, 1, 0, 'y'},
		{"port"		, 1, 0, 'z'},
		{ 0		, 0, 0,  0 }
	};	


	
	/* parse command line option */
	prog = argv[0];
	if(argc < 2)
	{
		USAGE;
		return -1;
	}
	opterr = 0;
	while((opt_cmd = getopt_long(argc, argv, "ab:d:e:fghx:y:z:", long_opt, &opt_idx)) != EOF)
	{
		switch(opt_cmd)
		{
			case 'a':
				opt.code = ALL;
				opt.fuzz = FO_ALL;
				get_range(&opt.attrrange_start, &opt.attrrange_end, "all", 0xFF);
				break;
			case 'b':
				if(!strcmp(optarg, "all"))
					opt.code = ALL;
				else if(!strcmp(optarg, "client"))
					opt.code = client;
				else if(!strcmp(optarg, "server"))
					opt.code = server;
				else
					errx(-1, "error: unknown code '%s'\n", optarg);
				break;
			case 'd':
				ret = get_range(&opt.attrrange_start,
					        &opt.attrrange_end, optarg, 0xFF);
				if(ret == -1)
					errx(-1, "error: attribute range is out-of-range\n");
				if(ret == -2)
					errx(-1, "error: attribute range contains invalid character\n");
				printf("attribute start: %d, end: %d\n", opt.attrrange_start, opt.attrrange_end);
				break;
			case 'e':
				if(!strcmp(optarg, "all"))
					opt.fuzz = FO_ALL;
				if(!strcmp(optarg, "overflow"))
					opt.fuzz |= FO_OVERFLOW;
				if(!strcmp(optarg, "format"))
					opt.fuzz |= FO_FORMAT;
				if(!strcmp(optarg, "length"))
					opt.fuzz |= FO_LENGTH;
				if(!strcmp(optarg, "integer"))
					opt.fuzz |= FO_INTEGER;
				if(!strcmp(optarg, "sql"))
					opt.fuzz |= FO_SQL;
				if(!strcmp(optarg, "ldap"))
					opt.fuzz |= FO_LDAP;
				if(!strcmp(optarg, "html"))
					opt.fuzz |= FO_HTML;
				if(!strcmp(optarg, "shell"))
					opt.fuzz |= FO_SHELL;
				if(!strcmp(optarg, "perl"))
					opt.fuzz |= FO_PERL;
				if(!strncmp(optarg, "username", 8))
				{
					if((ptr = strchr(optarg, '=')) == NULL)
						errx(-1, "error: missing username argument\n");
					ptr++;
					if(ptr == '\0')
						errx(-1, "error: missing username argument\n");
					opt.uname = strdup(ptr);
					ptr = NULL;
					if(strlen(opt.uname) >= 80)
						errx(-1, "error: username argument too long (>= 80)\n");

					opt.fuzz |= FO_USER;
				}
				if(!strncmp(optarg, "realm", 5))
				{
					if((ptr = strchr(optarg, '=')) == NULL)
						errx(-1, "error: missing realm argument\n");
					ptr++;
					if(ptr == '\0')
						errx(-1, "error: missing realm argument\n");
					if(strchr(optarg, '@') == NULL)
						errx(-1, "error: invalid format of realm argument, use <unsername@realm>\n");

					opt.realm = strdup(ptr);
					ptr = NULL;
					if(strlen(opt.realm) >= 80)
						errx(-1, "error: realm argument too long (>= 80)\n");

					opt.fuzz |= FO_REALM;
				}
				break;
			case 'f':
				opt.tunnel = 1;
				break;
			case 'g':
				opt.eap = 1;
				break;
			case 'h':
				opt.arap = 1;
				break;
			case 'i':
				if(optarg == NULL || *optarg == '-')
					errx(-1, "error: invalid VSA argument\n");

				opt.fuzz |= FO_VSA;

				warnx("set fuzz (0x%06X) to add FO_VSA (0x%06X)\n", opt.fuzz, FO_VSA);

				ret = get_range(&opt.vendor_start,
					        &opt.vendor_end, optarg, 0xFFFFFFFF);
				if(ret == -1)
					errx(-1, "error: VSA range is out-of-range\n");
				if(ret == -2)
					errx(-1, "error: VSA range contains invalid character\n");
				printf("VSA ID start: %d, end: %d\n", opt.vendor_start, opt.vendor_end);
				break;
			case 'x':
				if(optarg == NULL || *optarg == '-')
					errx(-1, "error: invalid secret argument\n");
				opt.secret = strdup(optarg);
				break;
			case 'y':
				if(optarg == NULL || *optarg == '-')
					errx(-1, "error: invalid host argument\n");
				opt.host = strdup(optarg);
				break;
			case 'z':
				if(optarg == NULL || *optarg == '-' || !isdigit(*optarg))
					errx(-1, "error: invalid port argument\n");
				opt.port = (short) atoi(optarg);
				break;
			case '?':
			default:
				errx(-1, "error: unknown argument: -%c <%s>\n", opt_cmd, optarg ? optarg : "none");
		}
	}

	
	/* sanatize arguments */
	if(opt.secret == NULL)
		errx(-1, "error: secret argument missing\n");


	/* setup session */
	if( (sid = make_fuzz_session(opt)) < 0)
		errx(-1, "error: unable to make a session\n");
	

	/* check options and run fuzzer function */
	if(opt.fuzz & FO_USER)
	{
		/* we do special username fuzzing of auth request packets
		** usernames are used by RADIUS to look up databses or 
		** checking for realms, this makes it an intresting input
		** value */
		run_username_fuzzer(sid, opt.uname);
	}
	if(opt.fuzz & FO_REALM)
		run_realm_fuzzer(sid, opt.realm);
// 	if(opt.fuzz & FO_VSA)
// 		for(i = opt.vendor_start; i <= opt.vendor_end; i++)
// 			run_vsa_fuzzer(sid, i);
	if(opt.fuzz & FO_VSA)
		for(i = 0; code_client[i] != 0; i++)
			run_vsa_fuzzer(sid, code_client[i]);
	if(opt.code == client)
		for(i = 0; code_client[i] != 0; i++)
			run_fuzzer(sid, code_client[i]);
	if(opt.code == server)
		for(i = 0; code_server[i] != 0; i++)
			run_fuzzer(sid, code_server[i]);
	if(opt.code == ALL)
		for(i = 0; i < 256; i++)
			run_fuzzer(sid, (uint8_t) i);

	
	/* clean up */
	if(opt.uname  != NULL) free(opt.uname);
	if(opt.uname  != NULL) free(opt.realm);
	if(opt.secret != NULL) free(opt.secret);
	if(opt.host   != NULL) free(opt.host);
// 	close(sess[sid].sock_auth);
// 	close(sess[sid].sock_acct);


	return 0;
}

int get_range(uint32_t *start, uint32_t *end, char *range, uint32_t limit)
{
	char	s[101] = {0}, e[101] = {0}, *dst, *src;
	int	i;
	size_t	bytes_left = strlen(range);

#ifdef RANGE_DEBUG
	#warning Enable range debugging
#endif

	if(bytes_left > 100)
		return -1;

	if(!strcmp(range, "all"))
	{
		*start = 0;
		*end   = limit;
	}
	else
	{
		src = range;
		for(dst = s; dst != NULL; )
		{
#ifdef RANGE_DEBUG
			printf("dst = %c\n", (dst == s) ? 's' : 'e');
#endif
			for(i = 0; bytes_left > 0 ; i++)
			{
				/* string ends */
				if(*src == '\0')
				{
#ifdef RANGE_DEBUG
					printf("\tstring ends, %d:%d\n", i, bytes_left);
#endif
					dst = NULL;
					bytes_left = 0;
					break;
				}
				/* skip + signs */
				if(*src == '+' && i == 0)
				{
#ifdef RANGE_DEBUG
					printf("\tskip + sign, %d:%d\n", i, bytes_left-1);
#endif
					src++;
					bytes_left--;
					i--; // repeat
					continue;
				}
				/* invalid char */
				if(*src != '-' && !isdigit((int) *src))
				{
#ifdef RANGE_DEBUG
					printf("\tinvalid char, %d:%d\n", i, bytes_left-1);
#endif
					return -2;
				}
				/* this minus sign indicates the range, 'to' */
				if(*src == '-' && i != 0)
				{
#ifdef RANGE_DEBUG
					printf("\tdetected range delimiter, %d:%d\n", i, bytes_left-1);
#endif
					src++;
					bytes_left--;
					break;
				}
				/* minus sign or digit */
#ifdef RANGE_DEBUG
				printf("\tcopy digit/sign: %c, %d:%d\n", *src, i, bytes_left-1);
#endif
				dst[i] = *src;
				src++;
				bytes_left--;
			}
			dst[i] = 0;

			/* convert values */
			if(dst == s)
			{
#ifdef RANGE_DEBUG
				printf("convert start: %s\n", s);
#endif
				*start = (uint32_t) atoi(dst);
				dst = e;
			}
			else
			{
#ifdef RANGE_DEBUG
				printf("convert end: %s\n", e);
#endif
				*end = (uint32_t) atoi(dst);
				dst = NULL; /* signalize we are done */
			}
			/* switch to next value */
		}
	}

	return 0;
}


// EOF
