#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <err.h>

#include <main.h>
#include <modules.h>
#include <stdnet.h>
#include <dns_lib.h>
#include <rad_send.h>
#include <fuzzer.h>
#include <radius.h>

static int 		idx;
static session_t	sess[MAX_SESSIONS];


int make_fuzz_session(struct cmdline_options opt)
{
	char			*hname;
	struct sockaddr_in  	sa, sa_local;


	if(idx == MAX_SESSIONS)
		return -1;


	/* set session parameters */
	sess[idx].attr_start = opt.attrrange_start;
	sess[idx].attr_end   = opt.attrrange_end;
	sess[idx].vid_start  = opt.vendor_start;
	sess[idx].vid_end    = opt.vendor_end;
	sess[idx].fuzz       = opt.fuzz;
	sess[idx].tunnel     = opt.tunnel;
	sess[idx].eap        = opt.eap;
	sess[idx].arap       = opt.arap;
	sess[idx].id         = 0;
	sess[idx].ip         = name_resolve(opt.host);
	if(sess[idx].ip == 0)
	{
		warnx("warn: make_fuzz_session: cannot resolve %s\n", opt.host);
		return -1;
	}
	memset(sess[idx].hostname, 0, sizeof(sess[idx].hostname));
	if((hname = host_lookup(sess[idx].ip)) == NULL)
		strncpy(sess[idx].hostname, opt.host, sizeof(sess[idx].hostname)-1);
	else
		strncpy(sess[idx].hostname, hname, sizeof(sess[idx].hostname)-1);
	strncpy(sess[idx].secret, opt.secret, sizeof(sess[idx].secret)-1);


	/* open UDP socket for auth */
	memset((char *) &sa, 0, sizeof sa);
	sa.sin_family      = AF_INET;
	sa.sin_port        = htons(PW_AUTH_UDP_PORT);
	sa.sin_addr.s_addr = sess[idx].ip;
	if((sess[idx].sock_auth = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		warnx("warn: make_fuzz_session: cannot ceate UDP socket\n");
		return -1;
	}
	memcpy((char *) &sess[idx].sa_auth, (char *) &sa, sizeof sa);

	/* open UDP socket for acct */
	memset((char *) &sa, 0, sizeof sa);
	sa.sin_family      = AF_INET;
	sa.sin_port        = htons(PW_ACCT_UDP_PORT);
	sa.sin_addr.s_addr = sess[idx].ip;
	if((sess[idx].sock_acct = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		warnx("warn: make_fuzz_session: cannot ceate UDP socket\n");
		return -1;
	}
	memcpy((char *) &sess[idx].sa_acct, (char *) &sa, sizeof sa);


	/* bind a local RADIUS port for auth */
	memset((char *) &sa_local, 0, sizeof sa_local);
	sa_local.sin_family      = AF_INET;
	sa_local.sin_port        = htons(PW_AUTH_UDP_PORT);
	sa_local.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(sess[idx].sock_auth, (struct sockaddr *) &sa_local, sizeof sa_local) < 0)
	{
		warnx("warn: make_fuzz_session: cannot bind to auth port %u\n", PW_AUTH_UDP_PORT);
		return -1;
	}

	/* bind a local RADIUS port for auth */
	memset((char *) &sa_local, 0, sizeof sa_local);
	sa_local.sin_family      = AF_INET;
	sa_local.sin_port        = htons(PW_ACCT_UDP_PORT);
	sa_local.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(sess[idx].sock_acct, (struct sockaddr *) &sa_local, sizeof sa_local) < 0)
	{
		warnx("warn: make_fuzz_session: cannot bind to acct port %u\n", PW_ACCT_UDP_PORT);
		return -1;
	}

	return idx++;
}

int run_fuzzer(int sid, uint8_t code)
{
	char		packet[2*RAD_PACK_MAX] __attribute__ ((packed));
	char		*fuzz_str;
	uint16_t	attr;
	size_t		rpack_length,
			str_size;
	radpack_t	*rhdr;	// radius packet header
	avp_t		*avp;	// radius attribute value pair


	if(sid < 0 || sid >= idx)
		return -1;

	I(2, "fuzz: code = %u, range: %d-%d", code, sess[sid].attr_start, sess[sid].attr_end);


	for(attr = sess[sid].attr_start; attr <= sess[sid].attr_end; attr++)
	{
		memset((char *) &packet, 0, sizeof(packet));
		rhdr = (radpack_t *) packet;

		if(sess[sid].fuzz & FO_OVERFLOW)
		{
			/* construct package: fix values */
			rhdr->code	= code;

			/** 0: construct a valid package **/
			rhdr->id	= sess[sid].id++;
			rhdr->length	= RAD_HDR_LENGTH;
			
			/* construct package: set AVP */
			avp 		= (avp_t *) &rhdr->avp;
			avp->type	= PW_USER_NAME;
			avp->length	= 6;
			strcpy((char *) &avp->value, "test");
			rhdr->length	+= avp->length;

			avp		= (avp_t *) (packet + rhdr->length);
			avp->type	= PW_USER_PASSWORD;
			avp->length	= 7;
			strcpy((char *) &avp->value, "hello");
			rhdr->length	+= avp->length;
			rpack_length	= rhdr->length;
			rhdr->length	= htons(rhdr->length);


			I(2, "fuzz: id: %u, attribute: %u, overflow: [%u:%u]",
			sess[sid].id-1, attr, rhdr->length, avp->length);

			/* send RADIUS package and calculate authenticator */
			radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
			radsend(sess[sid].sock_acct, sess[sid].sa_acct, packet, rpack_length, sess[sid].secret);
			/* we dont care about replies */


			/** 1: construct package: length = code + id + length + auth + vp **/
			rhdr->id	= sess[sid].id++;
			rhdr->length	= 10; /* ivalid */
			
			/* construct package: set AVP */
			str_size	= 200;
			avp 		= (avp_t *) &rhdr->avp;
			avp->type	= (uint8_t) (attr & 0xFF);
			avp->length	= (uint8_t) (str_size+2);
			memset(&avp->value, (int) 'A', str_size);
			rhdr->length	+= avp->length;
			rpack_length	= rhdr->length;
			rhdr->length	= htons(rhdr->length);


			I(2, "fuzz: id: %u, attribute: %u, overflow: [%u:%u]",
			sess[sid].id-1, attr, rhdr->length, avp->length);

			/* send RADIUS package and calculate authenticator */
			radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
			radsend(sess[sid].sock_acct, sess[sid].sa_acct, packet, rpack_length, sess[sid].secret);
			/* we dont care about replies */


			/** 2: construct package: length = code + id + length + auth + vp **/
			rhdr->id	= sess[sid].id++;
			rhdr->length	= RAD_PACK_MAX; /* ivalid */

			/* construct package: set AVP */
			str_size	= RAD_PACK_MAX+1;
			avp 		= (avp_t *) &rhdr->avp;
			avp->type	= (uint8_t) (attr & 0xFF);
			avp->length	= (uint8_t) (str_size+2);
			memset(&avp->value, (int) 'A', str_size);
			rhdr->length	+= avp->length;
			rpack_length	= rhdr->length;
			rhdr->length	= htons(rhdr->length);


			I(2, "fuzz: id: %u, attribute: %u, overflow: [%u:%u]",
			sess[sid].id-1, attr, rhdr->length, avp->length);

			/* send RADIUS package and calculate authenticator */
			radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
			radsend(sess[sid].sock_acct, sess[sid].sa_acct, packet, rpack_length, sess[sid].secret);
			/* we dont care about replies */


			/** 3: construct package: length = code + id + length + auth + vp **/
			rhdr->id	= sess[sid].id++;
			rhdr->length	= RAD_PACK_MAX; /* ivalid */

			/* construct package: set AVP */
			str_size	= RAD_PACK_MAX-2;
			avp 		= (avp_t *) &rhdr->avp;
			avp->type	= (uint8_t) (attr & 0xFF);
			avp->length	= (uint8_t) (str_size+2);
			memset(&avp->value, (int) 'A', str_size);
			rpack_length	= rhdr->length;
			rhdr->length	= htons(rhdr->length);


			I(2, "fuzz: id: %u, attribute: %u, overflow: [%u:%u]",
			sess[sid].id-1, attr, rhdr->length, avp->length);

			/* send RADIUS package and calculate authenticator */
			radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
			radsend(sess[sid].sock_acct, sess[sid].sa_acct, packet, rpack_length, sess[sid].secret);
			/* we dont care about replies */
		}
		if(sess[sid].fuzz & FO_FORMAT)
		{
			while((fuzz_str = fuzz_format("raudius-fuzzer")) != NULL)
			{
				/* construct package: fix values */
				rhdr->code	= code;
				rhdr->id	= sess[sid].id++;
				rhdr->length	= RAD_HDR_LENGTH;
			
				/* construct package: set AVP */
				str_size	= strlen(fuzz_str);
				avp 		= (avp_t *) &rhdr->avp;
				avp->type	= (uint8_t) (attr & 0xFF);
				avp->length	= (uint8_t) (str_size+2);
				memcpy((char *) &avp->value, fuzz_str, str_size);

				rhdr->length	+= avp->length;
				rpack_length	= rhdr->length;
				rhdr->length	= htons(rhdr->length);


				I(2, "fuzz: id: %u, attribute: %u, format[%u]: '%s'",
				sess[sid].id-1, attr, ntohs(rhdr->length), fuzz_str);

				/* send RADIUS package and calculate authenticator */
				radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
				radsend(sess[sid].sock_acct, sess[sid].sa_acct, packet, rpack_length, sess[sid].secret);
				/* we dont care about replies */
			}
		}
		if(sess[sid].fuzz & FO_LENGTH)
		{
			/* construct RADIUS package */

			/* send RADIUS package */

			/* wait n seconds for an answer */
		}
		if(sess[sid].fuzz & FO_INTEGER)
		{
			/* construct RADIUS package */

			/* send RADIUS package */

			/* wait n seconds for an answer */
		}
		if(sess[sid].fuzz & FO_SQL)
		{
			while((fuzz_str = fuzz_sql("raudius-fuzzer")) != NULL)
			{
				/* construct package: fix values */
				rhdr->code	= code;
				rhdr->id	= sess[sid].id++;
				rhdr->length	= RAD_HDR_LENGTH;
			
				/* construct package: set AVP */
				str_size	= strlen(fuzz_str);
				avp 		= (avp_t *) &rhdr->avp;
				avp->type	= (uint8_t) (attr & 0xFF);
				avp->length	= (uint8_t) (str_size+2);
				memcpy((char *) &avp->value, fuzz_str, str_size);

				rhdr->length	+= avp->length;
				rpack_length	= rhdr->length;
				rhdr->length	= htons(rhdr->length);


				I(2, "fuzz: id: %u, attribute: %u, sql[%u]: '%s'",
				sess[sid].id-1, attr, ntohs(rhdr->length), fuzz_str);

				/* send RADIUS package and calculate authenticator */
				radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
				radsend(sess[sid].sock_acct, sess[sid].sa_acct, packet, rpack_length, sess[sid].secret);
				/* we dont care about replies */
			}
		}
		if(sess[sid].fuzz & FO_LDAP)
		{
			while((fuzz_str = fuzz_ldap("raudius-fuzzer")) != NULL)
			{
				/* construct package: fix values */
				rhdr->code	= code;
				rhdr->id	= sess[sid].id++;
				rhdr->length	= RAD_HDR_LENGTH;
			
				/* construct package: set AVP */
				str_size	= strlen(fuzz_str);
				avp 		= (avp_t *) &rhdr->avp;
				avp->type	= (uint8_t) (attr & 0xFF);
				avp->length	= (uint8_t) (str_size+2);
				memcpy((char *) &avp->value, fuzz_str, str_size);

				rhdr->length	+= avp->length;
				rpack_length	= rhdr->length;
				rhdr->length	= htons(rhdr->length);


				I(2, "fuzz: id: %u, attribute: %u, ldap[%u]: '%s'",
				sess[sid].id-1, attr, ntohs(rhdr->length), fuzz_str);

				/* send RADIUS package and calculate authenticator */
				radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
				radsend(sess[sid].sock_acct, sess[sid].sa_acct, packet, rpack_length, sess[sid].secret);
				/* we dont care about replies */
			}
		}
		if(sess[sid].fuzz & FO_SHELL)
		{
			while((fuzz_str = fuzz_shell("raudius-fuzzer")) != NULL)
			{
				/* construct package: fix values */
				rhdr->code	= code;
				rhdr->id	= sess[sid].id++;
				rhdr->length	= RAD_HDR_LENGTH;
			
				/* construct package: set AVP */
				str_size	= strlen(fuzz_str);
				avp 		= (avp_t *) &rhdr->avp;
				avp->type	= (uint8_t) (attr & 0xFF);
				avp->length	= (uint8_t) (str_size+2);
				memcpy((char *) &avp->value, fuzz_str, str_size);

				rhdr->length	+= avp->length;
				rpack_length	= rhdr->length;
				rhdr->length	= htons(rhdr->length);


				I(2, "fuzz: id: %u, attribute: %u, shell[%u]: '%s'",
				sess[sid].id-1, attr, ntohs(rhdr->length), fuzz_str);

				/* send RADIUS package and calculate authenticator */
				radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
				radsend(sess[sid].sock_acct, sess[sid].sa_acct, packet, rpack_length, sess[sid].secret);
				/* we dont care about replies */
			}
		}
		if(sess[sid].fuzz & FO_PERL)
		{
			while((fuzz_str = fuzz_perl("raudius-fuzzer")) != NULL)
			{
				/* construct package: fix values */
				rhdr->code	= code;
				rhdr->id	= sess[sid].id++;
				rhdr->length	= RAD_HDR_LENGTH;
			
				/* construct package: set AVP */
				str_size	= strlen(fuzz_str);
				avp 		= (avp_t *) &rhdr->avp;
				avp->type	= (uint8_t) (attr & 0xFF);
				avp->length	= (uint8_t) (str_size+2);
				memcpy((char *) &avp->value, fuzz_str, str_size);

				rhdr->length	+= avp->length;
				rpack_length	= rhdr->length;
				rhdr->length	= htons(rhdr->length);


				I(2, "fuzz: id: %u, attribute: %u, perl[%u]: '%s'",
				sess[sid].id-1, attr, ntohs(rhdr->length), fuzz_str);

				/* send RADIUS package and calculate authenticator */
				radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
				radsend(sess[sid].sock_acct, sess[sid].sa_acct, packet, rpack_length, sess[sid].secret);
				/* we dont care about replies */
			}
		}
		if(sess[sid].fuzz & FO_HTML)
		{
			while((fuzz_str = fuzz_html("raudius-fuzzer")) != NULL)
			{
				/* construct package: fix values */
				rhdr->code	= code;
				rhdr->id	= sess[sid].id++;
				rhdr->length	= RAD_HDR_LENGTH;
			
				/* construct package: set AVP */
				str_size	= strlen(fuzz_str);
				avp 		= (avp_t *) &rhdr->avp;
				avp->type	= (uint8_t) (attr & 0xFF);
				avp->length	= (uint8_t) (str_size+2);
				memcpy((char *) &avp->value, fuzz_str, str_size);

				rhdr->length	+= avp->length;
				rpack_length	= rhdr->length;
				rhdr->length	= htons(rhdr->length);


				I(2, "fuzz: id: %u, attribute: %u, html[%u]: '%s'",
				sess[sid].id-1, attr, ntohs(rhdr->length), fuzz_str);

				/* send RADIUS package and calculate authenticator */
				radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
				radsend(sess[sid].sock_acct, sess[sid].sa_acct, packet, rpack_length, sess[sid].secret);
				/* we dont care about replies */
			}
		}


	}

	return 0;
}


int run_username_fuzzer(int sid, char *uname)
{
	char		packet[2*RAD_PACK_MAX] __attribute__ ((packed));
	char		*fuzz_str;
	size_t		rpack_length,
			str_size;
	radpack_t	*rhdr;	// radius packet header
	avp_t		*avp;	// radius attribute value pair


	if(sid < 0 || sid >= idx || uname == NULL)
		return -1;

	I(2, "username fuzz: username: %s", uname);


	memset((char *) &packet, 0, sizeof(packet));
	rhdr = (radpack_t *) packet;

	while((fuzz_str = fuzz_format(uname)) != NULL)
	{
		/* construct package: fix values */
		rhdr->code	= PW_AUTHENTICATION_REQUEST;
		rhdr->id	= sess[sid].id++;
		rhdr->length	= RAD_HDR_LENGTH;
	
		/* construct package: set AVP */
		str_size	= strlen(fuzz_str);
		avp 		= (avp_t *) &rhdr->avp;
		avp->type	= PW_USER_NAME;
		avp->length	= (uint8_t) (str_size+2);
		memcpy((char *) &avp->value, fuzz_str, str_size);

		rhdr->length	+= avp->length;
		rpack_length	= rhdr->length;
		rhdr->length	= htons(rhdr->length);


		I(2, "username fuzz: id: %u, format[%u]: '%s'", sess[sid].id-1, ntohs(rhdr->length), fuzz_str);

		/* send RADIUS package and calculate authenticator */
		radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
		/* we dont care about replies */
	}

	while((fuzz_str = fuzz_sql(uname)) != NULL)
	{
		/* construct package: fix values */
		rhdr->code	= PW_AUTHENTICATION_REQUEST;
		rhdr->id	= sess[sid].id++;
		rhdr->length	= RAD_HDR_LENGTH;

		/* construct package: set AVP */
		str_size	= strlen(fuzz_str);
		avp 		= (avp_t *) &rhdr->avp;
		avp->type	= PW_USER_NAME;
		avp->length	= (uint8_t) (str_size+2);
		memcpy((char *) &avp->value, fuzz_str, str_size);

		rhdr->length	+= avp->length;
		rpack_length	= rhdr->length;
		rhdr->length	= htons(rhdr->length);

		I(2, "username fuzz: id: %u, sql[%u]: '%s'", sess[sid].id-1, ntohs(rhdr->length), fuzz_str);


		/* send RADIUS package and calculate authenticator */
		radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
		/* we dont care about replies */
	}

	while((fuzz_str = fuzz_ldap(uname)) != NULL)
	{
		/* construct package: fix values */
		rhdr->code	= PW_AUTHENTICATION_REQUEST;
		rhdr->id	= sess[sid].id++;
		rhdr->length	= RAD_HDR_LENGTH;

		/* construct package: set AVP */
		str_size	= strlen(fuzz_str);
		avp 		= (avp_t *) &rhdr->avp;
		avp->type	= PW_USER_NAME;
		avp->length	= (uint8_t) (str_size+2);
		memcpy((char *) &avp->value, fuzz_str, str_size);

		rhdr->length	+= avp->length;
		rpack_length	= rhdr->length;
		rhdr->length	= htons(rhdr->length);


		I(2, "username fuzz: id: %u, ldap[%u]: '%s'", sess[sid].id-1, ntohs(rhdr->length), fuzz_str);

		/* send RADIUS package and calculate authenticator */
		radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
		/* we dont care about replies */
	}

	while((fuzz_str = fuzz_shell(uname)) != NULL)
	{
		/* construct package: fix values */
		rhdr->code	= PW_AUTHENTICATION_REQUEST;
		rhdr->id	= sess[sid].id++;
		rhdr->length	= RAD_HDR_LENGTH;

		/* construct package: set AVP */
		str_size	= strlen(fuzz_str);
		avp 		= (avp_t *) &rhdr->avp;
		avp->type	= PW_USER_NAME;
		avp->length	= (uint8_t) (str_size+2);
		memcpy((char *) &avp->value, fuzz_str, str_size);

		rhdr->length	+= avp->length;
		rpack_length	= rhdr->length;
		rhdr->length	= htons(rhdr->length);


		I(2, "username fuzz: id: %u, shell[%u]: '%s'", sess[sid].id-1, ntohs(rhdr->length), fuzz_str);

		/* send RADIUS package and calculate authenticator */
		radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
		/* we dont care about replies */
	}

	while((fuzz_str = fuzz_perl(uname)) != NULL)
	{
		/* construct package: fix values */
		rhdr->code	= PW_AUTHENTICATION_REQUEST;
		rhdr->id	= sess[sid].id++;
		rhdr->length	= RAD_HDR_LENGTH;

		/* construct package: set AVP */
		str_size	= strlen(fuzz_str);
		avp 		= (avp_t *) &rhdr->avp;
		avp->type	= PW_USER_NAME;
		avp->length	= (uint8_t) (str_size+2);
		memcpy((char *) &avp->value, fuzz_str, str_size);

		rhdr->length	+= avp->length;
		rpack_length	= rhdr->length;
		rhdr->length	= htons(rhdr->length);


		I(2, "username fuzz: id: %u, perl[%u]: '%s'", sess[sid].id-1, ntohs(rhdr->length), fuzz_str);

		/* send RADIUS package and calculate authenticator */
		radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
		/* we dont care about replies */
	}

	while((fuzz_str = fuzz_html(uname)) != NULL)
	{
		/* construct package: fix values */
		rhdr->code	= PW_AUTHENTICATION_REQUEST;
		rhdr->id	= sess[sid].id++;
		rhdr->length	= RAD_HDR_LENGTH;

		/* construct package: set AVP */
		str_size	= strlen(fuzz_str);
		avp 		= (avp_t *) &rhdr->avp;
		avp->type	= PW_USER_NAME;
		avp->length	= (uint8_t) (str_size+2);
		memcpy((char *) &avp->value, fuzz_str, str_size);

		rhdr->length	+= avp->length;
		rpack_length	= rhdr->length;
		rhdr->length	= htons(rhdr->length);


		I(2, "username fuzz: id: %u, html[%u]: '%s'", sess[sid].id-1, ntohs(rhdr->length), fuzz_str);

		/* send RADIUS package and calculate authenticator */
		radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
		/* we dont care about replies */
	}

	return 0;
}


int run_realm_fuzzer(int sid, char *realm)
{
	char		packet[2*RAD_PACK_MAX] __attribute__ ((packed));
	char		*fuzz_str;
	size_t		rpack_length,
			str_size;
	radpack_t	*rhdr;	// radius packet header
	avp_t		*avp;	// radius attribute value pair


	if(sid < 0 || sid >= idx || realm == NULL)
		return -1;

	I(2, "realm fuzz: realm: %s", realm);


	memset((char *) &packet, 0, sizeof(packet));
	rhdr = (radpack_t *) packet;

	while((fuzz_str = fuzz_format(realm)) != NULL)
	{
		/* construct package: fix values */
		rhdr->code	= PW_AUTHENTICATION_REQUEST;
		rhdr->id	= sess[sid].id++;
		rhdr->length	= RAD_HDR_LENGTH;
	
		/* construct package: set AVP */
		str_size	= strlen(fuzz_str);
		avp 		= (avp_t *) &rhdr->avp;
		avp->type	= PW_USER_NAME;
		avp->length	= (uint8_t) (str_size+2);
		memcpy((char *) &avp->value, fuzz_str, str_size);

		rhdr->length	+= avp->length;
		rpack_length	= rhdr->length;
		rhdr->length	= htons(rhdr->length);


		I(2, "realm fuzz: id: %u, format[%u]: '%s'", sess[sid].id-1, ntohs(rhdr->length), fuzz_str);

		/* send RADIUS package and calculate authenticator */
		radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
		/* we dont care about replies */
	}

	while((fuzz_str = fuzz_sql(realm)) != NULL)
	{
		/* construct package: fix values */
		rhdr->code	= PW_AUTHENTICATION_REQUEST;
		rhdr->id	= sess[sid].id++;
		rhdr->length	= RAD_HDR_LENGTH;

		/* construct package: set AVP */
		str_size	= strlen(fuzz_str);
		avp 		= (avp_t *) &rhdr->avp;
		avp->type	= PW_USER_NAME;
		avp->length	= (uint8_t) (str_size+2);
		memcpy((char *) &avp->value, fuzz_str, str_size);

		rhdr->length	+= avp->length;
		rpack_length	= rhdr->length;
		rhdr->length	= htons(rhdr->length);

		I(2, "realm fuzz: id: %u, sql[%u]: '%s'", sess[sid].id-1, ntohs(rhdr->length), fuzz_str);


		/* send RADIUS package and calculate authenticator */
		radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
		/* we dont care about replies */
	}

	while((fuzz_str = fuzz_ldap(realm)) != NULL)
	{
		/* construct package: fix values */
		rhdr->code	= PW_AUTHENTICATION_REQUEST;
		rhdr->id	= sess[sid].id++;
		rhdr->length	= RAD_HDR_LENGTH;

		/* construct package: set AVP */
		str_size	= strlen(fuzz_str);
		avp 		= (avp_t *) &rhdr->avp;
		avp->type	= PW_USER_NAME;
		avp->length	= (uint8_t) (str_size+2);
		memcpy((char *) &avp->value, fuzz_str, str_size);

		rhdr->length	+= avp->length;
		rpack_length	= rhdr->length;
		rhdr->length	= htons(rhdr->length);


		I(2, "realm fuzz: id: %u, ldap[%u]: '%s'", sess[sid].id-1, ntohs(rhdr->length), fuzz_str);

		/* send RADIUS package and calculate authenticator */
		radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
		/* we dont care about replies */
	}

	while((fuzz_str = fuzz_shell(realm)) != NULL)
	{
		/* construct package: fix values */
		rhdr->code	= PW_AUTHENTICATION_REQUEST;
		rhdr->id	= sess[sid].id++;
		rhdr->length	= RAD_HDR_LENGTH;

		/* construct package: set AVP */
		str_size	= strlen(fuzz_str);
		avp 		= (avp_t *) &rhdr->avp;
		avp->type	= PW_USER_NAME;
		avp->length	= (uint8_t) (str_size+2);
		memcpy((char *) &avp->value, fuzz_str, str_size);

		rhdr->length	+= avp->length;
		rpack_length	= rhdr->length;
		rhdr->length	= htons(rhdr->length);


		I(2, "realm fuzz: id: %u, shell[%u]: '%s'", sess[sid].id-1, ntohs(rhdr->length), fuzz_str);

		/* send RADIUS package and calculate authenticator */
		radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
		/* we dont care about replies */
	}

	while((fuzz_str = fuzz_perl(realm)) != NULL)
	{
		/* construct package: fix values */
		rhdr->code	= PW_AUTHENTICATION_REQUEST;
		rhdr->id	= sess[sid].id++;
		rhdr->length	= RAD_HDR_LENGTH;

		/* construct package: set AVP */
		str_size	= strlen(fuzz_str);
		avp 		= (avp_t *) &rhdr->avp;
		avp->type	= PW_USER_NAME;
		avp->length	= (uint8_t) (str_size+2);
		memcpy((char *) &avp->value, fuzz_str, str_size);

		rhdr->length	+= avp->length;
		rpack_length	= rhdr->length;
		rhdr->length	= htons(rhdr->length);


		I(2, "realm fuzz: id: %u, perl[%u]: '%s'", sess[sid].id-1, ntohs(rhdr->length), fuzz_str);

		/* send RADIUS package and calculate authenticator */
		radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
		/* we dont care about replies */
	}

	while((fuzz_str = fuzz_html(realm)) != NULL)
	{
		/* construct package: fix values */
		rhdr->code	= PW_AUTHENTICATION_REQUEST;
		rhdr->id	= sess[sid].id++;
		rhdr->length	= RAD_HDR_LENGTH;

		/* construct package: set AVP */
		str_size	= strlen(fuzz_str);
		avp 		= (avp_t *) &rhdr->avp;
		avp->type	= PW_USER_NAME;
		avp->length	= (uint8_t) (str_size+2);
		memcpy((char *) &avp->value, fuzz_str, str_size);

		rhdr->length	+= avp->length;
		rpack_length	= rhdr->length;
		rhdr->length	= htons(rhdr->length);


		I(2, "realm fuzz: id: %u, html[%u]: '%s'", sess[sid].id-1, ntohs(rhdr->length), fuzz_str);

		/* send RADIUS package and calculate authenticator */
		radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
		/* we dont care about replies */
	}

	return 0;
}


int run_vsa_fuzzer(int sid, uint8_t code)
{
	uint16_t	avp_length,
			vsa_type,
			vsa_length;
	uint32_t	id;
	char		packet[2*RAD_PACK_MAX] __attribute__ ((packed));
	size_t		rpack_length;
	radpack_t	*rhdr;	// radius packet header
	avp_t		*avp;	// radius attribute value pair
	vsa_t		*vsa;	// radius vendor specific attribute


	if(sid < 0 || sid >= idx)
		return -1;

	for(id = sess[sid].vid_start; id <= sess[sid].vid_end; id++)
	{
	I(2, "VSA fuzz: code: %u, vendor ID: %u", code, id);


	memset((char *) &packet, 0, sizeof(packet));
	rhdr = (radpack_t *) packet;


	/* construct package: fix values */
	rhdr->code	= code; //PW_AUTHENTICATION_REQUEST; // does this matter?
	rhdr->length	= RAD_HDR_LENGTH;
	
	/* construct package: set AVP */
	avp 		= (avp_t *) &rhdr->avp;
	avp->type	= PW_VENDOR_SPECIFIC;

	/* fuzz to death: 255^3 = more than 16 million packets per vendor ID!!! */
	for(avp_length = 0; avp_length <= 0xFF; avp_length++)
	{
		avp->length	= (uint8_t) avp_length;
		vsa		= (vsa_t *) &avp->value;
		vsa->id		= id;

		for(vsa_type = 0; vsa_type <= 0xFF; vsa_type++)
		{
			vsa->type = vsa_type;

			for(vsa_length = 0; vsa_length <= 0xFF; vsa_length++)
			{
				vsa->length	= vsa_length;
				memset(&vsa->value, 'A', vsa->length);

				/* setting this to the full size makes radiusd
				** parsing over the padding segment (zeros) 
				rhdr->length	= htons(RAD_PACK_MAX);
				rpack_length	= RAD_PACK_MAX;*/
				rhdr->length	= RAD_HDR_LENGTH + avp->length + vsa->length;
				rpack_length	= rhdr->length;
				rhdr->length	= htons(rhdr->length);
				rhdr->id	= ++sess[sid].id;

				I(2, "VSA fuzz: id: %u, avp->length: %u, vsa->type: %u, vsa->length: %u, packet length: %u",
					sess[sid].id, avp->length, vsa->type, vsa->length, rpack_length);

				radsend(sess[sid].sock_auth, sess[sid].sa_auth, packet, rpack_length, sess[sid].secret);
			}
		}
	}
	} // for(id)

	return 0;
}


// EOF
