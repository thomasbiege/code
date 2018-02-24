#ifndef _FUZZER_H_
#define _FUZZER_H_

#include <sys/types.h>

#define FO_ALL		0xFFFFFF
#define FO_NONE		0x000000
#define FO_OVERFLOW	0x000001
#define FO_FORMAT	0x000002
#define FO_LENGTH	0x000004
#define FO_INTEGER	0x000010
#define FO_SQL		0x000020
#define FO_SHELL	0x000040
#define FO_LDAP		0x000100
#define FO_HTML		0x000200
#define FO_PERL		0x000400
#define FO_USER		0x001000
#define FO_REALM	0x002000
#define FO_VSA		0x004000


char *fuzz_format(char *str);
char *fuzz_sql(char *str);
char *fuzz_shell(char *str);
char *fuzz_perl(char *str);
char *fuzz_ldap(char *str);
char *fuzz_html(char *str);
// vsa_t *fuzz_html(void);


#endif
