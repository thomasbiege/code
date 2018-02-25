#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>

int main(int argc, char **argv)
{
	int	i;
	int	opt;
	int	arg_n       = -1;	// integer
	char	*arg_s      = NULL;     // string with ascii content
	char	arg_b[4096] ={0};       // string with binary content
	char	*arg_shell  = NULL;     // string with shellcmd
	char	*arg_fmt    = NULL;     // string with format tags in it
	char	*arg_sep    = NULL;     // string with different separators in it
	char	*arg_sql    = NULL;     // string with SQL keywords in it
	char	*dst_buf    = NULL;
	char	*p          = NULL;

	opterr = 1;
	while((opt = getopt(argc, argv, "n:s:b:S:f:F:Q:")) != EOF)
	{
		switch(opt)
		{
			case 'n':
				if(optarg == NULL || optarg[0] == '-' || !isdigit(optarg[0]))
					errx(-1, "%s: arg n is missing or is not a digit\n", __FILE__);
				arg_n = atoi(optarg);
				break;
			case 's':
				if(optarg == NULL || optarg[0] == '-' || !isascii(optarg[0]))
					errx(-1, "%s: arg s is missing or is not ascii\n", __FILE__);
				arg_s = strdup(optarg);
				break;
			case 'b':
				if(optarg == NULL || optarg[0] == '-')
					errx(-1, "%s: arg b is missing\n", __FILE__);
				memcpy(&arg_b, optarg, sizeof(arg_b));
				break;
			case 'S':
				if(optarg == NULL || optarg[0] == '-' || !isascii(optarg[0]))
					errx(-1, "%s: arg shell is missing or is not ascii\n", __FILE__);
				arg_shell = strdup(optarg);
				break;
			case 'f':
				if(optarg == NULL || optarg[0] == '-' || !isascii(optarg[0]))
					errx(-1, "%s: arg fmt is missing or is not ascii\n", __FILE__);
				arg_fmt = strdup(optarg);
				break;
			case 'F':
				if(optarg == NULL || optarg[0] == '-' || !isascii(optarg[0]))
					errx(-1, "%s: arg sep is missing or is not ascii\n", __FILE__);
				arg_sep = strdup(optarg);
				break;
                        case 'Q':
                                if(optarg == NULL || optarg[0] == '-' || !isascii(optarg[0]))
                                        errx(-1, "%s: arg sql is missing or is not ascii\n", __FILE__);
                                arg_sql = strdup(optarg);
                                break;



		}
	}

	//if(arg_n == -1 || arg_s == NULL)
	//	errx(-1, "arg n/s is missing\n");


	if(arg_s != NULL)
	{
		fprintf(stderr, "%s: Buffer Overflow Test with String and Length provided by Caller.\n", __FILE__);
		fprintf(stderr, "%s: arg_s and arg_n: %u, %u\n", __FILE__, strlen(arg_s), arg_n);

		dst_buf = (char *) malloc(arg_n+1);
		if(dst_buf == NULL)
			err(-1, "\t%s: error while calling malloc().", __FILE__);
		memset(dst_buf, 0, arg_n+1);

		fprintf(stderr, "\t%s: calling strcpy\n", __FILE__);
		strcpy(dst_buf, arg_s);

		free(arg_s);
		free(dst_buf);
	}
	if(arg_b[0] != 0)
	{
		fprintf(stderr, "%s: Buffer Overflow Test with Binary-String provided by Caller and looking for Delimiter ('b').\n", __FILE__);

		dst_buf = (char *) malloc(strlen(arg_b)+1);
		if(dst_buf == NULL)
			err(-1, "\n%serror while calling malloc().", __FILE__);
		memset(dst_buf, 0, strlen(arg_b)+1);

		for(i = 0; arg_b[i] != 'b' && arg_b[i]; i++)
			;
		p = &arg_b[i];
		fprintf(stderr, "\t%s: calling strcpy\n", __FILE__);
		strcpy(dst_buf,p);

		free(dst_buf);
	}
	if(arg_shell != NULL)
	{
		fprintf(stderr, "%s: Shell Metachar Test with String provided by Caller.\n", __FILE__);
		fprintf(stderr, "%s: arg_shell: %s\n", __FILE__, arg_shell);
		system(arg_shell);
		free(arg_shell);
	}
	if(arg_fmt != NULL)
	{
		fprintf(stderr, "%s: Format-Bug Test with String provided by Caller.\n", __FILE__);
		fprintf(stderr, "%s: arg_fmt: '%s'\n", __FILE__, arg_fmt);
		printf(arg_fmt); putchar('\n');
		free(arg_fmt);
	}
	if(arg_sep != NULL)
	{
		fprintf(stderr, "%s: Separator Test with String provided by Caller.\n", __FILE__);
		fprintf(stderr, "%s: arg_sep: '%s' [%u]\n", __FILE__, arg_sep, strlen(arg_sep));
		printf(arg_sep); putchar('\n');
		free(arg_sep);
	}
	if(arg_sql != NULL)
	{
		fprintf(stderr, "%s: SQL Injection Test with String provided by Caller.\n", __FILE__);
		fprintf(stderr, "%s: arg_sql: '%s' [%u]\n", __FILE__, arg_sql, strlen(arg_sql));
		printf(arg_sql); putchar('\n');
		free(arg_sql);
	}


	fprintf(stderr, "\n%s: done\n\n\n", __FILE__);
	exit(0);
}

