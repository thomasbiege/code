#include <sys/types.h>
#include <stdio.h>
#include <err.h>

int main(int argc, char **argv)
{
	FILE *f = NULL;
	char l[20];

	if(argc != 2)
		errx(-1, "usage: %s <filename>", argv[0]);

	f = fopen(argv[1], "r");
	if(f == NULL)
		err(-1, "error: opening file '%s'", argv[1]);

	while(fgets(l, sizeof(l), f) != NULL)	
	{
		u_int occ;
		char  num[10];
		u_int num_bin;
		u_int base = 10;

#ifdef DBG
		printf("%s", l);
#endif

		if(sscanf(l, "%s %u\n", num, &occ) != 2)
			continue;

		if(strncmp(num, "0x", 2) == 0)
			base = 16;

		num_bin = (u_int) strtol(num, NULL, base);
		if(num_bin == 0)
			continue;

#ifdef DBG
		if(base == 16)
			printf("value %x occured %u times\n", num_bin, occ);
		else
			printf("value %u occured %u times\n", num_bin, occ);
#endif
#ifndef DBG
		for(; occ > 0; occ--)
			putchar(num_bin);
#endif
	}
	fclose(f);	
	
	return 0;
}
