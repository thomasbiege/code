#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <mice_pseudo.h>

#define USAGE   errx(-1, "usage: pseudo_key_gen\n"\
                         "\t\t\t--file <string>\n"\
                         "\t\t\t--encode\n\n")

#define MAX_KEYS     10
#define MAX_KEYLEN  100


int main(int argc, char **argv)
{
  char          **keys = NULL,
                *filename = NULL,
                *pseudo_key = NULL,
                *pseudo_key_enc = NULL;
  size_t        num_keys, key_len;
  int           cmd_opt = 0,
                opt_idx = 0,
                flag_encode = 0;
  FILE          *file = stdout;
  struct option long_options[] =
                {
                  {"file"   , 1, 0, 'f'},
                  {"encode" , 0, 0, 'e'},
                  {     0   , 0, 0,  0 }
                };


  opterr = 0;
  while((cmd_opt = getopt_long(argc, argv, "f:e", long_options, &opt_idx)) != EOF)
  {
    switch(cmd_opt)
    {
      case 'f':
        filename = strdup(optarg);
        if((file = fopen(filename, "w")) == NULL)
          errx(-1, "error: cannot open file '%s'\n", filename);
        break;
      case 'e':
        flag_encode = 1;
        break;
      case '?':
      default:
        USAGE;
    }
  }

  
  printf("enter keys (max. %d)...\n", MAX_KEYS);

  keys = (char **) malloc(MAX_KEYS);

  for(num_keys = 0; num_keys < MAX_KEYS; num_keys++)
  {
    keys[num_keys] = (char *) malloc(MAX_KEYLEN+1);
    
    memset(keys[num_keys], 0, MAX_KEYLEN+1);
    
    printf("\t%u. key (max. 100): ", num_keys+1);
    scanf("%100[a-zA-Z0-9]s", keys[num_keys]);
    
    while(getchar() != '\n')
      ;
      
    keys[num_keys][strlen(keys[num_keys])] = '\0';
    
    if(strlen(keys[num_keys]) == 0)
      break;
  }

  printf("\ngenerate combined key\n");
  if( (pseudo_key = psd_generate_key(num_keys, keys, &key_len)) == NULL)
    errx(-1, "\terror: psd_generate_key(num_keys = %u)\n", num_keys);

  printf("\nwrite key...\n");
  if(flag_encode)
  {
    if((pseudo_key_enc = psd_ascii_encode(pseudo_key, key_len)) == NULL)
      errx(-1, "\terror: psd_ascii_encode()\n");
  }
  else
    pseudo_key_enc = pseudo_key;

  fprintf(file, "%s", pseudo_key_enc);
  fflush(file);
  putchar('\n');
      
  if(pseudo_key != NULL)
    free(pseudo_key);
  if(pseudo_key_enc != NULL)
    free(pseudo_key_enc);
  if(filename != NULL)
    free(filename);
  fclose(file);

  exit(0);
}
