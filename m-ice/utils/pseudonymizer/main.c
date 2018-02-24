#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <mice_pseudo.h>

#define USAGE   errx(-1, "usage: pseudonymizer\n"\
                         "\t\t\t--identifier     <string>\n"\
                         "\t\t\t--pseudonym      <string>\n"\
                         "\t\t\t--identifier_num <positive number>\n"\
                         "\t\t\t--pseudonym_num  <positive number>\n\n")

#define MAX_KEYS     10
#define MAX_KEYLEN  100

                         
int main(int argc, char **argv)
{
  char          **keys = NULL,
                *identifier = NULL,
                *pseudonym = NULL,
                *pseudo_key;
  size_t        num_keys, key_len;
  int           cmd_opt = 0,
                opt_idx = 0;
  long          identifier_num = -1,
                pseudonym_num = -1;
  struct option long_options[] =
                {
                  {"identifier"     , 1, 0, 'i'},
                  {"pseudonym"      , 1, 0, 'p'},
                  {"identifier_num" , 1, 0, 'I'},
                  {"pseudonym_num"  , 1, 0, 'P'},
                  {         0       , 0, 0,  0 }
                };

                
  if(argc != 2)
    USAGE;

  opterr = 0;
  while((cmd_opt = getopt_long(argc, argv, "i:p:I:P:", long_options, &opt_idx)) != EOF)
  {
    switch(cmd_opt)
    {
      case 'i':
        if(optarg != NULL)
          identifier = strdup(optarg);
        break;
      case 'p':
        if(optarg != NULL)
          pseudonym  = strdup(optarg);
        break;
      case 'I':
        if(optarg != NULL)
          identifier_num = atol(optarg);
        break;
      case 'P':
        if(optarg != NULL)
          pseudonym_num  = atol(optarg);
        break;
      case '?':
      default:
        USAGE;
    }
  }

  if(identifier == NULL && pseudonym == NULL && identifier_num < 0 && pseudonym_num < 0)
    USAGE;
  if(identifier != NULL && pseudonym != NULL && identifier_num >= 0 && pseudonym_num >= 0)
    USAGE;

  //printf("encoding test:\n");
  //printf("\tbin = %s --> ascii = %s\n", "thomas", psd_ascii_encode("thomas", strlen("thomas"), &key_len));

          
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

  printf("\ninit. pseudonymisation framework\n");
  if(psd_init() < 0)
    errx(-1, "\terror: psd_init()\n");


  if(identifier != NULL)
  {
    printf("\ndeidentify\n");
    if( (pseudonym = psd_deidentify(identifier)) == NULL)
      errx(-1, "\terror: psd_deidentify(identifier = %s)\n", identifier);
  }
  else if(pseudonym != NULL)
  {
    printf("\nreidentify\n");
    if( (identifier = psd_reidentify(pseudonym)) == NULL)
      errx(-1, "\terror: psd_reidentify(pseudonym = %s)\n", pseudonym);
  }

  if(identifier_num >= 0)
  {
    printf("\ndeidentify number\n");
    pseudonym_num = psd_deidentify_num(identifier_num, pseudo_key, key_len);
  }
  else if(pseudonym_num > 0)
  {
    printf("\nreidentify number\n");
    identifier_num = psd_reidentify_num(pseudonym_num, pseudo_key, key_len);
  }

  printf("\nresult:\n");
  if(identifier != NULL)
    printf("\tidentifier[%u] = %s, pseudonym[%u] = %s\n", strlen(identifier), identifier, strlen(pseudonym), pseudonym);
  if(identifier_num >= 0)
    printf("\tidentifier_num = %ld, pseudonym_num = %ld\n", identifier_num, pseudonym_num);
  
  printf("\ndeinit. pseudonymisation framework\n");
  if(psd_deinit() < 0)
    errx(-1, "\terror: psd_init()\n");

  if(pseudo_key != NULL)
    free(pseudo_key);
  if(identifier != NULL)
    free(identifier);
  if(pseudonym != NULL)
    free(pseudonym);
    
  exit(0);    
}
