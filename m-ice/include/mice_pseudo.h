#ifndef __LIBMICE_PSEUDO_HDR__
#define __LIBMICE_PSEUDO_HDR__

#include <sys/types.h>
#include <mcrypt.h>


int    psd_init(void);
int    psd_deinit(void);
char  *psd_set_key(char *key, size_t *key_len);
char  *psd_generate_key(size_t num_keys, char **keys, size_t *key_len);
char  *psd_deidentify(char *identifier);
char  *psd_reidentify(char *pseudonym);
long   psd_deidentify_num(long identifier, char *key, size_t key_len);
long   psd_reidentify_num(long pseudonym, char *key, size_t key_len);
char  *psd_ascii_encode(char *bin_string, size_t bin_len);
char  *psd_ascii_decode(char *char_string, size_t *bin_len);

#endif
