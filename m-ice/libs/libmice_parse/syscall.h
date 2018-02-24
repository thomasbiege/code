#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(*(array)))
#endif

#include <logformat.h>

#define MAX_ARGS  8
struct syscall_data {
  unsigned int  major, minor;
  int    result;
  unsigned int  nargs;
  struct syscall_arg {
      int    type;
      const void *data;
      size_t  len;
  }    args[MAX_ARGS];
};

/*
 * Print primitives
 */
struct bitname {
  const char *  name;
  unsigned int  value;
  unsigned int  mask;
};
#define defbit(bit)  { #bit, bit, bit }

struct symbol {
  const char *  name;
  unsigned long  value;
};
#define defsym(sym)  { #sym, sym }


void                  get_result(long result, laus_scall_result *res);
struct syscall_info * syscall_get_name(unsigned int major, unsigned int minor, char *name, size_t name_len);
int                   syscall_get(struct syscall_data *sc, laus_scall *scall);
