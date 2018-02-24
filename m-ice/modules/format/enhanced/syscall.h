#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(*(array)))
#endif

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


struct laus_scall_result
{
#define SCRESULTTYPE_NUL  0x00
#define SCRESULTTYPE_PTR  0x01
#define SCRESULTTYPE_INT  0x02
#define SCRESULTTYPE_ERR  0x03
  int   type;
  long  value;
};

struct laus_scall
{
  struct laus_scall_result  result;
  char                      *name;
  int                       major;
  int                       minor;
  int                       nargs;
};

void                  _mice_mod_pop_mysql_get_result(long result, struct laus_scall_result *res);
struct syscall_info * _mice_mod_pop_mysql_syscall_get_name(unsigned int major, unsigned int minor, char *name, size_t name_len);
int                   _mice_mod_pop_mysql_syscall_get(struct syscall_data *sc, struct laus_scall *scall);
