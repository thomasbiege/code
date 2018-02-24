/***************************************************************************
                          secprog.h  -  description
                             -------------------
    begin                : Tue Feb 27 2001
    copyright            : (C) 2001 by Thomas Biege
    email                : thomas@uin4d.de
 ***************************************************************************/
#ifndef __LIBSECPROG
#define __LIBSECPROG

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <pwd.h>
#include <syslog.h>
#include <limits.h>   // ANSI C compile-time limits
#include <errno.h>



#ifndef TRUE
# define TRUE  1
# define FALSE 0
#endif

#define SP_OFF  0     // to turn protection off
#define SP_ON   1     // to turn protection on

#ifndef O_NOFOLLOW
# define O_NOFOLLOW 0  // was introduced in kernel 2.1.126, needs glibc > 2.0.100
#endif

#define NUMENVENT	20
#define ENVENTLEN 255

#define SL_CORE         1
#define SL_UPROC        2

#define CPP_ERROR       0
#define CPP_DEPTH       1
#define CPP_PATHHIT     2
#define CPP_PATHNOHIT   3
#define CPP_PATH2SMALL  4
#define CPP_STSET       5
#define CPP_OUTOFMEM    6
#define CPP_ISNOPATH    7

#define CPP_UNSET       0
#define CPP_SET         1
#define CPP_HIT         2
#define CPP_NOHIT       3

extern u_int se_closefds;

typedef struct
{
  int fsize;          /* max file size */
  int data;           /* max data size */
  int stack;          /* max stack size */
  int core;           /* max core file size */
  int rss;            /* max resident set size */
  int nproc;          /* max number of processes */
  int nofile;         /* max number of open files */
  int memlock;        /* max locked-in-memory address space */
} sl_limit;


extern char	*s_strncpy(char *dest, char *src, size_t n);
extern char	*s_strncat(char *dest, char *src, size_t n);
extern int	s_execv(const char *filename, char *const argv[]);
extern FILE	*s_tmpfile(void);
extern FILE	*s_popen(char *cmd, const char *type);
extern int	safe_tmpfile(char *filename);
extern int 	safe_reopen(char *file, int mode);
extern int	sigprotection(u_int toggle, sigset_t *sp_blockmask);
extern int	close_stdfds(void);
extern int	setlimits(sl_limit slim);
extern int	setupsbitproc(void);

#endif
