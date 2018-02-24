#ifndef __LIBMICE
#define __LIBMICE

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
extern int errno;

#define MAX_CHARS	4096

#define WARN        0
#define WARN_SYS    1
#define FATAL       2
#define FATAL_SYS   3
#define DUMP        4

#ifndef TRUE
  #define TRUE  1
  #define FALSE 0
#endif


#define LOG(syslog, kind, args...) \
do{ \
    if(syslog)  log_mesg(kind, ##args);  \
    else        err_mesg(kind, ##args);  \
} while(0);


/* Caller of log_mesg() or log_open() have to set
** 'debug':
**     0 => interaktiv
**     1 => daemon process
*/
int  _err_debug;
char *_err_pname;


void		err_mesg(int iID, const char *ccFmt, ...);
void		log_mesg(int iID, const char *ccFmt, ...);
void		debug(int iSyslog, int iDebugLevel, int iThreshold, const char *ccFmt, ...);
void		log_open(const char *ccID, int iOption, int iFacility);

unsigned	name_resolve(char *hostname);
char		*host_lookup(unsigned long in);

int		set_signal(int sig, void (*fkt_ptr) (int));

char		*host_err_str(void);
int		tcp_open(char *host, char *service, int port);
int		udp_open(char *host, char *service, int port, int dontconn);
int		readn(register int fd, register char *ptr, register int nbytes);
int		writen(register int fd, const char *ptr, register int nbytes);
int		readline(register int fd, register char *ptr, register int maxlen);
int		read_stream(int fd, char *ptr, int maxbytes);
void		str_echo(int sockfd);
void		str_cli(FILE *fp, register int sockfd);
void		dg_echo(int sockfd, struct sockaddr *pcli_addr, int maxclilen);
void		dg_cli(FILE *fp, int sockfd, struct sockaddr *pserv_addr, int servlen);

int		make_pidfile(const char *pathname, int force);

#endif
