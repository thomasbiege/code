#ifndef __ERRORHDR
#define __ERRORHDR

#define MAX_CHARS	4096

#define WARN        0
#define WARN_SYS    1
#define FATAL       2
#define FATAL_SYS   3
#define DUMP        4

extern int      _debug;		/* Caller of log_mesg() or log_open() have to
				 * set 'debug':	0 => interaktiv 1 => daemon
				 * process */


/* --- main error handling funktions --- */
extern void     err_mesg(int iID, const char *ccFmt,...);
extern void     log_mesg(int iID, const char *ccFmt,...);

/* --- log_open inits syslog() for daemon processes --- */
extern void     log_open(const char *ccID, int iOption, int iFacility);


#endif
