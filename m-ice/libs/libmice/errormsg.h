/***************************************************************************
                          errormsg.h  -  description
                             -------------------
    begin                : Thu Feb 22 2001
    copyright            : (C) 2001 by Thomas Biege
    email                : thomas@uin4d.de
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#ifndef __ERRORHDR
#define __ERRORHDR

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


#define LOG(syslog, args...) \
{ \
    if(syslog)  log_mesg(##args);  \
    else        err_mesg(##args);  \
}


extern int  _err_debug;   /* Caller of log_mesg() or log_open() have to set
                          ** 'debug':
                          **     0 => interaktiv
                          **     1 => daemon process
                          */
extern char *_err_pname;


/* --- main error handling funktions --- */
extern void  err_mesg(int iID, const char *ccFmt, ...);
extern void  log_mesg(int iID, const char *ccFmt, ...);
extern void  debug(int iSyslog, int iDebugLevel, int iThreshold, const char
                       *ccFmt, ...);

/* --- log_open inits syslog() for daemon processes --- */
extern void  log_open(const char *ccID, int iOption, int iFacility);


#endif

