/***************************************************************************
                          errormsg.c  -  description
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

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include "errormsg.h"

int   _debug;
int   _err_debug;
char  *_err_pname;


/* --- local funktions --- */
static void	err_message(int sys_mesg, const char *fmt, va_list az)
{
	int	error_no = errno;
	char	puffer[MAX_CHARS];
	
	vsnprintf(puffer, sizeof(puffer), fmt, az);
	if(sys_mesg)
		snprintf(puffer+strlen(puffer), sizeof(puffer)-strlen(puffer), ": %s ", strerror(error_no));
		
	fflush(stdout);
	fprintf(stderr, "%s\n", puffer);
	fflush(NULL);	/* flush all O-Buffers */
	
	return;
}

static void	log_message(int sys_mesg, int prio, const char *fmt, va_list az)
{
	int	error_no = errno;
	char	puffer[MAX_CHARS];
	
	vsnprintf(puffer, sizeof(puffer), fmt, az);
	if(sys_mesg)
		snprintf(puffer+strlen(puffer), sizeof(puffer)-strlen(puffer), ": %s ", strerror(error_no));
		
	if(_debug)
	{
		fflush(stdout);
		fprintf(stderr, "%s\n", puffer);
		fflush(NULL);
	}
	else
	{
		strcat(puffer, "\n");
		syslog(prio, "%s", puffer);
	}
	
	return;
}


/* --- global funktions --- */
void	err_mesg(int iID, const char *ccFmt, ...)
{
	va_list	az;
	
	va_start(az, ccFmt);
	switch(iID)
	{
		case WARN:
		case FATAL:
			err_message(0, ccFmt, az);
			break;
		case WARN_SYS:
		case FATAL_SYS:
			err_message(1, ccFmt, az);
			break;
		default:
			exit(3);
	}
	va_end(az);
	
	if(iID == WARN || iID == WARN_SYS)
		return;
	if(iID == DUMP)
		abort();
		
	exit(1);
}

void	log_mesg(int iID, const char *ccFmt, ...)
{
	va_list	az;
	
	va_start(az, ccFmt);
	switch(iID)
	{
		case WARN:
		case FATAL:
			log_message(0, LOG_ERR, ccFmt, az);
			break;
		case WARN_SYS:
		case FATAL_SYS:
			log_message(1, LOG_ERR, ccFmt, az);
			break;
		default:
			log_message(1, LOG_ERR, "Incorrect parameters for 'log_mesg()' ...", az);
			exit(3);
	}
	va_end(az);
	
	if(iID == WARN || iID == WARN_SYS)
		return;

	exit(2);
}

/* --- init syslog() --- */
void	log_open(const char *ccID, int iOption, int iFacility)
{
	if(_debug == 0)
		openlog(ccID, iOption, iFacility);
}

/* --- debug routine --- */
void debug(int iSyslog, int iDebugLevel, int iThreshold, const char *ccFmt, ...)
{
  va_list  az;

  va_start(az, ccFmt);

  if(iDebugLevel >= iThreshold)
  {
    if(iSyslog == TRUE)
      log_message(0, LOG_ERR, ccFmt, az);
    else
      err_message(0, ccFmt, az);
  }

  va_end(az);

  return;
}

