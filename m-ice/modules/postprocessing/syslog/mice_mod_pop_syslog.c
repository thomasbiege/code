/***************************************************************************
                          mice_mod_pop_syslog.c  -  description
                             -------------------
    copyright            : (C) 2003 by Thomas Biege
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>

#include <mice.h>
#include "mice_mod_pop_syslog.h"


int mice_mod_syslog_LTX_init(char *ConfigFile)
{
  log_open("mice_mod_pop_syslog", LOG_PID, LOG_USER);
  return(EXIT_SUCCESS);
}

int mice_mod_syslog_LTX_func(LogFormat LogFmt)
{
  log_mesg(WARN, "Host: %s | OpSystem: %s | Release: %s | Version: %s | Date: %s | Time: %s | Logline: %s\n", LogFmt.cHost, LogFmt.cOSystem, LogFmt.cRelease, LogFmt.cVersion, LogFmt.cDate, LogFmt.cTime, LogFmt.cLogLine);
  return(EXIT_SUCCESS);
}

