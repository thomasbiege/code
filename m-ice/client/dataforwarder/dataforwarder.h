/***************************************************************************
                          dataforwarder.h  -  description
                             -------------------
    begin                : Wed Feb 21 2001
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

#ifndef __DATAFORWARDER__
#define __DATAFORWARDER__

/*
** Limits
*/
#define MAX_FILTER    10

#define MAX_ARGC     100

#define MAX_ERRORS     5

#define PATHCONFFILE  "/etc/M-ICE/dataforwarder.conf"

/*
** Default Values
*/
#define CONFSLFAC   "LOG_DAEMON"

/*
** Define Names of valid Sections in the Conf File
*/
#define SECT_SQLSRV    "SQL_SERVER"
#define SECT_ANASRV    "ANALYSIS_SERVER"
#define SECT_SECNPRV   "SECURITY_AND_PRIVACY"
#define SECT_LOGFLST   "LOGFILE_LIST"
#define SECT_MODPATH   "MODULES_SEARCH_PATH"
#define SECT_MODULES   "MODULES"
#define SECT_MODCONF   "MODULES_CONFIG_FILE"
#define SECT_MISC      "MISC"
#define SECT_MAXSECT   8

/*
** PID Files
*/
#define PIDMAIN   "datafwd-main.pid"
#define PIDFDSRV  "datafwd-fdescserver.pid"
#define PIDLOGWA  "datafwd-logwatch.pid"

/*
** Misc
*/
#define SYMNAME_INIT  "init"       // <modulename>_LXT_init
#define SYMNAME_FUNC  "func"       // <modulename>_LXT_func

#define NORANDOM      "soft"

#ifndef TRUE
  #define TRUE  1
  #define FALSE 0
#endif

/*
** Error Codes
*/
#define PCR_INVALIDARGC   -1
#define PCR_INVALIDCMD    -2

/*
** FdescServer Commands
*/
#define FS_CMD_OPEN     "open "
#define FS_CMD_TERM     "term "
#define FS_CMD_PID      "pid "


char      *cProgname;

#endif
