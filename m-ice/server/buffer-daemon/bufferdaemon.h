/***************************************************************************
                          bufferdaemon.h  -  description
                             -------------------
    begin                : Sat May 5 2001
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

#ifndef __BUFFERDAEMON__
#define __BUFFERDAEMON__

/*
** Limits
*/
#define MAX_FILTER    10
#define MAX_OS        20
#define MAX_RELEASE   20
#define MAX_VERSION   20
#define MAX_DATE      30
#define MAX_TIME      30
#define MAX_IP        30
#define MAX_ARGC     100
//#define MAX_HOST     256
#define MAX_DATA    1024

#define MAX_ERRORS     5

/*
** Default Values
*/
#define CONFSLFAC   "LOG_DAEMON"

/*
** Define Names of valid Sections in the Conf File
*/
#define IPADDR      "ADDRESS"
#define PORTNUM     "PORT_NUMBER"
#define MODPATH     "MODULES_SEARCH_PATH"
#define DECMODS     "DECODING_MODULES"
#define DECCONFFILE "DECODING_MODULES_CONFIG_FILE"
#define POPMODS     "POSTPROC_MODULES"
#define POPCONFFILE "POSTPROC_MODULES_CONFIG_FILE"
#define TIMINV      "TIME_INTERVALS"
#define CACHE       "CACHE_AND_RINGBUFFER"
#define SECNPRV     "SECURITY_AND_PRIVACY"
#define MISC        "MISC"
#define MAXSECT     11

/*
** PID Files
*/
#define PIDMAIN   "bufferdaemon-main.pid"
#define PIDTIMER  "bufferdaemon-timer.pid"

/*
** Misc
*/
#define NORANDOM      "soft"
#define PATHCONFFILE  "/etc/M-ICE/bufferdaemon.conf"
#define SYMNAME_INIT  "init"       // <modulename>_LTX_init
#define SYMNAME_FUNC  "func"       // <modulename>_LTX_func

#ifndef TRUE
  #define TRUE  1
  #define FALSE 0
#endif

#endif
