/***************************************************************************
                          syslog_module.h  -  description
                             -------------------
    begin                : Tue May 15 2001
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

#ifndef __MICE_MOD_OUT_SYSLOG_HDR__
#define __MICE_MOD_OUT_SYSLOG_HDR__

#define MAX_OS        20
#define MAX_RELEASE   20
#define MAX_VERSION   20
#define MAX_DATE      30
#define MAX_TIME      30
#define MAX_ARGC     100
#define MAX_HOST     256
#define MAX_DATA    1024


typedef struct
{
  char    cHost[MAXHOSTNAMELEN];
  char    cOSystem[MAX_OS];
  char    cRelease[MAX_RELEASE];
  char    cVersion[MAX_VERSION];
  char    cDate[MAX_DATE];
  char    cTime[MAX_TIME];
  char    cLogLine[MAX_DATA];
  u_short sChkSum;
} LogFormat;

#endif

