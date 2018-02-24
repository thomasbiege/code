/***************************************************************************
                          mice_mod_out_mysql.h  -  description
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

#ifndef __MICE_MOD_OUT_MYSQL_HDR__
#define __MICE_MOD_OUT_MYSQL_HDR__

#include <sys/types.h>


typedef struct
{
  MYSQL       *Sock;
  char        *Hostname;
  char        *User;
  char        *Password;
  char        *DBName;
  char        *Port;
  MYSQL_RES   *Result;
} DBInfo;


#define MAX_QUERY_LENGTH 8192  // not 16K ?

#endif
