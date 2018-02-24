/***************************************************************************
                          unixdomainsocket.h  -  description
                             -------------------
    begin                : Mon Feb 26 2001
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

#ifndef __UNIXDOMAINSOCKET
#define __UNIXDOMAINSOCKET

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <mice.h>

#define UDS_ERR_PATH    -01
#define UDS_ERR_SOCK    -02
#define UDS_ERR_BIND    -03
#define UDS_ERR_SOCKP   -04
#define UDS_ERR_UNKNOWN -99

int intUDSockBind(char *cPath, int iMask);
int intUDSockPair(int iSockFd[2]);

#endif

