/***************************************************************************
                          unixdomainsocket.c  -  description
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

#include "unixdomainsocket.h"

extern int intUDSockBind(char *cPath, int iMask)
{
  int                 iOldMask;
  int                 iSockFd;
  struct sockaddr_un  Addr;


  if(cPath == NULL)
    return(UDS_ERR_PATH);

  iOldMask = umask(iMask);

  if((iSockFd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0)
  {
    umask(iOldMask);
    return(UDS_ERR_SOCK);
  }

  unlink(cPath);

  memset(&Addr, 0, sizeof(Addr));
  Addr.sun_family = AF_LOCAL;
  strncpy(Addr.sun_path, cPath, sizeof(Addr.sun_path)-1);
  if(bind(iSockFd, (struct sockaddr *) &Addr, SUN_LEN(&Addr)) < 0)
  {
    umask(iOldMask);
    return(UDS_ERR_BIND);
  }

  umask(iOldMask);
  return(iSockFd);
}


extern int intUDSockPair(int iSockFd[2])
{

  if(socketpair(AF_LOCAL, SOCK_STREAM, 0, iSockFd) < 0)
    return(UDS_ERR_SOCKP);

  return(0);
}


