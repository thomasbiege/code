/***************************************************************************
                          dns_lib.c  -  description
                             -------------------
    begin                : Wed May 9 2001
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

#define MAX_HOSTENTBUF 8192   // value from Steven's UNP

#ifndef MAXHOSTNAMELEN
  #define MAXHOSTNAMELEN 64
#endif


unsigned name_resolve(char *hostname)
{
  char            hostEntBuf[MAX_HOSTENTBUF+1] = {0};
  int             h_errnop;
  struct in_addr  addr;
  struct hostent  hostEnt,
                  *hostEntPtr;

  if((addr.s_addr = inet_addr(hostname)) == -1)
  {
    if(gethostbyname_r(hostname, &hostEnt, hostEntBuf, sizeof(hostEntBuf), &hostEntPtr, &h_errnop) != 0)
      return(0);
    memcpy((char *)&addr.s_addr, hostEnt.h_addr, hostEnt.h_length);
  }

  return(addr.s_addr);
}


char *host_lookup(u_long in)
{
  char            *hostname;
  struct in_addr  addr;
  struct hostent  *hostEnt;

  if( (hostname = calloc(MAXHOSTNAMELEN+1, sizeof(char))) == NULL)
    return(NULL);

  addr.s_addr = in;
  hostEnt = gethostbyaddr((char *)&addr, sizeof(struct in_addr), AF_INET);

  if(!hostEnt)
    strncpy(hostname, inet_ntoa(addr), MAXHOSTNAMELEN);
  else
    strncpy(hostname, hostEnt->h_name, MAXHOSTNAMELEN);

  return(hostname);
}




