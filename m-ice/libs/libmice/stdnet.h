/***************************************************************************
                          stdnet.h  -  description
                             -------------------
    begin                : Sun Feb 25 2001
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
#ifndef __STDNET_HDR
#define __STDNET_HDR

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

char  *host_err_str(void);
int   tcp_open(char *host, char *service, int port);
int   udp_open(char *host, char *service, int port, int dontconn);
int   readn(register int fd, register char *ptr, register int nbytes);
int   writen(register int fd, const char *ptr, register int nbytes);
int   readline(register int fd, register char *ptr, register int maxlen);
int   read_stream(int fd, char *ptr, int maxbytes);
void  str_echo(int sockfd);
void  str_cli(FILE *fp, register int sockfd);
void  dg_echo(int sockfd, struct sockaddr *pcli_addr, int maxclilen);
void  dg_cli(FILE *fp, int sockfd, struct sockaddr *pserv_addr, int servlen);

#endif

