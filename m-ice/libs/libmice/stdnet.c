/***************************************************************************
                          stdnet.c  -  description
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

/*
** Code from "UNIX Network Programming" by W. Richard Stevens
** Error Handler from "UNIX Systemprogrammierung" by Helmut Herold
*/


#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
extern int h_errno;
#include "errormsg.h"

#define MAXLINE     512
#define MAXMESG     2048

#ifndef INADDR_NONE
#define INADDR_NONE 0xFFFFFFFF    /* should be in <netinet/in.h> */
#endif


/*--------------------------------------------------------------------------*/

/*
** Return a string containing some additional infos after a host name or
** address lookup error - gethostbyname() or gethostbyaddr().
*/

int     h_error;        /* host error number */
int     h_nerr;         /* # of error message strings */
char    **h_errlist;   /* the error message table */

char *host_err_str(void)
{
  static char     msgstr[200];

  if(h_error != 0)
	{
    if(h_errno > 0 && h_errno < h_nerr)
      snprintf(msgstr, sizeof(msgstr), "(%s)", h_errlist[h_errno]);
    else
      snprintf(msgstr, sizeof(msgstr), "(h_errno = %d)", h_errno);
	}
  else
    msgstr[0] = '\0';

  return(msgstr);
}


/*--------------------------------------------------------------------------*/

/*
** Open a TCP connection.
*/

/*
** The following globals are available to the caller, if desired.
*/

struct sockaddr_in  tcp_srv_addr;   /* server's Internet socket addr */
struct servent      tcp_serv_info;  /* from getservbyname() */
struct hostent      tcp_host_info;  /* from gethostbyname() */

/*
** host:    name or dotted-decimal addr of other system
** service: name of service being requested
**          can be NULL, if port > 0
** port:    if == 0, nothing special - use port# of service
**          if <  0, bind a local reserved port
**          if >  0, it's the port# of server (host-byte-order)
*/
int tcp_open(char *host, char *service, int port)
{
  int             fd, resvport;
  unsigned long   inaddr;  
  struct servent  *sp;
  struct hostent  *hp;
  
  
  /*
  ** Initialize the server's Internet address structure.
  ** We'll store the actual 4-byte Internet address and the
  ** 2-byte port# below
  */
  
  memset(&tcp_srv_addr, 0, sizeof(tcp_srv_addr));
  tcp_srv_addr.sin_family = AF_INET;
  
  if(service != NULL)
  {
    if( (sp = getservbyname(service, "tcp")) == NULL)
    {
      log_mesg(WARN, "tcp_open: unknown service: %s/tcp\n", service);
      return(-1);
    }
    tcp_serv_info = *sp;    /* structure copy */
    if(port > 0)
      tcp_srv_addr.sin_port = htons(port);  /* caller's value */
    else
      tcp_srv_addr.sin_port = sp->s_port;   /* service's value */
  }
  else
  {
    if(port <= 0)
    {
      log_mesg(WARN, "tcp_open: must specify either service or port");
      return(-1);
    }
    tcp_srv_addr.sin_port = htons(port);
  }
  
  /*
  ** First try to convert the host name as a dotted-decimal number.
  ** Only if that fails do we call gethostbyname().
  */
  
  if( (inaddr = inet_addr(host)) != INADDR_NONE )
  {
    /* it's a dotted-decimal */
    memcpy(&tcp_srv_addr.sin_addr, &inaddr, sizeof(inaddr) );
    tcp_host_info.h_name = NULL;
  }
  else
  {
    if( (hp = gethostbyname(host)) == NULL )
    {
      log_mesg(WARN, "tcp_open: host name error: %s %s\n", host, host_err_str());
      return(-1);
    }
    tcp_host_info = *hp;    /* found it by name, structure copy */
    memcpy(&tcp_srv_addr.sin_addr, hp->h_addr, hp->h_length);
  }
  
  if(port >= 0)
  {
    if( (fd = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
    {
      log_mesg(WARN, "tcp_open: can't create TCP socket\n");
      return(-1);
    }
  }
  else if(port < 0)
  {
    resvport = IPPORT_RESERVED - 1;
    if( (fd = rresvport(&resvport)) < 0 )
    {
      log_mesg(WARN, "tcp_open: can't get a reserved TCP port\n");
      return(-1);
    }
  }
  
  /*
  ** Connect to the server.
  */
  
  if(connect(fd, (struct sockaddr *) &tcp_srv_addr, sizeof(tcp_srv_addr)) < 0)
  {
    log_mesg(WARN, "tcp_open: can't connect to server\n");
    close(fd);
    return(-1);
  }
  
  return(fd);   /* all OK */
}

/*--------------------------------------------------------------------------*/

/*
** Establish a UDP socket and optionally call connect() to set up
** the server's address for future I/O.
*/

/*
** The following globals are available to the caller, if desired.
*/

struct sockaddr_in  udp_srv_addr;   /* server's Internet socket addr */
struct sockaddr_in  udp_cli_addr;   /* client's Internet socket addr */
struct servent      udp_serv_info;  /* from getservbyname() */
struct hostent      udp_host_info;  /* from gethostbyname() */
  
/*
** host:      name of other system to communicate with
** service:   name of service being requested
**            can be NULL, if port > 0
** port:      if == 0, nothing special - use port# of service
**            if <  0, bind a local reserved port
**            if >  0, it's the port# of server (host-byte-order)
** dontconn:  if == 0, call connect(), else don't
*/
int udp_open(char *host, char *service, int port, int dontconn)
{
  int             fd;
  unsigned long   inaddr;
  struct servent  *sp;
  struct hostent  *hp;
  
  /*
  ** Init, the server's Inet addr strcut.
  ** We'll store the actual 4-byte Inet addr and the 2-byte port# below.
  */
  
  memset(&udp_srv_addr, 0, sizeof(udp_srv_addr));
  udp_srv_addr.sin_family = AF_INET;
  
  if(service != NULL)
  {
    if( (sp = getservbyname(service, "udp")) == NULL )
    {
      err_mesg(WARN, "udp_open: unknown service: %s/udp\n", service);
      return(-1);
    }
    udp_serv_info = *sp;    /* structure copy */
    
    if(port > 0)
      udp_srv_addr.sin_port = htons(port);    /* caller's info */
    else
      udp_srv_addr.sin_port = sp->s_port;     /* service's value */
  }
  else
  {
    if(port <= 0)
    {
      err_mesg(WARN, "udp_open: must specify either service or port\n");
      return(-1);
    }
    udp_srv_addr.sin_port = htons(port);
  }
  
  /*
  ** First try to convert the host name as dotted-decimal number.
  ** Only if that fails do we call gethostbyname().
  */
  
  if( (inaddr = inet_addr(host)) != INADDR_NONE )
  {
    /* it's dotted-decimal */
    memcpy(&udp_srv_addr.sin_addr, &inaddr, sizeof(inaddr) );
    udp_host_info.h_name = NULL;
  }
  else
  {
    if( (hp = gethostbyname(host)) == NULL )
    {
      err_mesg(WARN, "udp_open: host name error: %s %s\n", host, host_err_str());
      return(-1);
    }
    udp_host_info = *hp;    /* found by name, structure copy */
    memcpy(&udp_srv_addr.sin_addr, hp->h_addr, hp->h_length);
  }
  
  if(port < 0)
    err_mesg(FATAL, "udp_open: reserved ports not implemeneted yet\n");
    
  if( (fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 )
  {
    err_mesg(WARN, "udp_open: can't create UDP socket\n");
    return(-1);
  }
  
  /*
  ** Bind any local address for us.
  */
  
  memset(&udp_cli_addr, 0, sizeof(udp_cli_addr));
  udp_cli_addr.sin_family       = AF_INET;
  udp_cli_addr.sin_addr.s_addr  = htonl(INADDR_ANY);
  udp_cli_addr.sin_port         = htons(0);
  if( bind(fd, (struct sockaddr *) &udp_cli_addr, sizeof(udp_cli_addr)) < 0 )
  {
    err_mesg(WARN, "udp_open: bind error\n");
    close(fd);
    return(-1);
  }
  
  /*
  ** Call connect, if desired. This is used by most caller's,
  ** as the peer shouldn't change. (TFTP is an exception.)
  ** By calling connect, the caller can call send() and recv().
  */
  
  if( dontconn == 0 )
    if( connect(fd, (struct sockaddr *) &udp_srv_addr, sizeof(udp_srv_addr)) < 0 )
    {
      err_mesg(WARN, "udp_open: connect error\n");
      return(-1);
    }
    
  return(fd);
}

/*--------------------------------------------------------------------------*/

/*
** Read n bytes from a descriptor.
** Use in place of read() when fd is a stream socket.
*/
int readn(register int fd, register char *ptr, register int nbytes)
{
  int nleft, nread;
  
  nleft = nbytes;
  while(nleft > 0)
  {
    if( (nread = read(fd, ptr, nleft)) < 0)
      return(nread);
    else if(nread == 0)
      break;  /* EOF */
      
    nleft -= nread;
    ptr += nread;
  }
  return(nbytes - nleft);
}


/*--------------------------------------------------------------------------*/

/*
** Write n bytes to a desc..
** Use in place of write() when fd is a stream socket.
*/
int writen(register int fd, const char *ptr, register int nbytes)
{
  int nleft, nwritten;

  nleft = nbytes;
  while(nleft > 0)
  {
    if( (nwritten = write(fd, ptr, nleft)) <= 0)
      return(nwritten);
                        
    nleft -= nwritten;
    ptr += nwritten;
  }
  return(nbytes - nleft);
}


/*--------------------------------------------------------------------------*/

/*
** Read a line from a desc.. Read the line one byte at a time, looking for the
** newline. We store the newline in the buffer, then follow it with a null
** (the same as fgets(3)).
** We return the number of chars up to, but not including, the null (the same
** as strlen(3)).
*/
int readline(register int fd, register char *ptr, register int maxlen)
{
  int   n, rc;
  char  c;
  
  for(n = 1; n < maxlen; n++)
  {
    if( (rc = read(fd, &c, 1)) == 1)
    {
      *ptr++ = c;
      if(c == '\n')
        break;
    }
    else if(rc == 0)
    {
      if(n == 1)
        return(0);    /* EOF, no data read */
      else
        break;        /* EOF, some data was read */
    }
    else
      return(-1);     /* error */
  }
  
  *ptr = 0;
  return(n);
}


/*--------------------------------------------------------------------------*/

/*
** Read a stream socket one line at a time, and write each line back to
** the sender.
**
** Return when the connection is terminated.
*/
void str_echo(int sockfd)
{
  int   n;
  char  line[MAXLINE];
  
  while(1)
  {
    if( (n = readline(sockfd, line, MAXLINE)) < 0)
      err_mesg(DUMP, "str_echo: readline error\n");
    else if(n == 0)
      return;       /* connection closed */
      
    if(writen(sockfd, line, n) != n)
      err_mesg(DUMP, "str_echo: writen error\n");
  }
}


/*--------------------------------------------------------------------------*/

/*
** Read the contens of the FILE *fp, write each line to the stream socket
** (to the server process), then read a line back from the socket and write
** it to stdout.
*/
void str_cli(FILE *fp, register int sockfd)
{
  int   n;
  char  sendline[MAXLINE], recvline[MAXLINE+1];
  
  while(fgets(sendline, MAXLINE, fp) != NULL)
  {
    n = strlen(sendline);
    if(writen(sockfd, sendline, n) != n)
      err_mesg(FATAL_SYS, "str_cli: writen error.\n");
      
    /*
    ** Now read a line from the socket and write it ti our stdout
    */
    
    if( (n = readline(sockfd, recvline, MAXLINE)) < 0)
      err_mesg(DUMP, "str_cli: readline error\n");
    recvline[n] = 0;
    fputs(recvline, stdout);
  }
  if(ferror(fp))
    err_mesg(FATAL_SYS, "str_cli: error reading file\n");
}


/*--------------------------------------------------------------------------*/

/*
** Read a datagram from a connectionless socket and write it back to the
** sender.
**
** We never return, as we never know when a datagram client is done.
*/
void dg_echo(int sockfd, struct sockaddr *pcli_addr, int maxclilen)
{
  int   n, clilen;
  char  mesg[MAXMESG];
  
  while(1)
  {
    clilen = maxclilen;
    if( (n = recvfrom(sockfd, mesg, MAXMESG, 0, pcli_addr, &clilen)) < 0)
      err_mesg(DUMP, "dg_echo: recvfrom error\n");
      
    if(sendto(sockfd, mesg, n, 0, pcli_addr, clilen) != n)
      err_mesg(DUMP, "dg_echo: sendto error\n");
  }
}


/*--------------------------------------------------------------------------*/

/*
** Read the contens of the FILE *fp, write each line to the datagram socket,
** then read a line back from the socket and write
** it to stdout.
**
** Return to caller when an EOF is encountered on the input file.
*/
void dg_cli(FILE *fp, int sockfd, struct sockaddr *pserv_addr, int servlen)
{
  int   n;
  char  sendline[MAXLINE], recvline[MAXLINE+1];

  while(fgets(sendline, MAXLINE, fp) != NULL)
    {
    n = strlen(sendline);
    if(sendto(sockfd, sendline, n, 0, pserv_addr, servlen) != n)
      err_mesg(FATAL_SYS, "dg_cli: sendto error.\n");

    /*
    ** Now read a line from the socket and write it ti our stdout
    */

    if( (n = recvfrom(sockfd, recvline, MAXLINE, 0, NULL, NULL)) < 0)
      err_mesg(DUMP, "dg_cli: recvfrom error\n");
    recvline[n] = 0;
    fputs(recvline, stdout);
  }
  if(ferror(fp))
    err_mesg(FATAL_SYS, "dg_cli: error reading file\n");
}


/*--------------------------------------------------------------------------*/

/*
** read_stream() from 'TCP/IP Illustrated, Volume 3' by W. Richard Stevens+
** calls read() as many times as necessary, until either the input buffer is
** full, or an EOF is returned by read()
**
** return value: number of bytes read
*/

int read_stream(int fd, char *ptr, int maxbytes)
{
  int nleft, nread;

  nleft = maxbytes;
  while(nleft > 0)
  {
    if((nread = read(fd, ptr, nleft)) < 0)
      return(nread);      // error, return < 0
    else if(nread == 0)
      break;              // EOF, return #bytes read

    nleft -= nread;
    ptr += nread;
  }

  return(maxbytes - nleft); //return >= 0
}

