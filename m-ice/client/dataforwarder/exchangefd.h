/***************************************************************************
                          exchangefd.h  -  description
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

#ifndef __EXCHANGEFD
#define __EXCHANGEFD

#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>   // struct msghdr
#include <sys/uio.h>      // struct iovec

#include <mice.h>

#define CTRLLEN (sizeof(struct cmsghdr) + sizeof(int))
#define MAXBYTE 2048

/*
** Error Codes
*/
#define XFD_ERR_OPEN        -5    /* Could not open File */
#define XFD_ERR_MISSINGNULL -6    /* Client Request is not terminated with \0 */
#define XFD_ERR_PARSE       -7    /* Error while parsing Client Request */
#define XFD_ERR_TERM        -8    /* Client requests Termination */
#define XFD_ERR_STAT        -9    /* Error while trying to get File info via stat(2) */
#define XFD_ERR_FILETYPE    -10   /* Filetype is not supported, we just support Reg, FIFO, Char Device */


static struct cmsghdr *CmsgPtr = NULL;

int intSendFd(int SPipeFd, int Fd);
int intRecvFd(int UDSock);

#endif

