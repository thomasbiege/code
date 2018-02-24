/***************************************************************************
                          exchangefd.c  -  description
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

#include <string.h>
#include "exchangefd.h"
#include <mice.h>

/*
** intSendFd
** sends a fdesc to another process
** -fd = error
**
** error:
**  -1: malloc()
**  -2: sendmsg()
*/
int intSendFd(int UDSock, int Fd)
{
  struct iovec    IOV[1];
  struct msghdr   Message;
  char            cProtocol[2] = {0, 0};


  IOV[0].iov_base     = cProtocol;
  IOV[0].iov_len      = 2;

  Message.msg_iov     = IOV;
  Message.msg_iovlen  = 1;
  Message.msg_name    = NULL;
  Message.msg_namelen = 0;

  if(Fd < 0)
  {
    Message.msg_control     = NULL;
    Message.msg_controllen  = 0;

    cProtocol[1]            = Fd;    // status != 0 -> error
                                      // -Fd ???, fd ist schon neg. XXX
    //if(cProtocol[1] == 0)
      //cProtocol[1] = 1;   // catch overflows (???) XXX
  }
  else
  {
    if(CmsgPtr == NULL && (CmsgPtr = malloc(CTRLLEN)) == NULL)
      return(-1);

    CmsgPtr->cmsg_level         = SOL_SOCKET;
    CmsgPtr->cmsg_type          = SCM_RIGHTS;
    CmsgPtr->cmsg_len           = CTRLLEN;

    Message.msg_control         = (caddr_t) CmsgPtr;
    Message.msg_controllen      = CTRLLEN;

    *(int *) CMSG_DATA(CmsgPtr)  = Fd;
  }

  if(sendmsg(UDSock, &Message, 0) != 2)
    return(-2);

  return(0);
}


/*
** intRecvFd
** receives a fdesc from another process
**
** error:
**    -1: malloc()
**    -2: recvmsg()
**    -3: connection closed by server
**    -4: message incositency
**  < -4: XFD_ERR_XYZ
*/
int intRecvFd(int UDSock)
{
  int           NewFd, ByteCount, Status = -1;
  char          *cPtr, cBuffer[MAXBYTE];
  struct iovec  IOV[1];
  struct msghdr Message;


  while(1)
  {
    IOV[0].iov_base        = cBuffer;
    IOV[0].iov_len         = sizeof(cBuffer);

    Message.msg_iov        = IOV;
    Message.msg_iovlen     = 1;
    Message.msg_name       = NULL;
    Message.msg_namelen    = 0;

    if(CmsgPtr == NULL && (CmsgPtr = malloc(CTRLLEN)) == NULL)
      return(-1);

    Message.msg_control     = (caddr_t) CmsgPtr;
    Message.msg_controllen  = CTRLLEN;

    if((ByteCount = recvmsg(UDSock, &Message, 0)) < 0)
      return(-2);
    else if(ByteCount == 0)
      return(-3);

    /*
    ** Process Buffer, End-of-Data is indicated by \0.
    ** The Status follows the Null-Byte. Status == 0 ->
    ** Fdesc received.
    */
    for(cPtr = cBuffer; cPtr < &cBuffer[ByteCount]; )
    {
      if(*cPtr++ == 0)
      {
        if(cPtr != &cBuffer[ByteCount-1])
          return(-4);

        Status = *cPtr & 0xFF;
        //if(Status == 0)
        //{
          if(Message.msg_controllen != CTRLLEN)
            return(-4);
          NewFd = *(int *) CMSG_DATA(CmsgPtr);
          //log_mesg(WARN, "intRecvFd: NewFd: %d", NewFd);
        //}

        ByteCount -= 2;
      }
    }

    return(NewFd);
  } // while(1) { ...
}


/*
** intSendError
** Error:
**  -1: writen()
**  -2: intSendFd()
*/
int intSendError(int UDSock, int Status, const char *cErrorMsg)
{
  int n;

  if((n = strlen(cErrorMsg)) > 0)
    if(writen(UDSock, cErrorMsg, n) != n)
      return(-1);

  if(Status >= 0)
    Status = -1;    /* Status have to be negative */

  if(intSendFd(UDSock, Status) < 0)
    return(-2);

  return(0);
}

