/***************************************************************************
                          idmef-mesg-format.h  -  description
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

#ifndef __IDMEFMSGFORMAT__
#define __IDMEFMSGFORMAT__

#define MAX_IDMEFMSGSIZE 10*1024

typedef struct
{
  char    cIdmefMsg[MAX_IDMEFMSGSIZE+1]  __attribute__ ((packed));
  u_short sChkSum                        __attribute__ ((packed));
} IdmefMsgFormat;

typedef struct
{
  u_int       IVLen                                 __attribute__ ((packed));   // it's 0 to indicate 'no encryption'
  char        IV[16]                                __attribute__ ((packed));   // that's for Twofish, so please don't change crypto algo.!!!
  u_int       CipherTextLen                         __attribute__ ((packed));
  char        cCipherText[sizeof(IdmefMsgFormat)]   __attribute__ ((packed));   // Stream Mode = 1:1, we need more more more...
} CipherIdmefMsg;

#endif


