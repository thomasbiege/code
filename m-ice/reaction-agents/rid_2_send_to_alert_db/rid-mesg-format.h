/***************************************************************************
                             rid-mesg-format.h  -  description
                             -------------------
    copyright            : (C) 2002 by Thomas Biege
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

#ifndef __RIDMSGFORMAT__
#define __RIDMSGFORMAT__

#include "idmef-mesg-format.h"

#define RIDMSG_MAX_ALERTID    100
#define RIDMSG_MAX_ALERTDESC  2000


typedef struct
{
  char    cIdmefMsg[MAX_IDMEFMSGSIZE+1]          __attribute__ ((packed));
  char    cAlertID[RIDMSG_MAX_ALERTID+1]         __attribute__ ((packed));
  char    cAlertIDDesc[RIDMSG_MAX_ALERTDESC+1]   __attribute__ ((packed));
  int     iRID;
} RIDMsgFormat;

#endif


