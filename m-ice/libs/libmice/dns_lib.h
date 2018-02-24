/***************************************************************************
                          dns_lib.h  -  description
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
#ifndef __DNS_LIB_HDR
#define __DNS_LIB_HDR

unsigned name_resolve(char *hostname);
char *host_lookup(u_long in);

#endif



