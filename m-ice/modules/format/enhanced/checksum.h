/***************************************************************************
                          checksum.h  -  description
                             -------------------
    begin                : Sun May 6 2001
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

#ifndef __CHECKSUM_HDR
#define __CHECKSUM_HDR

#include <sys/types.h>

u_short in_chksum(u_short *ptr, int nbytes);

#endif
