/***************************************************************************
                          pv.h  -  description
                             -------------------
    begin                : Sat Feb 24 2001
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

#ifndef __PV
#define __PV

#define P(id)   pv(id, -1);
#define V(id)   pv(id, +1);

extern void pv(int id, int op);

#endif

