/***************************************************************************
                          setsignal.h  -  description
                             -------------------
    begin                : Thu Feb 22 2001
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

#ifndef __SETSIGNAL
#define __SETSIGNAL

#include <stdio.h>
#include <signal.h>


extern int set_signal(int sig, void (*fkt_ptr) (int));

#endif

