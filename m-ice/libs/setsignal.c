/***************************************************************************
                          setsignal.c  -  description
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

/*
** Set Signal Handler (reliable)
*/

#include "setsignal.h"

int set_signal(int sig, void (*fkt_ptr) (int))
{
  struct sigaction sig_act;

  sig_act.sa_handler = fkt_ptr;
  sigemptyset(&sig_act.sa_mask);
  sig_act.sa_flags = 0;

#ifdef SA_INTERRUPT   /* Solaris */
  sig_act.sa_flags |= SA_INTERRUPT;  /* don't restart read()-call */
#endif

  return(sigaction(sig, &sig_act, NULL));
}
