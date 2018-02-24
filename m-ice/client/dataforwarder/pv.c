/***************************************************************************
                          pv.c  -  description
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

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#include <mice.h>
#include "pv.h"

void pv(int id, int op)
{
  static struct sembuf  semaphor;

  semaphor.sem_op   = op;
  semaphor.sem_flg  = SEM_UNDO;

  if(semop(id, &semaphor, 1) == -1)
    log_mesg(WARN_SYS, "Error: semop() | Syserror");
}

