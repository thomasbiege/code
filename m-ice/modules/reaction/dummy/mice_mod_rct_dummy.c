/***************************************************************************
                          mice_mod_rct_dummy.c  -  description
                             -------------------
    begin                : Die Mai 25 18:08:40 CEST 2001
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>


#include <mice.h>
#include "mice_mod_rct_dummy.h"
#include "parsecfg.h"


#ifndef TRUE
  #define TRUE  1
  #define FALSE 0
#endif


u_int _mice_mod_rct_dummy_CfgDone = FALSE;

/*
** Function Declaration
*/
int    _mice_mod_rct_dummy_HandleConfFile(char *cConfFile);


/*
** Module Functions
*/
size_t mice_mod_rct_dummy_LTX_init(char *ConfFile)
{
  //log_open("mice_mod_rct_dummy", LOG_PID, LOG_USER);

  if(_mice_mod_rct_dummy_CfgDone != FALSE)
  {
    log_mesg(WARN, "mice_mod_rct_dummy: Do NOT call init function twice, call close function inbetween");
    return(-1);
  }

  if(_mice_mod_rct_dummy_HandleConfFile(ConfFile) < 0)
    return(-1);

  _mice_mod_rct_dummy_CfgDone = TRUE;

  return(1);  // only one argument
}


int mice_mod_rct_dummy_LTX_func(char *cArg, size_t ArgLen)
{
  return(system(cArg));
}

int mice_mod_rct_dummy_LTX_close(void)
{
  _mice_mod_rct_dummy_CfgDone = FALSE;

  return(0);
}


/*
** Handle Config File
*/
int _mice_mod_rct_dummy_HandleConfFile(char *cConfFile)
{
  return(0);
}
