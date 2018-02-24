/***************************************************************************
                          reactiondaemon.h  -  description
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

#ifndef __REACTIONDAEMON__
#define __REACTIONDAEMON__

/*
** Define Names of valid Sections in the Conf File
*/
#define FUNCID      "FUNCTION_ID"
#define RCTMOD      "REACTION_MODULES"
#define RCTMODCONF  "REACTION_MODULES_CONFIG_FILE"
#define NETWORK     "NETWORK"
#define SECURITY    "SECURITY"
#define MISC        "MISC"
#define MAXSECT     6

/*
** PID Files
*/
#define PIDMAIN       "reactiondaemon.pid"

/*
** MISC
*/
#define PATHCONFFILE  "/etc/M-ICE/reactiondaemon.conf"
#define SYMNAME_INIT  "init"       // <modulename>_LTX_init
#define SYMNAME_FUNC  "func"       // <modulename>_LTX_func

#ifndef TRUE
  #define TRUE  1
  #define FALSE 0
#endif

#endif

