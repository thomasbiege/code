/***************************************************************************
                           reaction-mesg-format.h  -  description
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

#ifndef __RCTMSGFORMAT__
#define __RCTMSGFORMAT__

#include "rid-mesg-format.h"


#define MAX_ARGSTRG_SIZE  1024
#define MAX_FMTSTRG_SIZE  1024
#define MAX_FUNCID          20
#define MAX_MODNAME        255


// Mode ID
#define MID_EXEC        0x001001
#define MID_SHOW        0x001002
#define MID_CHECK       0x001003
#define MID_RETVAL      0x001004
#define MID_ALL         0x001005
#define MID_SUPPORTED   0x001006
#define MID_ERROR       0x00FFFF

// RetValID
#define RID_SUCCESS     0x100001
#define RID_UNKNOWNMODE 0x100002
#define RID_NARGS       0x100003
#define RID_UNKNOWNFUNC 0x100004
#define RID_ERROR       0xFFFFFF



typedef struct
{
  char      alert_id[RIDMSG_MAX_ALERTID+1];
  u_int     reaction_id;
  uid_t     uid_for_exec;                                                  // uid to execute action
  gid_t     gid_for_exec;                                                  // gid to execute action
  u_int     function_id;                                                   // ID of function to execute
  u_int     num_of_args;                                                   // number of args
  char      arg_fmt_string[MAX_ARGSTRG_SIZE+1]  __attribute__ ((packed));  // printf like string
	char      arg_fmt_param[MAX_FMTSTRG_SIZE+1]   __attribute__ ((packed));  // printf like parameters
} stExecMsg;

typedef struct
{
  u_int     show;
} stShowMsg;

typedef struct
{
  u_int     function_id;      // ID of function to check
} stCheckMsg;

typedef struct
{
  int     ret_val;          // return value of exec function
} stRetvalMsg;

typedef struct
{
  struct
  {
    u_int   uiID;
    char    *cModName[MAX_MODNAME+1]  __attribute__ ((packed));
  } Function[MAX_FUNCID]              __attribute__ ((packed));
} stAllMsg;

typedef struct
{
  u_int     supported;
} stSupportedMsg;


typedef struct
{
  short     sChkSum;
  time_t    Timestamp;        // timestamp to avoid replay attacks

  u_int     Mode;

  union
  {
    stExecMsg       Exec;
    stShowMsg       Show;
    stCheckMsg      Check;
    stRetvalMsg     Retval;
    stAllMsg        All;
    stSupportedMsg  Supported;
  } ModeData;

} stReactionMsg;

typedef struct
{
  u_int       IVLen                                 __attribute__ ((packed));   // it's 0 to indicate 'no encryption'
  char        IV[16]                                __attribute__ ((packed));   // that's for Twofish, so please don't change crypto algo.!!!
  u_int       CipherTextLen                         __attribute__ ((packed));
  char        cCipherText[sizeof(stReactionMsg)]    __attribute__ ((packed));   // Stream Mode = 1:1, we need more more more...
} stCipherRctMsg;

#endif


