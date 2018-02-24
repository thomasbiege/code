/***************************************************************************
                          logformat.h  -  description
                             -------------------
    begin                : Sun Jul 22 2001
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

#ifndef __LOGFORMAT__
#define __LOGFORMAT__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <limits.h>

#ifndef TRUE
        #define TRUE  1
        #define FALSE 0
#endif

/* various array sizes */
#define MAX_OS        20
#define MAX_RELEASE   20
#define MAX_VERSION   20
#define MAX_DATE      30
#define MAX_TIME      30
#define MAX_IP        30
#define MAX_ACTION    50
#define MAX_ARGC     100
#define MAX_HOST     256
#define MAX_DOMAIN   256
#define MAX_SYSCALL  256
#define MAX_COMMENT  256
#define MAX_DATA    1024


/*
** File Type Tags
*/
#define FTT_UNKNOWN     NULL
#define FTT_FILE        "file:"
#define FTT_LAUS        "laus:"
#define FTT_SCSLOG      "scslog:"
#define FTT_FIREWALL    "firewall:"     
/*
** File Type Flags
*/
#define FTF_UNKNOWN     0x00
#define FTF_FILE        0x01
#define FTF_LAUS        0x02
#define FTF_SCSLOG      0x03
#define FTF_FIREWALL    0x04


typedef struct
{
  char    cSyscall[MAX_SYSCALL];
  char    cProgram[NAME_MAX];
  pid_t   PID;
  uid_t   UID;
  uid_t   EUID;
  char    cCall[MAX_DATA];
  char    cComment[MAX_COMMENT];
} SCSLogFormat;

typedef struct
{
  char    cAction[MAX_ACTION];
  char    cIn[NAME_MAX];
  char    cOut[NAME_MAX];
  char    cMAC[MAX_IP];
  char    cSource[MAX_IP];
  char    cDestination[MAX_IP];
  u_int   uiIPLength;
  u_int   uiTOS;
  u_int   uiPrec;
  u_int   uiTTL;
  u_int   uiID;
  char    cProtocol[10];
  u_int   uiSrcPort;
  u_int   uiDstPort;
  u_int   uiPacLength;
} FirewallLogFormat;

#ifdef HAVE_LIBLAUSSRV
#include <linux/audit.h>
#include <laussrv.h>
#include <laus.h>

typedef struct
{
#define SCRESULTTYPE_NUL  0x00
#define SCRESULTTYPE_PTR  0x01
#define SCRESULTTYPE_INT  0x02
#define SCRESULTTYPE_ERR  0x03
  int   type;
  long  value;
} laus_scall_result;

typedef struct
{
  laus_scall_result  result;
  char               *name;
  int                major;
  int                minor;
  int                nargs;
} laus_scall;

typedef struct
{
  struct aud_message        msg;
  union
  {
    struct aud_msg_child    msg_child;
    laus_scall              msg_syscall;
    struct aud_msg_login    msg_login;
    struct aud_msg_exit     msg_exit;
    struct aud_msg_netlink  msg_netlink;
    char                    msg_text[MAX_DATA];
  } type;
  
} LausLogFormat;
#endif

typedef struct
{
  /* client information */
  char    cHost     [MAX_HOST]      __attribute__ ((packed));
  char    cDomain   [MAX_DOMAIN]    __attribute__ ((packed));
  char    cIP       [MAX_IP]        __attribute__ ((packed));
  char    cOSystem  [MAX_OS]        __attribute__ ((packed));
  char    cRelease  [MAX_RELEASE]   __attribute__ ((packed));
  char    cVersion  [MAX_VERSION]   __attribute__ ((packed));
  char    cDate     [MAX_DATE]      __attribute__ ((packed));
  char    cTime     [MAX_TIME]      __attribute__ ((packed));
  char    cTimezone [MAX_TIME]      __attribute__ ((packed));
  int     iDaylight;

  /* raw log data */
  char    cLogdata[4*MAX_DATA];
  
  /* file type */
  u_int   uiFileType;

  /* flags */
  u_int   uiPseudonymized;  /* this flag is just a dirty workaround to
                               indicate if we pseudonymized values included
                               in the structure.
                               going this way releaves us from changing the
                               structure to make all values char types, even
                               the integer values, and mark pseudonymized
                               fields with an tag like '$' or something to
                               make this field recognizeable by other
                               components.
                               using a flag has the disadvantage that other
                               components have to know apriori which fields
                               or pseudonymized and that we have no choice
                               of pseudonymizing different fields and others
                               no. Either all or none. */
  
  
  /* structured log data */
  union
  {
    SCSLogFormat        scslog;
    FirewallLogFormat   firewall;
#ifdef HAVE_LIBLAUSSRV
    LausLogFormat       laus;
#endif
  } logtype;
  
  /* checksum */
  u_short sChkSum;
} LogFormat;


typedef struct
{
  u_int       IVLen                               __attribute__ ((packed));
              // it's 0 to indicate 'no encryption'
  char        IV[16]                              __attribute__ ((packed));
              // that's for Twofish, so please don't change crypto algo.!!!
  u_int       CipherTextLen                       __attribute__ ((packed));
  char        cCipherText[1*sizeof(LogFormat)]    __attribute__ ((packed));
              // Stream Mode = 1:1, we need more more more...
} CipherMsg;

#endif


