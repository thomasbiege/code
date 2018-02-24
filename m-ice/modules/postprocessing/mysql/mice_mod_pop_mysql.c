/***************************************************************************
                          mice_mod_pop_mysql.c  -  description
                             -------------------
    copyright            : (C) 2003 by Thomas Biege
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
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#if defined(_WIN32) || defined(_WIN64)
  #include <windows.h>
#endif
#include <mysql/mysql.h>

#include <logformat.h>
#include <mice.h>
#include <mice_parse.h>
#include <mice_pseudo.h>

#include "mice_mod_pop_mysql.h"
#include "parsecfg.h"

#define MYSQLSERV   "MYSQL_SERVER"
#define PSEUDONYM   "PSEUDONYMIZE"
#define MAXSECT     2

#ifndef TRUE
  #define TRUE  1
  #define FALSE 0
#endif

MYSQL *_mice_mod_pop_mysql_Sock;

int _mice_mod_pop_mysql_Debug = TRUE;


/*
** Function Declaration
*/
int    _mice_mod_pop_mysql_HandleConfFile(char *cConfFile);


/*
** Configure Stuff
*/
char      **_mice_mod_pop_mysql_CfgHostname;
char      **_mice_mod_pop_mysql_CfgUser;
char      **_mice_mod_pop_mysql_CfgPassword;
char      **_mice_mod_pop_mysql_CfgDBName;
int        *_mice_mod_pop_mysql_CfgPort;
int        *_mice_mod_pop_mysql_CfgMaxErr;

char      **_mice_mod_pop_mysql_CfgKey;
int        *_mice_mod_pop_mysql_CfgActive;

int       _mice_mod_pop_mysql_iSectMySQLServ;
int       _mice_mod_pop_mysql_iSectPseudo;

cfgStruct _mice_mod_pop_mysql_CfgIni[] =
{
  // MySQL Server Section
  {"HOSTNAME"   ,CFG_STRING ,&_mice_mod_pop_mysql_CfgHostname },
  {"PORT"       ,CFG_INT    ,&_mice_mod_pop_mysql_CfgPort     },
  {"USER"       ,CFG_STRING ,&_mice_mod_pop_mysql_CfgUser     },
  {"PASSWORD"   ,CFG_STRING ,&_mice_mod_pop_mysql_CfgPassword },
  {"DBNAME"     ,CFG_STRING ,&_mice_mod_pop_mysql_CfgDBName   },
  {"MAXERR"     ,CFG_INT    ,&_mice_mod_pop_mysql_CfgMaxErr   },

  // Pseudonymisation Section
  {"ACTIVE"     ,CFG_BOOL   ,&_mice_mod_pop_mysql_CfgActive   },
  {"KEY"        ,CFG_STRING ,&_mice_mod_pop_mysql_CfgKey      },

  {NULL         ,CFG_END    ,NULL                             }
};


u_int    _mice_mod_pop_mysql_iMaxErrCnt;
u_int    _mice_mod_pop_mysql_CfgDone = FALSE;
char    *_mice_mod_pop_mysql_PsdKey;
char    *_mice_mod_pop_mysql_decodedPsdKey;
size_t   _mice_mod_pop_mysql_decodedPsdKeyLen;


void    debug_message(char *data, size_t size);



/*
** Module Functions
*/
size_t mice_mod_pop_mysql_LTX_init(char *ConfFile)
{
  //log_open("mice_mod_pop_mysql", LOG_PID, LOG_USER);

  if(_mice_mod_pop_mysql_CfgDone == TRUE)
  {
    log_mesg(WARN, "mice_mod_pop_mysql: Do NOT call init function twice, call close function inbetween");
    return(-1);
  }

  if(_mice_mod_pop_mysql_HandleConfFile(ConfFile) < 0)
    return(-1);

  _mice_mod_pop_mysql_iMaxErrCnt = 0;

  if( (_mice_mod_pop_mysql_Sock = mysql_init(NULL)) == NULL)
  {
    log_mesg(WARN, "mice_mod_pop_mysql: Error: Connection to MySQL Server [%s:%d] Database '%s' failed\n",
                    _mice_mod_pop_mysql_CfgHostname[_mice_mod_pop_mysql_iSectMySQLServ],
                    _mice_mod_pop_mysql_CfgPort[_mice_mod_pop_mysql_iSectMySQLServ],
                    _mice_mod_pop_mysql_CfgDBName[_mice_mod_pop_mysql_iSectMySQLServ]);
    return(-2);
  }

  if(mysql_real_connect(_mice_mod_pop_mysql_Sock,
                        _mice_mod_pop_mysql_CfgHostname[_mice_mod_pop_mysql_iSectMySQLServ],
                        _mice_mod_pop_mysql_CfgUser[_mice_mod_pop_mysql_iSectMySQLServ],
                        _mice_mod_pop_mysql_CfgPassword[_mice_mod_pop_mysql_iSectMySQLServ],
                        _mice_mod_pop_mysql_CfgDBName[_mice_mod_pop_mysql_iSectMySQLServ],
                        _mice_mod_pop_mysql_CfgPort[_mice_mod_pop_mysql_iSectMySQLServ], NULL, 0) == 0)
  {
    if(mysql_errno(_mice_mod_pop_mysql_Sock))
    {
      log_mesg(WARN, "mice_mod_pop_mysql: Error: mysql_real_connect() | MySQL_Error: %s\n",
                      mysql_error(_mice_mod_pop_mysql_Sock));
      return(-3);
    }
    log_mesg(WARN, "mice_mod_pop_mysql: Error: Failed to logon to Database '%s'\n",
                    _mice_mod_pop_mysql_CfgDBName[_mice_mod_pop_mysql_iSectMySQLServ]);
    return(-4);
  }

  _mice_mod_pop_mysql_CfgDone = TRUE;


  /* check if we have to de-pseudonymize data */
  if(_mice_mod_pop_mysql_CfgActive[_mice_mod_pop_mysql_iSectPseudo] == FALSE)
  {
    _mice_mod_pop_mysql_decodedPsdKey = NULL;
    _mice_mod_pop_mysql_PsdKey = NULL;

    return(sizeof(LogFormat));
  }
  
                     
  /* init pseudo. lib */
  _mice_mod_pop_mysql_PsdKey = _mice_mod_pop_mysql_CfgKey[_mice_mod_pop_mysql_iSectPseudo];
  if((_mice_mod_pop_mysql_decodedPsdKey = psd_set_key(
      _mice_mod_pop_mysql_PsdKey, &_mice_mod_pop_mysql_decodedPsdKeyLen))
      == NULL)
  {
    log_mesg(WARN, "mice_mod_pop_mysql: Error: psd_set_key(%s)\n", _mice_mod_pop_mysql_PsdKey);
    return(-5);
  }

  if(psd_init() < 0)
  {
    log_mesg(WARN, "mice_mod_pop_mysql: Error: psd_init()\n");
    return(-6);
  }

  
  return(sizeof(LogFormat));
}


int mice_mod_pop_mysql_LTX_func(char *cData, size_t DataSize)
{
  char              *PsdKey         = _mice_mod_pop_mysql_PsdKey;
  char              *decodedPsdKey  = _mice_mod_pop_mysql_decodedPsdKey;
  char              cQuery[MAX_QUERY_LENGTH]      = {0};
  char              cQuotedLogLine[2*MAX_DATA+1]  = {0};
  u_int             uiQuotedLogLineLen;
  SCSLogFormat      *SCSLogPtr;
  FirewallLogFormat *FwLogPtr;
  LogFormat         *LogFmt;


  //log_mesg(WARN, "mice_mod_pop_mysql: _func CALLED!");

  if(_mice_mod_pop_mysql_CfgDone != TRUE)
  {
    log_mesg(WARN, "mice_mod_pop_mysql: Please call mice_mod_LTX_init() first!");
    return(-100);
  }

  if(_mice_mod_pop_mysql_Debug)
    log_mesg(WARN, "mice_mod_pop_mysql: Checking arguments");

  if(DataSize != sizeof(LogFormat))
  {
    log_mesg(WARN, "mice_mod_pop_mysql: Invalid Data Length!");
    return(-1);
  }

  if(_mice_mod_pop_mysql_iMaxErrCnt >=  _mice_mod_pop_mysql_CfgMaxErr[_mice_mod_pop_mysql_iSectMySQLServ])
  {
    log_mesg(WARN, "mice_mod_pop_mysql: MAXERR Cnt. reached!");
    return(-666); // something went really wrong :-(
  }

  LogFmt = (LogFormat *) cData;

  /*
  ** Check for SQL commands in text-only log messages
  */
  if(LogFmt->uiFileType == FTF_FILE)
  {
    if(_mice_mod_pop_mysql_Debug)
      log_mesg(WARN, "mice_mod_pop_mysql: Checking for SQL-Injection-Attacks");

    uiQuotedLogLineLen = mysql_real_escape_string(_mice_mod_pop_mysql_Sock,
                                                  cQuotedLogLine, LogFmt->cLogdata,
                                                  (u_int) strlen(LogFmt->cLogdata));

    /*
    ** Does the Log Line include SQL commands?
    */
    if(uiQuotedLogLineLen > strlen(LogFmt->cLogdata))
      log_mesg(WARN, "mice_mod_pop_mysql: IMPORTANT WARNING! The Log Line may "
                     "include SQL Commands, that can be an Attack! All dangerous "
                     "Commands have been quoted to allow Secure Logging in the "
                     "MySQL Database.");

    /*
    ** The Log Line becames too long.
    ** We may use valueable log data!
    */
    if(uiQuotedLogLineLen >
       sizeof(cQuery) - (sizeof(LogFormat)-sizeof(LogFmt->cLogdata)) - 51)
      log_mesg(WARN, "mice_mod_pop_mysql: IMPORTANT WARNING! The quoted MySQL "
                     "Logline is too long to send it to the MySQL Server. The "
                     "String will be truncated!\n");
  }


  /*********************************************************
  **                                                      **
  ** raw log line                                         **
  **                                                      **
  *********************************************************/
  if(LogFmt->uiFileType == FTF_FILE)
  {
    if(_mice_mod_pop_mysql_Debug)
      log_mesg(WARN, "mice_mod_pop_mysql: Processing raw log line");

    memset(cQuery, 0, sizeof(cQuery));
    snprintf(cQuery, sizeof(cQuery),
             "INSERT INTO rawlog_line (hostname, domain, ip, osystem, release, "
             "version, date, time, logline, signature) "
              "VALUES ('%s', '%s', '%s','%s','%s','%s','%s','%s','%s','%s')",
             LogFmt->cHost,
             LogFmt->cDomain,
             LogFmt->cIP,
             LogFmt->cOSystem,
             LogFmt->cRelease,
             LogFmt->cVersion,
             LogFmt->cDate,
             LogFmt->cTime,
             cQuotedLogLine,
             "not supported" );

    //log_mesg(WARN, "mice_mod_pop_mysql: Debug: %s", cQuery);

    if(_mice_mod_pop_mysql_Debug)
      log_mesg(WARN, "mice_mod_pop_mysql: Query raw log line (%s)",
               strlen(cQuery) ? cQuery : "EMPTY");

    if(strlen(cQuery) == 0 || mysql_query(_mice_mod_pop_mysql_Sock, cQuery))
    {
      if(strlen(cQuery))
        _mice_mod_pop_mysql_iMaxErrCnt++;
      log_mesg(WARN, "mice_mod_pop_mysql: Error: mysql_query(%s) | MySQL_Error: %s\n",
               strlen(cQuery) ? cQuery : "EMPTY", mysql_error(_mice_mod_pop_mysql_Sock));
      return(-2);
    }
  }


  /*********************************************************
  **                                                      **
  ** scslog line                                          **
  **                                                      **
  *********************************************************/
  else if(LogFmt->uiFileType == FTF_SCSLOG)
  {
    if(_mice_mod_pop_mysql_Debug)
      log_mesg(WARN, "mice_mod_pop_mysql: Processing scslog line");

    SCSLogPtr = &LogFmt->logtype.scslog;
      
    memset(cQuery, 0, sizeof(cQuery));
    snprintf(cQuery, sizeof(cQuery),
             "INSERT INTO scslog_line (hostname, domain, ip, osystem, release, "
             "version, date, time, syscall, program, pid, uid, euid, call, comment) "
             "VALUES ('%s', '%s', '%s','%s','%s','%s','%s','%s','%s','%s',%d,%d,%d,'%s','%s')",
             LogFmt->cHost,
             LogFmt->cDomain,
             LogFmt->cIP,
             LogFmt->cOSystem,
             LogFmt->cRelease,
             LogFmt->cVersion,
             LogFmt->cDate,
             LogFmt->cTime,
             SCSLogPtr->cSyscall,
             SCSLogPtr->cProgram,
             SCSLogPtr->PID,
             SCSLogPtr->UID,
             SCSLogPtr->EUID,
             SCSLogPtr->cCall,
             SCSLogPtr->cComment );
     
    if(_mice_mod_pop_mysql_Debug)
      log_mesg(WARN, "mice_mod_pop_mysql: Query scslog line (%s)",
               strlen(cQuery) ? cQuery : "EMPTY");

    if(strlen(cQuery) == 0 || mysql_query(_mice_mod_pop_mysql_Sock, cQuery))
    {
      if(strlen(cQuery))
        _mice_mod_pop_mysql_iMaxErrCnt++;
      log_mesg(WARN, "mice_mod_pop_mysql: Error: mysql_query(%s) | MySQL_Error: %s\n",
               strlen(cQuery) ? cQuery : "EMPTY", mysql_error(_mice_mod_pop_mysql_Sock));
      return(-3);
    }
  }


  /*********************************************************
  **                                                      **
  ** firewall log line                                    **
  **                                                      **
  *********************************************************/
  else if(LogFmt->uiFileType == FTF_FIREWALL)
  {
    if(_mice_mod_pop_mysql_Debug)
      log_mesg(WARN, "mice_mod_pop_mysql: Processing firewall log line");

    FwLogPtr = &LogFmt->logtype.firewall;
    
    memset(cQuery, 0, sizeof(cQuery));
    snprintf(cQuery, sizeof(cQuery),
             "INSERT INTO firewall_line (action, if_in, if_out, mac, source, "
             "destination, ip_length, tos, prec, ttl, id, protocol, src_port, "
             "dst_port, pac_length, date, time) "
             "VALUES ('%s','%s','%s','%s','%s','%s',%d,%d,%d,%d,%d,'%s',%d,%d,%d,'%s','%s')",
             FwLogPtr->cAction,
             FwLogPtr->cIn,
             FwLogPtr->cOut,
             FwLogPtr->cMAC,
             FwLogPtr->cSource,
             FwLogPtr->cDestination,
             FwLogPtr->uiIPLength,
             FwLogPtr->uiTOS,
             FwLogPtr->uiPrec,
             FwLogPtr->uiTTL,
             FwLogPtr->uiID,
             FwLogPtr->cProtocol,
             FwLogPtr->uiSrcPort,
             FwLogPtr->uiDstPort,
             FwLogPtr->uiPacLength,
             LogFmt->cDate,
             LogFmt->cTime );

    if(_mice_mod_pop_mysql_Debug)
      log_mesg(WARN, "mice_mod_pop_mysql: Query firewall log line (%s)",
               strlen(cQuery) ? cQuery : "EMPTY");

    if(strlen(cQuery) == 0 || mysql_query(_mice_mod_pop_mysql_Sock, cQuery))
    {
      if(strlen(cQuery))
         _mice_mod_pop_mysql_iMaxErrCnt++;
      log_mesg(WARN, "mice_mod_pop_mysql: Error: mysql_query(%s) | MySQL_Error: %s\n",
               strlen(cQuery) ? cQuery : "EMPTY", mysql_error(_mice_mod_pop_mysql_Sock));
      return(-3);
    }
  }


#if defined(HAVE_LIBLAUSSRV)
  /*********************************************************
  **                                                      **
  ** laus log line                                        **
  **                                                      **
  *********************************************************/
  else if(LogFmt->uiFileType == FTF_LAUS)
  {
    struct aud_message  *amsg =  &(LogFmt->logtype.laus.msg);
    
    if(_mice_mod_pop_mysql_Debug)
      log_mesg(WARN, "mice_mod_pop_mysql: Processing laus log line");

    memset(cQuery, 0, sizeof(cQuery));


    /* create cQuery depending on Message Type */
    if(amsg->msg_size >= sizeof(*amsg))
    {
      switch (amsg->msg_type)
      {
        case AUDIT_MSG_LOGIN:
          if(_mice_mod_pop_mysql_Debug)
            log_mesg(WARN, "mice_mod_pop_mysql: laus -> login msg");
          if(laus_gen_login_msg(cQuery, LogFmt) < 0)
          {
            log_mesg(WARN, "mice_mod_pop_mysql: Error in laus_gen_login_msg()");
            return(-4);
          } 
          break;
        case AUDIT_MSG_TEXT:
          if(_mice_mod_pop_mysql_Debug)
            log_mesg(WARN, "mice_mod_pop_mysql: laus -> text msg");
          if(laus_gen_text_msg(cQuery, LogFmt) < 0)
          {
            log_mesg(WARN, "mice_mod_pop_mysql: Error in laus_gen_text_msg()");
            return(-4);
          }
          break;
        case AUDIT_MSG_SYSCALL:
          if(_mice_mod_pop_mysql_Debug)
            log_mesg(WARN, "mice_mod_pop_mysql: laus -> syscall msg");
          if(laus_gen_syscall_msg(cQuery, LogFmt) < 0)
          {
            log_mesg(WARN, "mice_mod_pop_mysql: Error in laus_gen_syscall_msg()");
            return(-4);
          }
          break;
        case AUDIT_MSG_NETLINK:
          if(_mice_mod_pop_mysql_Debug)
            log_mesg(WARN, "mice_mod_pop_mysql: laus -> netlink msg");
          if(laus_gen_netlink_msg(cQuery, LogFmt)  < 0)
          {
            log_mesg(WARN, "mice_mod_pop_mysql: Error in laus_gen_netlink_msg()");
            return(-4);
          }
          break;
        case AUDIT_MSG_EXIT:
          if(_mice_mod_pop_mysql_Debug)
            log_mesg(WARN, "mice_mod_pop_mysql: laus -> exit msg");
          if(laus_gen_exit_msg(cQuery, LogFmt) < 0)
          {
            log_mesg(WARN, "mice_mod_pop_mysql: Error in laus_gen_exit_msg()");
            return(-4);
          }
          break;
        default:
          if(_mice_mod_pop_mysql_Debug)
            log_mesg(WARN, "mice_mod_pop_mysql: laus -> unknown");
          if(laus_gen_unknown_msg(cQuery, LogFmt) < 0)
          {
            log_mesg(WARN, "mice_mod_pop_mysql: Error in laus_gen_unknown_msg()");
            return(-4);
          }
          break;
      }
    }
    else
    {
      if(_mice_mod_pop_mysql_Debug)
        log_mesg(WARN, "mice_mod_pop_mysql: amsg->msg_size [%d] < sizeof(*amsg) [%d]",
                        amsg->msg_size, sizeof(*amsg));
    }

    if(_mice_mod_pop_mysql_Debug)
      log_mesg(WARN, "mice_mod_pop_mysql: Query LAuS log line (%s)",
               strlen(cQuery) ? cQuery : "EMPTY");

    if(strlen(cQuery) == 0 || mysql_query(_mice_mod_pop_mysql_Sock, cQuery))
    {
      if(strlen(cQuery))
        _mice_mod_pop_mysql_iMaxErrCnt++;
      log_mesg(WARN, "mice_mod_pop_mysql: Error: mysql_query(%s) | MySQL_Error: %s\n",
               strlen(cQuery) ? cQuery : "EMPTY", mysql_error(_mice_mod_pop_mysql_Sock));
      return(-3);
    }
  }
#endif


  /*********************************************************
  **                                                      **
  ** UNKNOWN                                              **
  **                                                      **
  *********************************************************/
  else
  {
    if(_mice_mod_pop_mysql_Debug)
      log_mesg(WARN, "mice_mod_pop_mysql: log file type unknown");
  }


  if(_mice_mod_pop_mysql_iMaxErrCnt > 0)
    _mice_mod_pop_mysql_iMaxErrCnt--;
  return(0);
}

/* not used, but anyway... ;-) */
int mice_mod_pop_mysql_LTX_close(void)
{
  _mice_mod_pop_mysql_CfgDone = FALSE;

  if(_mice_mod_pop_mysql_Sock)
    mysql_close(_mice_mod_pop_mysql_Sock);

  return(0);
}




#ifdef HAVE_LIBLAUSSRV
int laus_gen_header(char *sql_query, LogFormat *lfmt, char *fmt)
{
  return(strlen(sql_query));
}

int laus_gen_login_msg(char *sql_query, LogFormat *lfmt)
{
  struct aud_message      *msg = &(lfmt->logtype.laus.msg);
  struct aud_msg_login	  *logmsg = &(lfmt->logtype.laus.type.msg_login);
  char                    timestr[64];
  time_t                  timestamp = msg->msg_timestamp;
  struct tm               *tm;
  
  
  if(sql_query == NULL || msg == NULL || msg->msg_type != AUDIT_MSG_LOGIN)
    return(-1);
  
  if (msg->msg_size != sizeof(*msg) + sizeof(*logmsg))
    return(-2);

  /* ensemble message */
  tm = localtime(&timestamp);
  strftime(timestr, sizeof(timestr), "%Y-%m-%dT%H:%M:%S", tm);

  snprintf(sql_query, MAX_QUERY_LENGTH,
           "INSERT INTO laus_login (seqnr, type, arch, pid, size, timestamp, "
           "audit_id, login_uid, euid, ruid, suid, fsuid, egid, rgid, sgid, "
           "fsgid, evname, uid, hostname, address, terminal, executeable) "
           "VALUES (%d,%d,%d,%d,%d,'%s',%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,'%s',%d,'%s','%s','%s','%s')",
           msg->msg_seqnr, msg->msg_type,
           msg->msg_arch, msg->msg_pid,
           msg->msg_size, timestr,
           msg->msg_audit_id, msg->msg_login_uid,
           msg->msg_euid, msg->msg_ruid,
           msg->msg_suid, msg->msg_fsuid,
           msg->msg_egid, msg->msg_rgid,
           msg->msg_sgid, msg->msg_fsgid,
           msg->msg_evname[0]    ? msg->msg_evname    : "NONE",
           logmsg->uid,
           logmsg->hostname[0]   ? logmsg->hostname   : "UNKNOWN",
           logmsg->address[0]    ? logmsg->address    : "UNKNOWN",
           logmsg->terminal[0]   ? logmsg->terminal   : "UNKNOWN",
           logmsg->executable[0] ? logmsg->executable : "UNKNOWN");

  return(strlen(sql_query));
}


int laus_gen_text_msg(char *sql_query, LogFormat *lfmt)
{
  struct aud_message      *msg = &(lfmt->logtype.laus.msg);
  char                    *txtmsg = (char *) &(lfmt->logtype.laus.type.msg_text);
  char                    timestr[64];
  time_t                  timestamp = msg->msg_timestamp;
  struct tm               *tm;


  if(sql_query == NULL || msg == NULL || msg->msg_type != AUDIT_MSG_TEXT)
    return(-1);

  if ( (msg->msg_size - sizeof(*msg)) <= 0)
    return(-2);

  /* ensemble message */
  tm = localtime(&timestamp);
  strftime(timestr, sizeof(timestr), "%Y-%m-%dT%H:%M:%S", tm);
    
  snprintf(sql_query, MAX_QUERY_LENGTH,
           "INSERT INTO laus_text (seqnr, type, arch, pid, size, timestamp, "
           "audit_id, login_uid, euid, ruid, suid, fsuid, egid, rgid, sgid, "
           "fsgid, evname, text) "
           "VALUES (%d,%d,%d,%d,%d,'%s',%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,'%s','%s')",
           msg->msg_seqnr, msg->msg_type,
           msg->msg_arch, msg->msg_pid,
           msg->msg_size, timestr,
           msg->msg_audit_id, msg->msg_login_uid,
           msg->msg_euid, msg->msg_ruid,
           msg->msg_suid, msg->msg_fsuid,
           msg->msg_egid, msg->msg_rgid,
           msg->msg_sgid, msg->msg_fsgid,
           msg->msg_evname[0] ? msg->msg_evname : "NONE",
           txtmsg[0]          ? txtmsg          : "UNKNOWN");

      
  return(strlen(sql_query));
}


int laus_gen_syscall_msg(char *sql_query, LogFormat *lfmt)
{
  struct aud_message            *msg = &(lfmt->logtype.laus.msg);
  laus_scall                    *scall = &(lfmt->logtype.laus.type.msg_syscall);
  char                          timestr[64];
  time_t                        timestamp = msg->msg_timestamp;
  struct tm                     *tm;
  char                          *result_type;

  
  if(sql_query == NULL || msg == NULL || msg->msg_type != AUDIT_MSG_SYSCALL)
    return(-1);

  if ( (msg->msg_size - sizeof(*msg)) <= 0)
    return(-2);

  /* ensemble message */
  tm = localtime(&timestamp);
  strftime(timestr, sizeof(timestr), "%Y-%m-%dT%H:%M:%S", tm);
  
  if(scall->result.type == SCRESULTTYPE_PTR)
    result_type = "Pointer";
  else if(scall->result.type == SCRESULTTYPE_INT)
    result_type = "Integer";
  else if(scall->result.type == SCRESULTTYPE_ERR)
    result_type = "Error";
  else
    result_type = "UNKNOWN";

  snprintf(sql_query, MAX_QUERY_LENGTH,
           "INSERT INTO laus_text (seqnr, type, arch, pid, size, timestamp, "
           "audit_id, login_uid, euid, ruid, suid, fsuid, egid, rgid, sgid, "
           "fsgid, evname, major, minor, name, result, resulttype, nargs) "
           "VALUES (%d,%d,%d,%d,%d,'%s',%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,'%s',%d,%d,'%s',%d,'%s',%d)",
           msg->msg_seqnr, msg->msg_type,
           msg->msg_arch, msg->msg_pid,
           msg->msg_size, timestr,
           msg->msg_audit_id, msg->msg_login_uid,
           msg->msg_euid, msg->msg_ruid,
           msg->msg_suid, msg->msg_fsuid,
           msg->msg_egid, msg->msg_rgid,
           msg->msg_sgid, msg->msg_fsgid,
           msg->msg_evname[0] ? msg->msg_evname : "NONE",
           scall->major,
           scall->minor,
           scall->name[0]     ? scall->name     : "UNKNOWN",
           scall->result.value,
           result_type,
           scall->nargs);


  return(strlen(sql_query));
}

int laus_gen_netlink_msg(char *sql_query, LogFormat *lfmt)
{
  /* XXX thomas: we do not support them now */
  log_mesg(WARN, "mice_mod_pop_mysql: Netlink messages are not supported.\n");
  return(0);
}

int laus_gen_exit_msg(char *sql_query, LogFormat *lfmt)
{
  struct aud_message    *msg = &(lfmt->logtype.laus.msg);
  struct aud_msg_exit   *exitmsg = &(lfmt->logtype.laus.type.msg_exit);
  char                  timestr[64];
  time_t                timestamp = msg->msg_timestamp;
  struct tm             *tm;

  
  if(sql_query == NULL || msg == NULL || msg->msg_type != AUDIT_MSG_EXIT)
    return(-1);

    
  /* ensemble message */
  tm = localtime(&timestamp);
  strftime(timestr, sizeof(timestr), "%Y-%m-%dT%H:%M:%S", tm);

  snprintf(sql_query, MAX_QUERY_LENGTH,
           "INSERT INTO laus_text (seqnr, type, arch, pid, size, timestamp, "
           "audit_id, login_uid, euid, ruid, suid, fsuid, egid, rgid, sgid, "
           "fsgid, evname, exit_code) "
           "VALUES (%d,%d,%d,%d,%d,'%s',%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,'%s','%ld')",
           msg->msg_seqnr, msg->msg_type,
           msg->msg_arch, msg->msg_pid,
           msg->msg_size, timestr,
           msg->msg_audit_id, msg->msg_login_uid,
           msg->msg_euid, msg->msg_ruid,
           msg->msg_suid, msg->msg_fsuid,
           msg->msg_egid, msg->msg_rgid,
           msg->msg_sgid, msg->msg_fsgid,
           msg->msg_evname[0] ? msg->msg_evname : "NONE",
           exitmsg->code);


  return(strlen(sql_query));
}

int laus_gen_unknown_msg(char *sql_query, LogFormat *lfmt)
{
  struct aud_message    *msg = &(lfmt->logtype.laus.msg);

  log_mesg(WARN, "mice_mod_pop_mysql: unknown message type %d:0x%02x\n", msg->msg_type, msg->msg_type);
  
  if(_mice_mod_pop_mysql_Debug)
  {
    //debug_message((char *) msg, sizeof(*msg));
  }
    
  return(-1);
}
#endif

void debug_message(char *data, size_t size)
{
  int i;

  for(i = 0; i < size; i++)
    log_mesg(WARN, "mice_mod_pop_mysql: debug_message: %d [%d | 0x%02x | %c]\n",
             i, data[i], data[i], isascii(data[i]) ? data[i] : '?');
}



/*
** Handle Config File
*/
int _mice_mod_pop_mysql_HandleConfFile(char *cConfFile)
{
  int             iCfgCount;
  int             iCnt;
  struct stat     StatBuf;

  _mice_mod_pop_mysql_iSectMySQLServ  = -1;
  _mice_mod_pop_mysql_iSectPseudo     = -1;

  if(lstat(cConfFile, &StatBuf) < 0)
  {
    log_mesg(WARN_SYS, "Error while trying lstat(%s) | Syserror", cConfFile);
    return(-1);
  }

  if((iCfgCount = cfgParse(cConfFile, _mice_mod_pop_mysql_CfgIni, CFG_INI)) < 0)
  {
    log_mesg(WARN, "Error while parsing Config File %s\n", cConfFile);
    return(-1);
  }

  if(iCfgCount != MAXSECT)
  {
    log_mesg(WARN, "Error while parsing Config File %s | Sections Read: %d | Sections Expect: %d", cConfFile, iCfgCount, MAXSECT);
    return(-1);
  }

  for(iCnt = 0; iCnt < iCfgCount; iCnt++)
  {
    if(!strcasecmp(cfgSectionNumberToName(iCnt), MYSQLSERV))
      _mice_mod_pop_mysql_iSectMySQLServ = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), PSEUDONYM))
      _mice_mod_pop_mysql_iSectPseudo = iCnt;
    else
    {
      log_mesg(WARN, "Error in Config File %s | Unknown Section: %s", cConfFile, cfgSectionNumberToName(iCnt));
      return(-1);
    }
  }

  if(_mice_mod_pop_mysql_iSectMySQLServ == -1 || _mice_mod_pop_mysql_iSectPseudo == -1)
  {
    log_mesg(WARN, "Error in Config File %s, Section is missing!\n", cConfFile);
    return(-1);
  }

  return(0);
}
