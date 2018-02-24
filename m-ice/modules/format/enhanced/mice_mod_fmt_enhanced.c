/***************************************************************************
                          mice_mod_fmt_enhanced.c  -  description
                             -------------------
    copyright            : (C) 2004 by Thomas Biege
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

#include "mice_mod_fmt_enhanced.h"

extern char *tzname[2];
extern long timezone;
extern int  daylight;

#define __USE_GNU

int  _mice_mod_fmt_enhanced_Debug = 1;

/*
** Configure Stuff
*/
char        **_mice_mod_fmt_enhanced_CfgDomainName;

int         _mice_mod_fmt_enhanced_iSectLogFormat;

cfgStruct   _mice_mod_fmt_enhanced_CfgIni[] =
{
  {"DOMAINNAME" ,CFG_STRING       ,&_mice_mod_fmt_enhanced_CfgDomainName },
  {NULL         ,CFG_END          ,NULL                                  }
};


/*
** Function Declaration
*/
int     _mice_mod_fmt_enhanced_HandleConfFile(char *cConfFile);


/*
** Module Functions
*/
int mice_mod_fmt_enhanced_LTX_init(char *ConfFile)
{
  //log_open("mice_mod_fmt_enhanced", LOG_PID, LOG_USER);

  _mice_mod_fmt_enhanced_HandleConfFile(ConfFile);

  /* timezome init */
  (void) tzset();

  return(0);
}

int mice_mod_fmt_enhanced_LTX_func(LogFormat *LogFmt, char *cLogData, size_t LogDataLen, u_int uiFileType)
{
  char              cFQDN[MAX_HOST+MAX_DOMAIN+1] = {0};

  time_t            Time;

  struct utsname    SysInfo;
  struct tm         *TimePtr;
  struct in_addr    InAddr;
  

  if(_mice_mod_fmt_enhanced_iSectLogFormat != (SECT_MAXSECT-1))
  {
    log_mesg(WARN, "mice_mod_fmt_enhanced: Error: you have to call mice_mod_fmt_enhanced_LTX_init() first!\n");
    return(-1);
  }

  if(_mice_mod_fmt_enhanced_Debug)
    log_mesg(WARN, "mice_mod_fmt_enhanced: Checking arguments");
      
  if(LogFmt == NULL || cLogData == NULL || LogDataLen == 0)
  {
    log_mesg(WARN, "mice_mod_fmt_enhanced: Error: invalid argument\n");
    return(-1);
  }
  
  

  /*
  ** Client Informations
  */
  if(gethostname(LogFmt->cHost, sizeof(LogFmt->cHost)-1) != 0)
  {
    log_mesg(WARN, "mice_mod_fmt_enhanced: Error while looking up local Hostname\n");
    strncpy(LogFmt->cHost, "ERROR", sizeof(LogFmt->cHost)-1);
  }

  if(uname(&SysInfo) != 0)
  {
    log_mesg(WARN, "mice_mod_fmt_enhanced: Error while calling uname(2)\n");
    //strncat(LogFmt->cDomain , "ERROR", sizeof(LogFmt->cDomain )-1);
    strncpy(LogFmt->cOSystem, "ERROR", sizeof(LogFmt->cOSystem)-1);
    strncpy(LogFmt->cRelease, "ERROR", sizeof(LogFmt->cRelease)-1);
    strncpy(LogFmt->cVersion, "ERROR", sizeof(LogFmt->cVersion)-1);
  }
  else
  {                             // XXX: __domainname, this sux! :(
    //strncpy(LogFmt->cDomain , SysInfo.__domainname, sizeof(LogFmt->cDomain )-1);
    strncpy(LogFmt->cOSystem, SysInfo.sysname     , sizeof(LogFmt->cOSystem)-1);
    strncpy(LogFmt->cRelease, SysInfo.release     , sizeof(LogFmt->cRelease)-1);
    strncpy(LogFmt->cVersion, SysInfo.version     , sizeof(LogFmt->cVersion)-1);
  }
  // XXX: ersetzen durch host_lookup() nameResolv()
  strncpy(LogFmt->cDomain, _mice_mod_fmt_enhanced_CfgDomainName[_mice_mod_fmt_enhanced_iSectLogFormat],
          sizeof(LogFmt->cDomain )-1);
  sprintf(cFQDN, "%s.%s", LogFmt->cHost, LogFmt->cDomain);
  if((InAddr.s_addr = name_resolve(cFQDN)) == 0)
  {
    log_mesg(WARN_SYS, "mice_mod_fmt_enhanced: Error name_resolve(%s) | Syserror", cFQDN);
    strncat(LogFmt->cIP, "ERROR", sizeof(LogFmt->cIP)-1);
  }
  else
    strncpy(LogFmt->cIP, inet_ntoa(InAddr), sizeof(LogFmt->cIP)-1);

  if(time(&Time) == ((time_t)-1))
  {
    log_mesg(WARN, "mice_mod_fmt_enhanced: Error while calling time(2)\n");
    strncpy(LogFmt->cDate, "ERROR", sizeof(LogFmt->cDate)-1);
    strncpy(LogFmt->cTime, "ERROR", sizeof(LogFmt->cTime)-1);
    strncpy(LogFmt->cTimezone, "ERROR", sizeof(LogFmt->cTimezone)-1);
    LogFmt->iDaylight = -1;
  }
  else
  {
    char dummy[MAX_DATE];
    TimePtr = localtime(&Time);
    if(TimePtr->tm_year < 100)
      snprintf(dummy, sizeof(dummy), "19%d", TimePtr->tm_year);
    else // XXX: we just handle years < 21XX hope it's enough ;)
      snprintf(dummy, sizeof(dummy), "20%02d", TimePtr->tm_year-100);

    snprintf(LogFmt->cDate, sizeof(LogFmt->cDate), "%s/%02d/%02d", dummy,
             TimePtr->tm_mon+1, TimePtr->tm_mday);
    snprintf(LogFmt->cTime, sizeof(LogFmt->cTime), "%02d:%02d:%02d",
             TimePtr->tm_hour, TimePtr->tm_min, TimePtr->tm_sec);
    snprintf(LogFmt->cTimezone, sizeof(LogFmt->cTimezone), "%s %s",
             tzname[0] ? tzname[0] : "UNKNOWN", tzname[1] ? tzname[1] : "UNKNOWN");
    LogFmt->iDaylight = daylight;
  }

  
  /*********************************************************
  **                                                      **
  ** raw log line                                         **
  **                                                      **
  *********************************************************/
  if(LogDataLen > sizeof(LogFmt->cLogdata)-1) /* XXX record truncated */
    memcpy(LogFmt->cLogdata, cLogData, sizeof(LogFmt->cLogdata)-1);
  else
    memcpy(LogFmt->cLogdata, cLogData, LogDataLen);


  /* lets got with the more structured data */
  
  /*********************************************************
  **                                                      **
  ** scslog line                                          **
  **                                                      **
  *********************************************************/
  if(uiFileType == FTF_SCSLOG)
  {
    if(_mice_mod_fmt_enhanced_Debug)
      log_mesg(WARN, "mice_mod_fmt_enhanced: Processing scslog line");

    if(parse_scslog_entry(cLogData, &(LogFmt->logtype.scslog)) < 0)
      log_mesg(WARN, "mice_mod_fmt_enhanced: Error while parsing scslog line");
      
  }

  /*********************************************************
  **                                                      **
  ** firewall log line                                    **
  **                                                      **
  *********************************************************/
  else if(uiFileType == FTF_FIREWALL)
  {
    if(_mice_mod_fmt_enhanced_Debug)
      log_mesg(WARN, "mice_mod_fmt_enhanced: Processing firewall log line");
  
    if(parse_firewall_entry(cLogData, &(LogFmt->logtype.firewall)) < 0)
      log_mesg(WARN, "mice_mod_fmt_enhanced: Error while parsing scslog line");

  }

#if defined(HAVE_LIBLAUSSRV)
  /*********************************************************
  **                                                      **
  ** laus log line                                        **
  **                                                      **
  *********************************************************/
  else if(uiFileType == FTF_LAUS)
  {
    struct aud_message  *amsg =  (struct aud_message *) cLogData;
    //typedef char amsg_aligned_t[-(ssize_t)(offsetof(LogFormat, cLogData) & (__alignof__(*amsg) - 1))];

    if(_mice_mod_fmt_enhanced_Debug)
      log_mesg(WARN, "mice_mod_fmt_enhanced: Processing laus log line (size= %d)", amsg->msg_size);


    /* create LogFmt depending on Message Type */
    if (amsg->msg_size >= sizeof(*amsg))
    {
      switch (amsg->msg_type)
      {
        case AUDIT_MSG_LOGIN:
          if(_mice_mod_fmt_enhanced_Debug)
            log_mesg(WARN, "mice_mod_fmt_enhanced: Processing laus log line -> login");
          if(parse_laus_login_msg(cLogData, &(LogFmt->logtype.laus)) < 0)
          {
            log_mesg(WARN, "mice_mod_fmt_enhanced: Error in parse_laus_login_msg()");
            return(-4);
          }
          break;
        case AUDIT_MSG_TEXT:
          if(_mice_mod_fmt_enhanced_Debug)
            log_mesg(WARN, "mice_mod_fmt_enhanced: Processing laus log line -> text");
          if(parse_laus_text_msg(cLogData, &(LogFmt->logtype.laus)) < 0)
          {
            log_mesg(WARN, "mice_mod_fmt_enhanced: Error in parse_laus_text_msg()");
            return(-4);
          }
          break;
        case AUDIT_MSG_SYSCALL:
          if(_mice_mod_fmt_enhanced_Debug)
            log_mesg(WARN, "mice_mod_fmt_enhanced: Processing laus log line -> syscall");
          if(parse_laus_syscall_msg(cLogData, &(LogFmt->logtype.laus)) < 0)
          {
            log_mesg(WARN, "mice_mod_fmt_enhanced: Error in parse_laus_syscall_msg()");
            return(-4);
          }
          break;
        case AUDIT_MSG_NETLINK:
          if(_mice_mod_fmt_enhanced_Debug)
            log_mesg(WARN, "mice_mod_fmt_enhanced: Processing laus log line -> netlink");
          if(parse_laus_netlink_msg(cLogData, &(LogFmt->logtype.laus))  < 0)
          {
            log_mesg(WARN, "mice_mod_fmt_enhanced: Error in parse_laus_netlink_msg()");
            return(-4);
          }
          break;
        case AUDIT_MSG_EXIT:
          if(_mice_mod_fmt_enhanced_Debug)
            log_mesg(WARN, "mice_mod_fmt_enhanced: Processing laus log line -> exit");
          if(parse_laus_exit_msg(cLogData, &(LogFmt->logtype.laus)) < 0)
          {
            log_mesg(WARN, "mice_mod_fmt_enhanced: Error in parse_laus_exit_msg()");
            return(-4);
          }
          break;
        default:
          if(_mice_mod_fmt_enhanced_Debug)
            log_mesg(WARN, "mice_mod_fmt_enhanced: Processing laus log line -> unknown");
          return(-4);
      }
    }
  }
#endif
  else
  {
    if(_mice_mod_fmt_enhanced_Debug)
      log_mesg(WARN, "mice_mod_fmt_enhanced: Unknown file type: %d", uiFileType);
    return(-1);
  }


  /*
  ** Keep Data Integrity by calculating a CRC sum
  */
  LogFmt->sChkSum = 0;
  LogFmt->sChkSum = in_chksum((u_short *) LogFmt, sizeof(LogFormat));

  return(0);
}

/* not used, but anyway... ;-) */
int mice_mod_fmt_enhanced_LTX_close(void)
{
  return(0);
}

void debug_message(char *data, size_t size)
{
  int i;

  for(i = 0; i < size; i++)
    log_mesg(WARN, "mice_mod_fmt_enhanced: debug_message: %d [%d | 0x%02x | %c]\n",
    i, data[i], data[i], isascii(data[i]) ? data[i] : '?');
}


/*
** Handle Config File
*/
int _mice_mod_fmt_enhanced_HandleConfFile(char *cConfFile)
{
  int             iCfgCount;
  int             iCnt;
  struct stat     StatBuf;


  _mice_mod_fmt_enhanced_iSectLogFormat = -1;

  if(lstat(cConfFile, &StatBuf) < 0)
  {
    log_mesg(WARN_SYS, "mice_mod_fmt_enhanced: Error while trying lstat(%s) | Syserror", cConfFile);
    return(-1);
  }

  if((iCfgCount = cfgParse(cConfFile, _mice_mod_fmt_enhanced_CfgIni, CFG_INI)) < 0)
  {
    log_mesg(WARN, "mice_mod_fmt_enhanced: Error while parsing Config File %s\n", cConfFile);
    return(-2);
  }

  if(iCfgCount != SECT_MAXSECT)
  {
    log_mesg(WARN, "mice_mod_fmt_enhanced: Error while parsing Config File %s | Sections Read: %d | Sections Expect: %d", cConfFile, iCfgCount, SECT_MAXSECT);
    return(-3);
  }

  for(iCnt = 0; iCnt < iCfgCount; iCnt++)
  {
    if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_FORMAT))
      _mice_mod_fmt_enhanced_iSectLogFormat = iCnt;
    else
    {
      log_mesg(WARN, "mice_mod_fmt_enhanced: Error in Config File %s | Unknown Section: %s", cConfFile, cfgSectionNumberToName(iCnt));
      return(-4);
    }
  }

  if(_mice_mod_fmt_enhanced_iSectLogFormat == -1)
  {
    log_mesg(WARN, "mice_mod_fmt_enhanced: Error in Config File %s, Section is missing!\n", cConfFile);
    return(-5);
  }

  return(0);
}

