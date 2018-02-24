/***************************************************************************
                          mice_mod_fmt_simple.c  -  description
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

#include "mice_mod_fmt_simple.h"


#define __USE_GNU


/*
** Configure Stuff
*/
char        **_mice_mod_fmt_simple_CfgDomainName;

int         _mice_mod_fmt_simple_iSectLogFormat;

cfgStruct   _mice_mod_fmt_simple_CfgIni[] =
{
  {"DOMAINNAME" ,CFG_STRING       ,&_mice_mod_fmt_simple_CfgDomainName },
  {NULL         ,CFG_END          ,NULL                }
};


/*
** Function Declaration
*/
int _mice_mod_fmt_simple_HandleConfFile(char *cConfFile);


/*
** Module Functions
*/
int mice_mod_fmt_simple_LTX_init(char *ConfFile)
{
  //log_open("mice_mod_fmt_simple", LOG_PID, LOG_USER);

  _mice_mod_fmt_simple_HandleConfFile(ConfFile);

  return(0);
}

int mice_mod_fmt_simple_LTX_func(LogFormat *LogEntry, char *cLogData, size_t LogDataLen, u_int uiFileType)
{
  char              cFQDN[MAX_HOST+MAX_DOMAIN+1] = {0};

  time_t            Time;

  struct utsname    SysInfo;
  struct tm         *TimePtr;
  struct in_addr    InAddr;


  if(_mice_mod_fmt_simple_iSectLogFormat != (SECT_MAXSECT-1))
  {
    log_mesg(WARN, "mice_mod_fmt_simple: Error! You have to call mice_mod_fmt_simple_LTX_init() first!\n");
    return(-1);
  }

  if(gethostname(LogEntry->cHost, sizeof(LogEntry->cHost)-1) != 0)
  {
    log_mesg(WARN, "mice_mod_fmt_simple: Error while looking up local Hostname\n");
    strncpy(LogEntry->cHost, "ERROR", sizeof(LogEntry->cHost)-1);
  }

  if(uname(&SysInfo) != 0)
  {
    log_mesg(WARN, "mice_mod_fmt_simple: Error while calling uname(2)\n");
    //strncat(LogEntry->cDomain , "ERROR", sizeof(LogEntry->cDomain )-1);
    strncpy(LogEntry->cOSystem, "ERROR", sizeof(LogEntry->cOSystem)-1);
    strncpy(LogEntry->cRelease, "ERROR", sizeof(LogEntry->cRelease)-1);
    strncpy(LogEntry->cVersion, "ERROR", sizeof(LogEntry->cVersion)-1);
  }
  else
  {                             // XXX: __domainname, this sux! :(
    //strncpy(LogEntry->cDomain , SysInfo.__domainname, sizeof(LogEntry->cDomain )-1);
    strncpy(LogEntry->cOSystem, SysInfo.sysname     , sizeof(LogEntry->cOSystem)-1);
    strncpy(LogEntry->cRelease, SysInfo.release     , sizeof(LogEntry->cRelease)-1);
    strncpy(LogEntry->cVersion, SysInfo.version     , sizeof(LogEntry->cVersion)-1);
  }
  // XXX: ersetzen durch host_lookup() nameResolv()
  strncpy(LogEntry->cDomain, _mice_mod_fmt_simple_CfgDomainName[_mice_mod_fmt_simple_iSectLogFormat], sizeof(LogEntry->cDomain )-1);
  sprintf(cFQDN, "%s.%s", LogEntry->cHost, LogEntry->cDomain);
  if((InAddr.s_addr = name_resolve(cFQDN)) == 0)
  {
    log_mesg(WARN_SYS, "mice_mod_fmt_simple: Error name_resolve(%s) | Syserror", cFQDN);
    strncat(LogEntry->cIP, "ERROR", sizeof(LogEntry->cIP)-1);
  }
  else
    strncpy(LogEntry->cIP, inet_ntoa(InAddr), sizeof(LogEntry->cIP)-1);

  if(time(&Time) == ((time_t)-1))
  {
    log_mesg(WARN, "mice_mod_fmt_simple: Error while calling time(2)\n");
    strncpy(LogEntry->cDate, "ERROR", sizeof(LogEntry->cDate)-1);
    strncpy(LogEntry->cTime, "ERROR", sizeof(LogEntry->cTime)-1);
  }
  else
  {
    char dummy[MAX_DATE];
    TimePtr = localtime(&Time);
    if(TimePtr->tm_year < 100)
      snprintf(dummy, sizeof(dummy), "19%d", TimePtr->tm_year);
    else // XXX: we just handle years < 21XX hope it's enough ;)
      snprintf(dummy, sizeof(dummy), "20%02d", TimePtr->tm_year-100);

    snprintf(LogEntry->cDate, sizeof(LogEntry->cDate), "%s/%02d/%02d", dummy, TimePtr->tm_mon+1, TimePtr->tm_mday);
    snprintf(LogEntry->cTime, sizeof(LogEntry->cTime), "%02d:%02d:%02d", TimePtr->tm_hour, TimePtr->tm_min, TimePtr->tm_sec);
  }
  // XXX should we add an extra entry for GMT -> better when monitoring host in different timezones!!!

  if(LogDataLen > sizeof(LogEntry->cLogdata)-1) /* XXX record truncated */
    memcpy(LogEntry->cLogdata, cLogData, sizeof(LogEntry->cLogdata)-1);
  else
    memcpy(LogEntry->cLogdata, cLogData, LogDataLen);

  /*
  ** Keep Data Integrity by calculating a CRC sum
  */
  LogEntry->sChkSum = 0;
  LogEntry->sChkSum = in_chksum((u_short *) LogEntry, sizeof(LogFormat));

  return(0);
}

/* not used, but anyway... ;-) */
int mice_mod_fmt_simple_LTX_close(void)
{
  return(0);
}



/*
** Handle Config File
*/
int _mice_mod_fmt_simple_HandleConfFile(char *cConfFile)
{
  int             iCfgCount;
  int             iCnt;
  struct stat     StatBuf;


  _mice_mod_fmt_simple_iSectLogFormat = -1;

  if(lstat(cConfFile, &StatBuf) < 0)
  {
    log_mesg(WARN_SYS, "mice_mod_fmt_simple: Error while trying lstat(%s) | Syserror", cConfFile);
    return(-1);
  }

  if((iCfgCount = cfgParse(cConfFile, _mice_mod_fmt_simple_CfgIni, CFG_INI)) < 0)
  {
    log_mesg(WARN, "mice_mod_fmt_simple: Error while parsing Config File %s\n", cConfFile);
    return(-2);
  }

  if(iCfgCount != SECT_MAXSECT)
  {
    log_mesg(WARN, "mice_mod_fmt_simple: Error while parsing Config File %s | Sections Read: %d | Sections Expect: %d", cConfFile, iCfgCount, SECT_MAXSECT);
    return(-3);
  }

  for(iCnt = 0; iCnt < iCfgCount; iCnt++)
  {
    if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_FORMAT))
      _mice_mod_fmt_simple_iSectLogFormat = iCnt;
    else
    {
      log_mesg(WARN, "mice_mod_fmt_simple: Error in Config File %s | Unknown Section: %s", cConfFile, cfgSectionNumberToName(iCnt));
      return(-4);
    }
  }

  if(_mice_mod_fmt_simple_iSectLogFormat == -1)
  {
    log_mesg(WARN, "mice_mod_fmt_simple: Error in Config File %s, Section is missing!\n", cConfFile);
    return(-5);
  }

  return(0);
}

