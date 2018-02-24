/***************************************************************************
                          mice_mod_pop_aa_regex.c  -  description
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
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <resolv.h>
#include <regex.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <mcrypt.h>


/*
** Get LibIDMEF from http://www.silicondefense.com/idwg/
*/
#include <libidmef/idmefxml.h>

#include <libxml/xmlversion.h>


#include <mice.h>
#include <logformat.h>
#include "mice_mod_pop_aa_regex.h"
#include "idmef-mesg-format.h"
#include "checksum.h"
#include "parsecfg.h"



#ifndef MAXHOSTNAMELEN
  #define MAXHOSTNAMELEN  64
#endif

#define TRUE              1
#define FALSE             0



int _mice_mod_pop_aa_regex_iDebug = FALSE;


/*
** Crypto
*/
MCRYPT _mice_mod_pop_aa_regex_CryptModule;


/*
** RegEx stuff
*/
struct re_pattern_buffer    *_mice_mod_pop_aa_regex_RegExBuf = NULL;


/*
** static IDMEF informations
*/
struct
{
  // For Alert Class
  u_long  ulAlertID;
  char    *cAlertIDFile;

  // For Analyzer Class
  char *cAnalyzerID;
  char *cManufactur;
  char *cModel;
  char *cVersion;
  char *cClass;
  char *cOSType;
  char *cOSVersion;

  // For Node Class
  char *cLocation;  // not used
  char *cNodeName;

  // For Address Class
  char *cAddress;

  // For Process Class
  char *cProcName;
  char *cPID;    // XXX wirklich statisch?
  char *cPath;   // not used
  char *cArg;    // not used
  char *cEnv;    // not used

  // Crypto
  char  *cKey_MH;
  char  *cKey_AA;
  int   iEnc;
} _mice_mod_pop_aa_regex_StaticInfo;


/*
** MatchLine Info
*/
typedef struct
{
  int   iMatched;
  int   iSectNr;
  int   iSectType;
  int   iRuleNr;
  char  *cRuleType;
  int   iLogType;       // Either LT_RAW or LT_SCS
  char  *cMatchedRule;
  char  *cSendTo;
} MatchInfo;


/*
** Host Tupels
*/
char  *_mice_mod_pop_aa_regex_cMngmntAddr;
char  *_mice_mod_pop_aa_regex_cMngmntPort;
char  *_mice_mod_pop_aa_regex_cAgentAddr;
char  *_mice_mod_pop_aa_regex_cAgentPort;


/*
** Configure Stuff
*/

int _mice_mod_pop_aa_regex_CfgDone = FALSE;

struct
{
  int     iSectionNr;
  char    **cCfgMngmnt;
  char    **cCfgAgent;
  int      *iCfgEncryption;
  char    **cCfgMngmntKey;  // XXX: what's about protected pages for our Keys so they can not be swapped?
  char    **cCfgAgentKey;
} _mice_mod_pop_aa_regex_CfgHostInfo;

struct
{
  int     iSectionNr;
  char    **cCfgAlertID;
  char    **cCfgAlertIDFile;
  char    **cCfgDTDFile;
} _mice_mod_pop_aa_regex_CfgIdmefInfo;

struct
{
  int     iSectionNr;
  char    **cCfgSendTo;
  cfgList **aCfgAuthSucc;
  cfgList **aCfgAuthFail;
} _mice_mod_pop_aa_regex_CfgAuth;

struct
{
  int     iSectionNr;
  char    **cCfgSendTo;
  cfgList **aCfgRootExec;
  cfgList **aCfgRootWrite;
  cfgList **aCfgRootRead;
  cfgList **aCfgRootOpen;
  cfgList **aCfgRootSock;
} _mice_mod_pop_aa_regex_CfgRoot;

struct
{
  int     iSectionNr;
  char    **cCfgSendTo;
  cfgList **aCfgReadSucc;
  cfgList **aCfgReadFail;
} _mice_mod_pop_aa_regex_CfgRead;

struct
{
  int     iSectionNr;
  char    **cCfgSendTo;
  cfgList **aCfgWriteSucc;
  cfgList **aCfgWriteFail;
} _mice_mod_pop_aa_regex_CfgWrite;

struct
{
  int     iSectionNr;
  char    **cCfgSendTo;
  cfgList **aCfgMonUID;
  cfgList **aCfgMonGID;
} _mice_mod_pop_aa_regex_CfgMon;

struct
{
  int     iSectionNr;
  char    **cCfgSendTo;
  cfgList **aCfgAppsName;
} _mice_mod_pop_aa_regex_CfgApps;

struct
{
  int     iSectionNr;
  char    **cCfgSendTo;
  cfgList **aCfgExplSig;
} _mice_mod_pop_aa_regex_CfgExpl;

struct
{
  int     iSectionNr;
  char    **cCfgSendTo;
  cfgList **aCfgFwDrop;
  cfgList **aCfgFwReject;
  cfgList **aCfgFwAccept;
  cfgList **aCfgFwIllegal;
} _mice_mod_pop_aa_regex_CfgFw;

struct
{
  int     iSectionNr;
  char    **cCfgSendTo;
} _mice_mod_pop_aa_regex_CfgDefault;


cfgStruct    _mice_mod_pop_aa_regex_CfgIni[] =
{
  // Host Info
  {"Management"   ,CFG_STRING       ,&_mice_mod_pop_aa_regex_CfgHostInfo.cCfgMngmnt        },
  {"Agent"        ,CFG_STRING       ,&_mice_mod_pop_aa_regex_CfgHostInfo.cCfgAgent         },
  {"Encryption"   ,CFG_BOOL         ,&_mice_mod_pop_aa_regex_CfgHostInfo.iCfgEncryption    },
  {"MngmntKey"    ,CFG_STRING       ,&_mice_mod_pop_aa_regex_CfgHostInfo.cCfgMngmntKey     },
  {"AgentKey"     ,CFG_STRING       ,&_mice_mod_pop_aa_regex_CfgHostInfo.cCfgAgentKey      },

  // IDMEF Info
  {"AlertID"      ,CFG_STRING       ,&_mice_mod_pop_aa_regex_CfgIdmefInfo.cCfgAlertID      },
  {"AlertIDFile"  ,CFG_STRING       ,&_mice_mod_pop_aa_regex_CfgIdmefInfo.cCfgAlertIDFile  },
  {"DTDFile"      ,CFG_STRING       ,&_mice_mod_pop_aa_regex_CfgIdmefInfo.cCfgDTDFile      },

  // Auth Section
  {"AuSendTo"     ,CFG_STRING       ,&_mice_mod_pop_aa_regex_CfgAuth.cCfgSendTo            },
  {"AuS_Rule"     ,CFG_STRING_LIST  ,&_mice_mod_pop_aa_regex_CfgAuth.aCfgAuthSucc          },
  {"AuF_Rule"     ,CFG_STRING_LIST  ,&_mice_mod_pop_aa_regex_CfgAuth.aCfgAuthFail          },

  // Root Section
  {"RoSendTo"     ,CFG_STRING       ,&_mice_mod_pop_aa_regex_CfgRoot.cCfgSendTo            },
  {"RoE_Rule"     ,CFG_STRING_LIST  ,&_mice_mod_pop_aa_regex_CfgRoot.aCfgRootExec          },
  {"RoW_Rule"     ,CFG_STRING_LIST  ,&_mice_mod_pop_aa_regex_CfgRoot.aCfgRootWrite         },
  {"RoR_Rule"     ,CFG_STRING_LIST  ,&_mice_mod_pop_aa_regex_CfgRoot.aCfgRootRead          },
  {"RoO_Rule"     ,CFG_STRING_LIST  ,&_mice_mod_pop_aa_regex_CfgRoot.aCfgRootOpen          },
  {"RoS_Rule"     ,CFG_STRING_LIST  ,&_mice_mod_pop_aa_regex_CfgRoot.aCfgRootSock          },

  // Read Section
  {"ReSendTo"     ,CFG_STRING       ,&_mice_mod_pop_aa_regex_CfgRead.cCfgSendTo            },
  {"ReS_Rule"     ,CFG_STRING_LIST  ,&_mice_mod_pop_aa_regex_CfgRead.aCfgReadSucc          },
  {"ReF_Rule"     ,CFG_STRING_LIST  ,&_mice_mod_pop_aa_regex_CfgRead.aCfgReadFail          },

  // Write Section
  {"WrSendTo"     ,CFG_STRING       ,&_mice_mod_pop_aa_regex_CfgWrite.cCfgSendTo           },
  {"WrS_Rule"     ,CFG_STRING_LIST  ,&_mice_mod_pop_aa_regex_CfgWrite.aCfgWriteSucc        },
  {"WrF_Rule"     ,CFG_STRING_LIST  ,&_mice_mod_pop_aa_regex_CfgWrite.aCfgWriteFail        },

  // Monitoring Section
  {"MoSendTo"     ,CFG_STRING       ,&_mice_mod_pop_aa_regex_CfgMon.cCfgSendTo             },
  {"Mo_UID"       ,CFG_STRING_LIST  ,&_mice_mod_pop_aa_regex_CfgMon.aCfgMonUID             },
  {"Mo_GID"       ,CFG_STRING_LIST  ,&_mice_mod_pop_aa_regex_CfgMon.aCfgMonGID             },

  // Apps Section
  {"ApSendTo"     ,CFG_STRING       ,&_mice_mod_pop_aa_regex_CfgApps.cCfgSendTo            },
  {"Ap_Name"      ,CFG_STRING_LIST  ,&_mice_mod_pop_aa_regex_CfgApps.aCfgAppsName          },

  // Exploit Section
  {"ExSendTo"     ,CFG_STRING       ,&_mice_mod_pop_aa_regex_CfgExpl.cCfgSendTo            },
  {"Ex_Rule"      ,CFG_STRING_LIST  ,&_mice_mod_pop_aa_regex_CfgExpl.aCfgExplSig           },

  // Firewall Section
  {"FwSendTo"     ,CFG_STRING       ,&_mice_mod_pop_aa_regex_CfgFw.cCfgSendTo              },
  {"FwD_Rule"     ,CFG_STRING_LIST  ,&_mice_mod_pop_aa_regex_CfgFw.aCfgFwDrop              },
  {"FwR_Rule"     ,CFG_STRING_LIST  ,&_mice_mod_pop_aa_regex_CfgFw.aCfgFwAccept            },
  {"FwA_Rule"     ,CFG_STRING_LIST  ,&_mice_mod_pop_aa_regex_CfgFw.aCfgFwReject            },
  {"FwI_Rule"     ,CFG_STRING_LIST  ,&_mice_mod_pop_aa_regex_CfgFw.aCfgFwIllegal           },

  // Default Section
  {"DeSendTo"     ,CFG_STRING       ,&_mice_mod_pop_aa_regex_CfgDefault.cCfgSendTo         },

  // The End
  {NULL           ,CFG_END          ,NULL                                              }
};



/*
** Function Declaration
*/
int          mice_mod_pop_aa_regex_LTX_close       (void);
int         _mice_mod_pop_aa_regex_HandleConfFile  (char *cConfFile);
int         _mice_mod_pop_aa_regex_MatchLine       (char *cLogLine, size_t LogLineLen, MatchInfo *mInfo);
int         _mice_mod_pop_aa_regex_DoesMatch       (char *cLogLine, size_t LogLineLen, char *cRule);
int         _mice_mod_pop_aa_regex_Action          (LogFormat LogFmt, MatchInfo mInfo);
int         _mice_mod_pop_aa_regex_WhichHost       (char cSendTo);
int         _mice_mod_pop_aa_regex_SendTo          (char *cAddress, char *cPort, char *cData, size_t DataLen, char *cKey);
xmlNodePtr  _mice_mod_pop_aa_regex_FormatIDMEF     (LogFormat LogFmt, MatchInfo mInfo);
xmlNodePtr  _mice_mod_pop_aa_regex_BuildMsg        (LogFormat LogFmt, MatchInfo mInfo);
xmlNodePtr  _mice_mod_pop_aa_regex_BuildMsgTree    (LogFormat LogFmt, MatchInfo mInfo);
xmlNodePtr  _mice_mod_pop_aa_regex_BuildAnalyzer   (LogFormat LogFmt);
xmlNodePtr  _mice_mod_pop_aa_regex_BuildSource     (LogFormat LogFmt);
xmlNodePtr  _mice_mod_pop_aa_regex_BuildTarget     (LogFormat LogFmt);



/***************************************************************************************
**
** p u b l i c   M o d u l e   F u n c t i o n s
**
***************************************************************************************/


/*
** Init
*/
size_t mice_mod_pop_aa_regex_LTX_init(char *ConfFile)
{
  char            *cPtr;
  char            cHostname[MAXHOSTNAMELEN+1]   = {0};
  char            cFQDN[2*MAXHOSTNAMELEN+2]     = {0};

  char            *cKey_MH,
                  *cKey_AA;

  struct utsname  UnameInfo;
  struct in_addr  IpAddr;

  size_t          KeySize = 16;


  //log_open("mice_mod_pop_aa_regex", LOG_PID, LOG_USER);


  if(_mice_mod_pop_aa_regex_CfgDone != FALSE)
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: Do NOT call init function twice, call close function inbetween");
    return(-1);
  }


  /*
  ** Parse config File
  */
  if(_mice_mod_pop_aa_regex_iDebug)
    log_mesg(WARN, "mice_mod_pop_aa_regex: parse config file");

  if(_mice_mod_pop_aa_regex_HandleConfFile(ConfFile) < 0)
    return(-1);

  if(uname(&UnameInfo) != 0)
    return(-2);


  /*
  ** Split up Host Info
  */
  if(_mice_mod_pop_aa_regex_iDebug)
    log_mesg(WARN, "mice_mod_pop_aa_regex: read host info");

  if( (cPtr = strchr(_mice_mod_pop_aa_regex_CfgHostInfo.cCfgMngmnt[_mice_mod_pop_aa_regex_CfgHostInfo.iSectionNr], (int) ':')) == NULL)
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: Error splitting up Host Info for Management Host\n");
    return(-3);
  }
  *cPtr = 0;
  cPtr++;
  _mice_mod_pop_aa_regex_cMngmntAddr = _mice_mod_pop_aa_regex_CfgHostInfo.cCfgMngmnt[_mice_mod_pop_aa_regex_CfgHostInfo.iSectionNr];
  _mice_mod_pop_aa_regex_cMngmntPort = cPtr;

  if( (cPtr = strchr((const char *) _mice_mod_pop_aa_regex_CfgHostInfo.cCfgAgent[_mice_mod_pop_aa_regex_CfgHostInfo.iSectionNr], (int) ':')) == NULL)
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: Error splitting up Host Info for Agent Host\n");
    return(-4);
  }
  *cPtr = 0;
  cPtr++;
  _mice_mod_pop_aa_regex_cAgentAddr = _mice_mod_pop_aa_regex_CfgHostInfo.cCfgAgent[_mice_mod_pop_aa_regex_CfgHostInfo.iSectionNr];
  _mice_mod_pop_aa_regex_cAgentPort = cPtr;


  /*
  ** Let's init the RegEx Stuff
  */
  if(_mice_mod_pop_aa_regex_iDebug)
    log_mesg(WARN, "mice_mod_pop_aa_regex: init regex");

  re_syntax_options = RE_SYNTAX_POSIX_EGREP;

  if(_mice_mod_pop_aa_regex_RegExBuf != NULL)
    mice_mod_pop_aa_regex_LTX_close();

  if((_mice_mod_pop_aa_regex_RegExBuf = (struct re_pattern_buffer *) malloc(sizeof(struct re_pattern_buffer))) == NULL)
  {
    log_mesg(WARN_SYS, "mice_mod_pop_aa_regex: Error while allocating Memory for _mice_mod_pop_aa_regex_RegExBuf | Syserror");
    return(-5);
  }

  if((_mice_mod_pop_aa_regex_RegExBuf->fastmap = (char *) malloc(FASTMAPSIZE)) == NULL)
  {
    log_mesg(WARN_SYS, "mice_mod_pop_aa_regex: Error while allocating Memory for _mice_mod_pop_aa_regex_RegExBuf->fastmap | Syserror");
    return(-6);
  }

  _mice_mod_pop_aa_regex_RegExBuf->translate = (char *) 0;
  _mice_mod_pop_aa_regex_RegExBuf->buffer    = NULL;
  _mice_mod_pop_aa_regex_RegExBuf->allocated = 0;


  /*
  ** IDMEF Init Stuff
  */
  if(_mice_mod_pop_aa_regex_iDebug)
    log_mesg(WARN, "mice_mod_pop_aa_regex: init IDMEF");

  xmlSubstituteEntitiesDefault(0);

  globalsInit(_mice_mod_pop_aa_regex_CfgIdmefInfo.cCfgDTDFile[_mice_mod_pop_aa_regex_CfgIdmefInfo.iSectionNr]);

  if(gethostname(cHostname, MAXHOSTNAMELEN) != 0)
  {
    log_mesg(WARN_SYS, "mice_mod_pop_aa_regex: Error while looking up local host name | Syserror");
    return(-7);
  }

  /*
  if(res_init() != 0)
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: Error while calling res_init()");
    return(-8);
  }

  snprintf(cFQDN, sizeof(cFQDN), "%s.%s", cHostname, _res.defdname);
  */


  if( (cPtr = host_lookup(name_resolve(cHostname))) == NULL )
  {
    log_mesg(WARN_SYS, "mice_mod_pop_aa_regex: Error while looking up local host name | Syserror");
    return(-7);
  }
  snprintf(cFQDN, sizeof(cFQDN), "%s", cPtr);
  free(cPtr);


  if(_mice_mod_pop_aa_regex_iDebug)
    log_mesg(WARN, "mice_mod_pop_aa_regex: FQDN = %s", cFQDN);

  IpAddr.s_addr = name_resolve(cFQDN);


  _mice_mod_pop_aa_regex_StaticInfo.ulAlertID      = (u_long) strtol(_mice_mod_pop_aa_regex_CfgIdmefInfo.cCfgAlertID[_mice_mod_pop_aa_regex_CfgIdmefInfo.iSectionNr], NULL, 10);
  _mice_mod_pop_aa_regex_StaticInfo.cAlertIDFile   = _mice_mod_pop_aa_regex_CfgIdmefInfo.cCfgAlertIDFile[_mice_mod_pop_aa_regex_CfgIdmefInfo.iSectionNr];
  _mice_mod_pop_aa_regex_StaticInfo.cAnalyzerID    = "MICE-RegEx";
  _mice_mod_pop_aa_regex_StaticInfo.cManufactur    = "Thomas Biege <TheTom@UnixIsNot4Dummies.org>";
  _mice_mod_pop_aa_regex_StaticInfo.cModel         = "M-ICE - Modular Intrusion Countermeasure Environment";
  _mice_mod_pop_aa_regex_StaticInfo.cVersion       = "Release 0.1 Beta";
  _mice_mod_pop_aa_regex_StaticInfo.cClass         = "HIDS";
  _mice_mod_pop_aa_regex_StaticInfo.cOSType        = strdup(UnameInfo.sysname);
  _mice_mod_pop_aa_regex_StaticInfo.cOSVersion     = strdup(UnameInfo.release);

  _mice_mod_pop_aa_regex_StaticInfo.cNodeName      = strdup(cFQDN);
  _mice_mod_pop_aa_regex_StaticInfo.cAddress       = strdup(inet_ntoa(IpAddr));

  _mice_mod_pop_aa_regex_StaticInfo.cProcName      = "mice_mod_pop_aa_regex";
  _mice_mod_pop_aa_regex_StaticInfo.cPID           = intToString(getpid());


  /* attempt to retrieve a stored Alert ID */
  if(!access(_mice_mod_pop_aa_regex_StaticInfo.cAlertIDFile, F_OK))
  {
    _mice_mod_pop_aa_regex_StaticInfo.ulAlertID = getStoredAlertID(_mice_mod_pop_aa_regex_StaticInfo.cAlertIDFile);

    if(_mice_mod_pop_aa_regex_StaticInfo.ulAlertID == 0)
    {
      log_mesg(WARN, "mice_mod_pop_aa_regex: Error retreiving the stored Alert ID\n");
      return(-8);
    }
  }


  /*
  ** Init the Crypto Stuff
  */
  if(_mice_mod_pop_aa_regex_CfgHostInfo.iCfgEncryption[_mice_mod_pop_aa_regex_CfgHostInfo.iSectionNr] &&
     (_mice_mod_pop_aa_regex_CfgHostInfo.cCfgMngmntKey[_mice_mod_pop_aa_regex_CfgHostInfo.iSectionNr] != NULL ||
      _mice_mod_pop_aa_regex_CfgHostInfo.cCfgAgentKey[_mice_mod_pop_aa_regex_CfgHostInfo.iSectionNr] != NULL)
    )
    _mice_mod_pop_aa_regex_StaticInfo.iEnc = TRUE;
  else
    _mice_mod_pop_aa_regex_StaticInfo.iEnc = FALSE;


  if(_mice_mod_pop_aa_regex_StaticInfo.iEnc == TRUE)
  {
    if(_mice_mod_pop_aa_regex_iDebug)
      log_mesg(WARN, "mice_mod_pop_aa_regex: start init crypto");


    // Key
    if(_mice_mod_pop_aa_regex_iDebug)
      log_mesg(WARN, "mice_mod_pop_aa_regex: alloc memory for key");

    if(_mice_mod_pop_aa_regex_CfgHostInfo.cCfgMngmntKey[_mice_mod_pop_aa_regex_CfgHostInfo.iSectionNr] != NULL)
    {
      if((_mice_mod_pop_aa_regex_StaticInfo.cKey_MH = calloc(1, KeySize)) == NULL)
      {
        log_mesg(WARN, "mice_mod_pop_aa_regex: Error while allocating Memory for Twofish Key\n");
        return(-9);
      }
      memmove(_mice_mod_pop_aa_regex_StaticInfo.cKey_MH, _mice_mod_pop_aa_regex_CfgHostInfo.cCfgMngmntKey[_mice_mod_pop_aa_regex_CfgHostInfo.iSectionNr], KeySize);
    }

    if(_mice_mod_pop_aa_regex_CfgHostInfo.cCfgAgentKey[_mice_mod_pop_aa_regex_CfgHostInfo.iSectionNr] != NULL)
    {
      if((_mice_mod_pop_aa_regex_StaticInfo.cKey_AA = calloc(1, KeySize)) == NULL)
      {
        log_mesg(WARN, "mice_mod_pop_aa_regex: Error while allocating Memory for Twofish Key\n");
        return(-10);
      }
      memmove(_mice_mod_pop_aa_regex_StaticInfo.cKey_AA, _mice_mod_pop_aa_regex_CfgHostInfo.cCfgAgentKey[_mice_mod_pop_aa_regex_CfgHostInfo.iSectionNr], KeySize);
    }


    // open Crypt Module
    if(_mice_mod_pop_aa_regex_iDebug)
      log_mesg(WARN, "mice_mod_pop_aa_regex: open crypt module");

    if((_mice_mod_pop_aa_regex_CryptModule = mcrypt_module_open("twofish", NULL, "cfb", NULL)) == MCRYPT_FAILED)
    {
      log_mesg(WARN, "mice_mod_pop_aa_regex: Error while trying to load Crypto Module '%s'\n", "twofish");
      return(-11);
    }
  }


  // XXX open tcp connection and init mcrypt


  _mice_mod_pop_aa_regex_CfgDone = TRUE;

  return(sizeof(LogFormat));
}



/*
** Main Function
*/
int mice_mod_pop_aa_regex_LTX_func(char *cData, size_t DataSize)
{
  size_t      LogLineLen;
  LogFormat   LogFmt;
  cfgList     *TmpList;
  MatchInfo   mInfo;


  if(_mice_mod_pop_aa_regex_CfgDone != TRUE)
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: Error! You have to call mice_mod_pop_aa_regex_LTX_init() first!\n");
    return(-1);
  }

  if(sizeof(LogFormat) != DataSize)
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: Error! Received Datasize does not match expected Datasize!\n");
    return(-2);
  }

  if(_mice_mod_pop_aa_regex_iDebug > 1)
    log_mesg(WARN, "mice_mod_pop_aa_regex: data = %s | strlen = %d | datalen = %d", cData, strlen(cData), DataSize);

  //LogFmt = (LogFormat) cData;
  memcpy((char *) &LogFmt, cData, sizeof(LogFormat));


  LogLineLen = strlen(LogFmt.cLogdata);


  /*
  ** Let's see if the log data does match or does not
  */
  if(_mice_mod_pop_aa_regex_iDebug)
    log_mesg(WARN, "mice_mod_pop_aa_regex: try to match line");

  if(_mice_mod_pop_aa_regex_MatchLine(LogFmt.cLogdata, LogLineLen, &mInfo) == TRUE)
  {
    if(_mice_mod_pop_aa_regex_iDebug)
      log_mesg(WARN, "mice_mod_pop_aa_regex: line matched");
  }
  else
  {
    if(_mice_mod_pop_aa_regex_iDebug)
      log_mesg(WARN, "mice_mod_pop_aa_regex: line did NOT match");
  }




  /*
  ** XXX: hier SCSLogs erkennen, parsen und strukturieren!!!
  *
  ParseScsLogLine(irgendeine struct fuellen)
  */


  /*
  ** Execute the appropriate action.
  */
  if(_mice_mod_pop_aa_regex_iDebug)
    log_mesg(WARN, "mice_mod_pop_aa_regex: execute action");

  _mice_mod_pop_aa_regex_Action(LogFmt, mInfo);


  return(mInfo.iMatched);
}



/* not used, but anyway... ;-) */
/*
** Close
*/
int mice_mod_pop_aa_regex_LTX_close(void)
{

  if(!saveAlertID(_mice_mod_pop_aa_regex_StaticInfo.ulAlertID, _mice_mod_pop_aa_regex_StaticInfo.cAlertIDFile))
    log_mesg(WARN, "mice_mod_pop_aa_regex: Error trying to save last IDMEF Alert ID (%lu) to %s\n", _mice_mod_pop_aa_regex_StaticInfo.ulAlertID, _mice_mod_pop_aa_regex_StaticInfo.cAlertIDFile);

  free(_mice_mod_pop_aa_regex_RegExBuf->fastmap);
  free(_mice_mod_pop_aa_regex_RegExBuf);

  free(_mice_mod_pop_aa_regex_StaticInfo.cAlertIDFile);
  free(_mice_mod_pop_aa_regex_StaticInfo.cOSType);
  free(_mice_mod_pop_aa_regex_StaticInfo.cOSVersion);
  free(_mice_mod_pop_aa_regex_StaticInfo.cAddress);
  free(_mice_mod_pop_aa_regex_StaticInfo.cNodeName);

  // libidmef
  clearCurrentDoc();

  // XXX close tcp connection and mcrypt stuff here
  return(0);
}



/**************************************************************************************
**
** private Sub Routines
**
**************************************************************************************/


/*
** Go throu all Rules and try to match them
**
** Return: FALSE, TRUE
*/
int _mice_mod_pop_aa_regex_MatchLine(char *cLogLine, size_t LogLineLen, MatchInfo *mInfo)
{
  int     iRuleCtr;
  cfgList *TmpList;


  if(_mice_mod_pop_aa_regex_iDebug > 1)
    log_mesg(WARN, "mice_mod_pop_aa_regex: LINE '%s'", cLogLine);


  /******************************************************************************
  **
  ** A U T H   R U L E S
  **
  ******************************************************************************/

  // Auth Success
  for(TmpList = _mice_mod_pop_aa_regex_CfgAuth.aCfgAuthSucc[_mice_mod_pop_aa_regex_CfgAuth.iSectionNr], iRuleCtr = 0; TmpList != NULL; TmpList = TmpList->next, iRuleCtr++)
  {
    if(_mice_mod_pop_aa_regex_DoesMatch(cLogLine, LogLineLen, TmpList->str) == TRUE)
    {
      if(_mice_mod_pop_aa_regex_iDebug)
        log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: Auth Success");

      /*
      ** Fill in Match Info Data
      */
      mInfo->iMatched     = TRUE;
      mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgAuth.iSectionNr;
      mInfo->iSectType    = ST_AUTH;
      mInfo->iRuleNr      = iRuleCtr;
      mInfo->cRuleType    = RT_AUTH_S;
      mInfo->cMatchedRule = TmpList->str;
      mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgAuth.cCfgSendTo[_mice_mod_pop_aa_regex_CfgAuth.iSectionNr];

      return(TRUE);
    }
  }


  // Auth Failure
  for(TmpList = _mice_mod_pop_aa_regex_CfgAuth.aCfgAuthFail[_mice_mod_pop_aa_regex_CfgAuth.iSectionNr], iRuleCtr = 0; TmpList != NULL; TmpList = TmpList->next, iRuleCtr++)
  {
    if(_mice_mod_pop_aa_regex_DoesMatch(cLogLine, LogLineLen, TmpList->str) == TRUE)
    {
      if(_mice_mod_pop_aa_regex_iDebug)
        log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: Auth Failure");

      /*
      ** Fill in Match Info Data
      */
      mInfo->iMatched     = TRUE;
      mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgAuth.iSectionNr;
      mInfo->iSectType    = ST_AUTH;
      mInfo->iRuleNr      = iRuleCtr;
      mInfo->cRuleType    = RT_AUTH_F;
      mInfo->cMatchedRule = TmpList->str;
      mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgAuth.cCfgSendTo[_mice_mod_pop_aa_regex_CfgAuth.iSectionNr];

      return(TRUE);
    }
  }



  /******************************************************************************
  **
  ** R O O T   R U L E S
  **
  ******************************************************************************/

  // Root Write
  for(TmpList = _mice_mod_pop_aa_regex_CfgRoot.aCfgRootWrite[_mice_mod_pop_aa_regex_CfgRoot.iSectionNr], iRuleCtr = 0; TmpList != NULL; TmpList = TmpList->next, iRuleCtr++)
  {
    if(_mice_mod_pop_aa_regex_DoesMatch(cLogLine, LogLineLen, TmpList->str) == TRUE)
    {
      if(_mice_mod_pop_aa_regex_iDebug)
        log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: Root Write");

      /*
      ** Fill in Match Info Data
      */
      mInfo->iMatched     = TRUE;
      mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgRoot.iSectionNr;
      mInfo->iSectType    = ST_ROOT;
      mInfo->iRuleNr      = iRuleCtr;
      mInfo->cRuleType    = RT_ROOT_W;
      mInfo->cMatchedRule = TmpList->str;
      mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgRoot.cCfgSendTo[_mice_mod_pop_aa_regex_CfgRoot.iSectionNr];

      return(TRUE);
    }
  }

  // Root Open
  for(TmpList = _mice_mod_pop_aa_regex_CfgRoot.aCfgRootOpen[_mice_mod_pop_aa_regex_CfgRoot.iSectionNr], iRuleCtr = 0; TmpList != NULL; TmpList = TmpList->next, iRuleCtr++)
  {
    if(_mice_mod_pop_aa_regex_DoesMatch(cLogLine, LogLineLen, TmpList->str) == TRUE)
    {
      if(_mice_mod_pop_aa_regex_iDebug)
        log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: Root Open");

      /*
      ** Fill in Match Info Data
      */
      mInfo->iMatched     = TRUE;
      mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgRoot.iSectionNr;
      mInfo->iSectType    = ST_ROOT;
      mInfo->iRuleNr      = iRuleCtr;
      mInfo->cRuleType    = RT_ROOT_O;
      mInfo->cMatchedRule = TmpList->str;
      mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgRoot.cCfgSendTo[_mice_mod_pop_aa_regex_CfgRoot.iSectionNr];

      return(TRUE);
    }
  }

  // Root Read
  for(TmpList = _mice_mod_pop_aa_regex_CfgRoot.aCfgRootRead[_mice_mod_pop_aa_regex_CfgRoot.iSectionNr], iRuleCtr = 0; TmpList != NULL; TmpList = TmpList->next, iRuleCtr++)
  {
    if(_mice_mod_pop_aa_regex_DoesMatch(cLogLine, LogLineLen, TmpList->str) == TRUE)
    {
      if(_mice_mod_pop_aa_regex_iDebug)
        log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: Root Read");

      /*
      ** Fill in Match Info Data
      */
      mInfo->iMatched     = TRUE;
      mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgRoot.iSectionNr;
      mInfo->iSectType    = ST_ROOT;
      mInfo->iRuleNr      = iRuleCtr;
      mInfo->cRuleType    = RT_ROOT_R;
      mInfo->cMatchedRule = TmpList->str;
      mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgRoot.cCfgSendTo[_mice_mod_pop_aa_regex_CfgRoot.iSectionNr];

      return(TRUE);
    }
  }

  // Root Socket
  for(TmpList = _mice_mod_pop_aa_regex_CfgRoot.aCfgRootSock[_mice_mod_pop_aa_regex_CfgRoot.iSectionNr], iRuleCtr = 0; TmpList != NULL; TmpList = TmpList->next, iRuleCtr++)
  {
    if(_mice_mod_pop_aa_regex_DoesMatch(cLogLine, LogLineLen, TmpList->str) == TRUE)
    {
      if(_mice_mod_pop_aa_regex_iDebug)
        log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: Root Socket");

      /*
      ** Fill in Match Info Data
      */
      mInfo->iMatched     = TRUE;
      mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgRoot.iSectionNr;
      mInfo->iSectType    = ST_ROOT;
      mInfo->iRuleNr      = iRuleCtr;
      mInfo->cRuleType    = RT_ROOT_S;
      mInfo->cMatchedRule = TmpList->str;
      mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgRoot.cCfgSendTo[_mice_mod_pop_aa_regex_CfgRoot.iSectionNr];

      return(TRUE);
    }
  }

  // Root Exec
  for(TmpList = _mice_mod_pop_aa_regex_CfgRoot.aCfgRootExec[_mice_mod_pop_aa_regex_CfgRoot.iSectionNr], iRuleCtr = 0; TmpList != NULL; TmpList = TmpList->next, iRuleCtr++)
  {
    if(_mice_mod_pop_aa_regex_DoesMatch(cLogLine, LogLineLen, TmpList->str) == TRUE)
    {
      if(_mice_mod_pop_aa_regex_iDebug)
        log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: Root Exec");

      /*
      ** Fill in Match Info Data
      */
      mInfo->iMatched     = TRUE;
      mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgRoot.iSectionNr;
      mInfo->iSectType    = ST_ROOT;
      mInfo->iRuleNr      = iRuleCtr;
      mInfo->cRuleType    = RT_ROOT_E;
      mInfo->cMatchedRule = TmpList->str;
      mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgRoot.cCfgSendTo[_mice_mod_pop_aa_regex_CfgRoot.iSectionNr];

      return(TRUE);
    }
  }



  /******************************************************************************
  **
  ** R E A D   R U L E S
  **
  ******************************************************************************/

  // Read Success
  for(TmpList = _mice_mod_pop_aa_regex_CfgRead.aCfgReadSucc[_mice_mod_pop_aa_regex_CfgRead.iSectionNr], iRuleCtr = 0; TmpList != NULL; TmpList = TmpList->next, iRuleCtr++)
  {
    if(_mice_mod_pop_aa_regex_DoesMatch(cLogLine, LogLineLen, TmpList->str) == TRUE)
    {
      if(_mice_mod_pop_aa_regex_iDebug)
        log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: Root Success");

      /*
      ** Fill in Match Info Data
      */
      mInfo->iMatched     = TRUE;
      mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgRead.iSectionNr;
      mInfo->iSectType    = ST_READ;
      mInfo->iRuleNr      = iRuleCtr;
      mInfo->cRuleType    = RT_READ_S;
      mInfo->cMatchedRule = TmpList->str;
      mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgRead.cCfgSendTo[_mice_mod_pop_aa_regex_CfgRead.iSectionNr];

      return(TRUE);
    }
  }


  // Read Failure
  for(TmpList = _mice_mod_pop_aa_regex_CfgRead.aCfgReadFail[_mice_mod_pop_aa_regex_CfgRead.iSectionNr], iRuleCtr = 0; TmpList != NULL; TmpList = TmpList->next, iRuleCtr++)
  {
    if(_mice_mod_pop_aa_regex_DoesMatch(cLogLine, LogLineLen, TmpList->str) == TRUE)
    {
      if(_mice_mod_pop_aa_regex_iDebug)
        log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: Root Failure");

      /*
      ** Fill in Match Info Data
      */
      mInfo->iMatched     = TRUE;
      mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgRead.iSectionNr;
      mInfo->iSectType    = ST_READ;
      mInfo->iRuleNr      = iRuleCtr;
      mInfo->cRuleType    = RT_READ_F;
      mInfo->cMatchedRule = TmpList->str;
      mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgRead.cCfgSendTo[_mice_mod_pop_aa_regex_CfgRead.iSectionNr];

      return(TRUE);
    }
  }



  /******************************************************************************
  **
  ** W R I T E   R U L E S
  **
  ******************************************************************************/

  // Write Success
  for(TmpList = _mice_mod_pop_aa_regex_CfgWrite.aCfgWriteSucc[_mice_mod_pop_aa_regex_CfgWrite.iSectionNr], iRuleCtr = 0; TmpList != NULL; TmpList = TmpList->next, iRuleCtr++)
  {
    if(_mice_mod_pop_aa_regex_DoesMatch(cLogLine, LogLineLen, TmpList->str) == TRUE)
    {
      if(_mice_mod_pop_aa_regex_iDebug)
        log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: Write Success");

      /*
      ** Fill in Match Info Data
      */
      mInfo->iMatched     = TRUE;
      mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgWrite.iSectionNr;
      mInfo->iSectType    = ST_WRITE;
      mInfo->iRuleNr      = iRuleCtr;
      mInfo->cRuleType    = RT_WRITE_S;
      mInfo->cMatchedRule = TmpList->str;
      mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgWrite.cCfgSendTo[_mice_mod_pop_aa_regex_CfgWrite.iSectionNr];

      return(TRUE);
    }
  }


  // Write Failure
  for(TmpList = _mice_mod_pop_aa_regex_CfgWrite.aCfgWriteFail[_mice_mod_pop_aa_regex_CfgWrite.iSectionNr], iRuleCtr = 0; TmpList != NULL; TmpList = TmpList->next, iRuleCtr++)
  {
    if(_mice_mod_pop_aa_regex_DoesMatch(cLogLine, LogLineLen, TmpList->str) == TRUE)
    {
      if(_mice_mod_pop_aa_regex_iDebug)
        log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: Write Failure");

      /*
      ** Fill in Match Info Data
      */
      mInfo->iMatched     = TRUE;
      mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgWrite.iSectionNr;
      mInfo->iSectType    = ST_WRITE;
      mInfo->iRuleNr      = iRuleCtr;
      mInfo->cRuleType    = RT_WRITE_F;
      mInfo->cMatchedRule = TmpList->str;
      mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgWrite.cCfgSendTo[_mice_mod_pop_aa_regex_CfgWrite.iSectionNr];

      return(TRUE);
    }
  }



  /******************************************************************************
  **
  ** M O N I T O R I N G   R U L E S
  **
  ******************************************************************************/

  // Monitor UID
  for(TmpList = _mice_mod_pop_aa_regex_CfgMon.aCfgMonUID[_mice_mod_pop_aa_regex_CfgMon.iSectionNr], iRuleCtr = 0; TmpList != NULL; TmpList = TmpList->next, iRuleCtr++)
  {
    if(_mice_mod_pop_aa_regex_DoesMatch(cLogLine, LogLineLen, TmpList->str) == TRUE)
    {
      if(_mice_mod_pop_aa_regex_iDebug)
        log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: Monitor UID");

      /*
      ** Fill in Match Info Data
      */
      mInfo->iMatched     = TRUE;
      mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgMon.iSectionNr;
      mInfo->iSectType    = ST_MONI;
      mInfo->iRuleNr      = iRuleCtr;
      mInfo->cRuleType    = RT_MONI_U;
      mInfo->cMatchedRule = TmpList->str;
      mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgMon.cCfgSendTo[_mice_mod_pop_aa_regex_CfgMon.iSectionNr];

      return(TRUE);
    }
  }


  // Monitor GID
  for(TmpList = _mice_mod_pop_aa_regex_CfgMon.aCfgMonGID[_mice_mod_pop_aa_regex_CfgMon.iSectionNr], iRuleCtr = 0; TmpList != NULL; TmpList = TmpList->next, iRuleCtr++)
  {
    if(_mice_mod_pop_aa_regex_DoesMatch(cLogLine, LogLineLen, TmpList->str) == TRUE)
    {
      if(_mice_mod_pop_aa_regex_iDebug)
        log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: Monitor GID");

      /*
      ** Fill in Match Info Data
      */
      mInfo->iMatched     = TRUE;
      mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgMon.iSectionNr;
      mInfo->iSectType    = ST_MONI;
      mInfo->iRuleNr      = iRuleCtr;
      mInfo->cRuleType    = RT_MONI_G;
      mInfo->cMatchedRule = TmpList->str;
      mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgMon.cCfgSendTo[_mice_mod_pop_aa_regex_CfgMon.iSectionNr];

      return(TRUE);
    }
  }



  /******************************************************************************
  **
  ** A P P L I C A T I O N   R U L E S
  **
  ******************************************************************************/

  // App. Name
  for(TmpList = _mice_mod_pop_aa_regex_CfgApps.aCfgAppsName[_mice_mod_pop_aa_regex_CfgApps.iSectionNr], iRuleCtr = 0; TmpList != NULL; TmpList = TmpList->next, iRuleCtr++)
  {
    if(_mice_mod_pop_aa_regex_DoesMatch(cLogLine, LogLineLen, TmpList->str) == TRUE)
    {
      if(_mice_mod_pop_aa_regex_iDebug)
        log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: App Name");

      /*
      ** Fill in Match Info Data
      */
      mInfo->iMatched     = TRUE;
      mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgApps.iSectionNr;
      mInfo->iSectType    = ST_APPS;
      mInfo->iRuleNr      = iRuleCtr;
      mInfo->cRuleType    = RT_APPS_N;
      mInfo->cMatchedRule = TmpList->str;
      mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgApps.cCfgSendTo[_mice_mod_pop_aa_regex_CfgApps.iSectionNr];

      return(TRUE);
    }
  }



  /******************************************************************************
  **
  ** E X P L O I T   S I G N A T U R E   R U L E S
  **
  ******************************************************************************/

  // Exploit Rules
  for(TmpList = _mice_mod_pop_aa_regex_CfgExpl.aCfgExplSig[_mice_mod_pop_aa_regex_CfgExpl.iSectionNr], iRuleCtr = 0; TmpList != NULL; TmpList = TmpList->next, iRuleCtr++)
  {
    if(_mice_mod_pop_aa_regex_DoesMatch(cLogLine, LogLineLen, TmpList->str) == TRUE)
    {
      if(_mice_mod_pop_aa_regex_iDebug)
        log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: Exploit Rule");

      /*
      ** Fill in Match Info Data
      */
      mInfo->iMatched     = TRUE;
      mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgExpl.iSectionNr;
      mInfo->iSectType    = ST_EXPL;
      mInfo->iRuleNr      = iRuleCtr;
      mInfo->cRuleType    = RT_EXPL_R;
      mInfo->cMatchedRule = TmpList->str;
      mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgExpl.cCfgSendTo[_mice_mod_pop_aa_regex_CfgExpl.iSectionNr];

      return(TRUE);
    }
  }



  /******************************************************************************
  **
  ** F I R E W A L L   R U L E S
  **
  ******************************************************************************/

  // Drop
  for(TmpList = _mice_mod_pop_aa_regex_CfgFw.aCfgFwDrop[_mice_mod_pop_aa_regex_CfgFw.iSectionNr], iRuleCtr = 0; TmpList != NULL; TmpList = TmpList->next, iRuleCtr++)
  {
    if(_mice_mod_pop_aa_regex_DoesMatch(cLogLine, LogLineLen, TmpList->str) == TRUE)
    {
      if(_mice_mod_pop_aa_regex_iDebug)
        log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: Firewall Rule: Drop");

      /*
      ** Fill in Match Info Data
      */
      mInfo->iMatched     = TRUE;
      mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgFw.iSectionNr;
      mInfo->iSectType    = ST_FW;
      mInfo->iRuleNr      = iRuleCtr;
      mInfo->cRuleType    = RT_FW_D;
      mInfo->cMatchedRule = TmpList->str;
      mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgFw.cCfgSendTo[_mice_mod_pop_aa_regex_CfgFw.iSectionNr];

      return(TRUE);
    }
  }

  // Reject
  for(TmpList = _mice_mod_pop_aa_regex_CfgFw.aCfgFwReject[_mice_mod_pop_aa_regex_CfgFw.iSectionNr], iRuleCtr = 0; TmpList != NULL; TmpList = TmpList->next, iRuleCtr++)
  {
    if(_mice_mod_pop_aa_regex_DoesMatch(cLogLine, LogLineLen, TmpList->str) == TRUE)
    {
      if(_mice_mod_pop_aa_regex_iDebug)
        log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: Firewall Rule: Reject");

      /*
      ** Fill in Match Info Data
      */
      mInfo->iMatched     = TRUE;
      mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgFw.iSectionNr;
      mInfo->iSectType    = ST_FW;
      mInfo->iRuleNr      = iRuleCtr;
      mInfo->cRuleType    = RT_FW_R;
      mInfo->cMatchedRule = TmpList->str;
      mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgFw.cCfgSendTo[_mice_mod_pop_aa_regex_CfgFw.iSectionNr];

      return(TRUE);
    }
  }

  // Accept
  for(TmpList = _mice_mod_pop_aa_regex_CfgFw.aCfgFwAccept[_mice_mod_pop_aa_regex_CfgFw.iSectionNr], iRuleCtr = 0; TmpList != NULL; TmpList = TmpList->next, iRuleCtr++)
  {
    if(_mice_mod_pop_aa_regex_DoesMatch(cLogLine, LogLineLen, TmpList->str) == TRUE)
    {
      if(_mice_mod_pop_aa_regex_iDebug)
        log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: Firewall Rule: Accept");

      /*
      ** Fill in Match Info Data
      */
      mInfo->iMatched     = TRUE;
      mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgFw.iSectionNr;
      mInfo->iSectType    = ST_FW;
      mInfo->iRuleNr      = iRuleCtr;
      mInfo->cRuleType    = RT_FW_A;
      mInfo->cMatchedRule = TmpList->str;
      mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgFw.cCfgSendTo[_mice_mod_pop_aa_regex_CfgFw.iSectionNr];

      return(TRUE);
    }
  }

  // Illegal
  for(TmpList = _mice_mod_pop_aa_regex_CfgFw.aCfgFwIllegal[_mice_mod_pop_aa_regex_CfgFw.iSectionNr], iRuleCtr = 0; TmpList != NULL; TmpList = TmpList->next, iRuleCtr++)
  {
    if(_mice_mod_pop_aa_regex_DoesMatch(cLogLine, LogLineLen, TmpList->str) == TRUE)
    {
      if(_mice_mod_pop_aa_regex_iDebug)
        log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: Firewall Rule: Illegal");

      /*
      ** Fill in Match Info Data
      */
      mInfo->iMatched     = TRUE;
      mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgFw.iSectionNr;
      mInfo->iSectType    = ST_FW;
      mInfo->iRuleNr      = iRuleCtr;
      mInfo->cRuleType    = RT_FW_I;
      mInfo->cMatchedRule = TmpList->str;
      mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgFw.cCfgSendTo[_mice_mod_pop_aa_regex_CfgFw.iSectionNr];

      return(TRUE);
    }
  }


  /******************************************************************************
  **
  ** D E F A U L T
  **
  ******************************************************************************/

  if(_mice_mod_pop_aa_regex_iDebug)
    log_mesg(WARN, "mice_mod_pop_aa_regex: MATCHED: Nothing found");

  mInfo->iMatched     = FALSE;
  mInfo->iSectNr      = _mice_mod_pop_aa_regex_CfgDefault.iSectionNr;
  mInfo->iSectType    = ST_DEF;
  mInfo->iRuleNr      = -1;
  mInfo->cRuleType    = "0x0000";
  mInfo->cMatchedRule = NULL;
  mInfo->cSendTo      = _mice_mod_pop_aa_regex_CfgDefault.cCfgSendTo[_mice_mod_pop_aa_regex_CfgDefault.iSectionNr];

  return(FALSE);
}


/*
** Match a Line
**
** Return: FALSE, TRUE
*/
int _mice_mod_pop_aa_regex_DoesMatch(char *cLogLine, size_t LogLineLen, char *cRule)
{
  if(strlen(cRule) <= 0)  // empty rule
    return(FALSE);

  if(re_compile_pattern(cRule, strlen(cRule), _mice_mod_pop_aa_regex_RegExBuf) != 0 )
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: Error while compiling Regular Expression '%s'. Skipped...\n", cRule);
    return(FALSE);
  }

  _mice_mod_pop_aa_regex_RegExBuf->regs_allocated = REGS_FIXED;

  if(re_match(_mice_mod_pop_aa_regex_RegExBuf, cLogLine, LogLineLen, 0, NULL) >= 0)
    return(TRUE);
  else
    return(FALSE);
}


/*
** To which Host should we send our Data
*/
int _mice_mod_pop_aa_regex_WhichHost(char cSendTo)
{
  char *cPtr;


/*
  if(cSendTo == NULL || strlen(cSendTo) != 1)
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: Error in _mice_mod_pop_aa_regex_SendTo Argument\n");
    return(-1);
  }
*/

  if(cSendTo == 'N')
    return(HI_NONE);
  if(cSendTo == 'M')
    return(HI_MNGMNT);
  if(cSendTo == 'A')
    return(HI_AGENT);
  if(cSendTo == 'B')
    return(HI_BOTH);

  log_mesg(WARN, "mice_mod_pop_aa_regex: Unknown SendTo Argument: %c\n", cSendTo);
  return(-2);
}



/*
** Action depending on matched Line
*/
int _mice_mod_pop_aa_regex_Action(LogFormat LogFmt, MatchInfo mInfo)
{
  int     iResult = 0;
  u_int   uiHostInfo = 0;


  if( (uiHostInfo = _mice_mod_pop_aa_regex_WhichHost(mInfo.cSendTo[0])) < 0)
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: _mice_mod_pop_aa_regex_Action: Error while parsing SendTo Argument\n");
    return(-1);
  }

  if(_mice_mod_pop_aa_regex_iDebug)
    log_mesg(WARN, "mice_mod_pop_aa_regex: checked SendTo (%s) argument = 0x%06x", mInfo.cSendTo, uiHostInfo);


  /*
  ** Send it to the Management Host
  */
  if( (uiHostInfo & HI_MNGMNT) == HI_MNGMNT )
  {
    xmlNodePtr  MsgIDMEF;
    xmlChar     *MsgIDMEFChar; // get string for "doc" from libxml
    size_t      MsgIDMEFLen;


    if(_mice_mod_pop_aa_regex_iDebug)
      log_mesg(WARN, "mice_mod_pop_aa_regex: send to Management Host");


    /*
    ** IDMEF Format
    */
    if(_mice_mod_pop_aa_regex_iDebug)
      log_mesg(WARN, "mice_mod_pop_aa_regex: create IDMEF message");

    if( (MsgIDMEF = _mice_mod_pop_aa_regex_FormatIDMEF(LogFmt, mInfo)) == NULL)
    {
      log_mesg(WARN, "mice_mod_pop_aa_regex: _mice_mod_pop_aa_regex_Action: Error while constructing IDMEF Format\n");
      return(-2);
    }



    /*
    ** Send Away
    */
    xmlDocDumpMemory(doc, &MsgIDMEFChar, &MsgIDMEFLen);

    if(MsgIDMEFLen > MAX_IDMEFMSGSIZE)
    {
      log_mesg(WARN, "mice_mod_pop_aa_regex: WARNING: Current IDMEF Message Length (%u) exceeds Maximum IDMEF Message Length (%u). Message will be DROPPED!", MsgIDMEFLen, MAX_IDMEFMSGSIZE);
      return(-666);
    }

    if(_mice_mod_pop_aa_regex_iDebug)
      log_mesg(WARN, "mice_mod_pop_aa_regex: send it away (len = %u)...", MsgIDMEFLen);
    iResult = _mice_mod_pop_aa_regex_SendTo(_mice_mod_pop_aa_regex_cMngmntAddr, _mice_mod_pop_aa_regex_cMngmntPort, (char *)MsgIDMEFChar, MsgIDMEFLen, _mice_mod_pop_aa_regex_StaticInfo.cKey_MH);
    if(_mice_mod_pop_aa_regex_iDebug)
      log_mesg(WARN, "mice_mod_pop_aa_regex: resetCurrentDoc");
    resetCurrentDoc();
    //xmlFreeNode(MsgIDMEF);
    xmlFree(MsgIDMEFChar);
    //clearCurrentDoc();
  }



  /*
  ** Send it to another Agent // XXX NOT SUPPORTED
  */
  if( (uiHostInfo & HI_AGENT) == HI_AGENT )
  {

    if(_mice_mod_pop_aa_regex_iDebug)
      log_mesg(WARN, "mice_mod_pop_aa_regex: send to another Agent");

    /*
    ** XXX
    ** Sollten wir hier auch das IDMEF benutzen, sodass weiter oben in unserer
    ** Hierachie liegende Analyse-Agenten auf die Analyseergebnisse ihrer Vorgaenger
    ** zugreifen koennen und anschliessend ihre eigenen Erbenisse dem IDMEF Strukturen
    ** hinzufuegen? Waere irgendwie sinnvoller. Oder vll. als Konfigurationoption
    ** anbieten?
    */

    /*
    ** Send Away
    ** XXX!!!: LogFmt senden nicht die LogLine!!!!
    */
    iResult = _mice_mod_pop_aa_regex_SendTo(_mice_mod_pop_aa_regex_cAgentAddr, _mice_mod_pop_aa_regex_cAgentPort, LogFmt.cLogdata, strlen(LogFmt.cLogdata), _mice_mod_pop_aa_regex_StaticInfo.cKey_AA);
  }


  return(iResult);
}



/*
** Convert raw log data to Intrusion Detection Message Exchange Format (IDMEF)
** This is the main Function for handling the IDMEF Lib.
*/
xmlNodePtr _mice_mod_pop_aa_regex_FormatIDMEF(LogFormat LogFmt, MatchInfo mInfo)
{


  //if(LogFmt == NULL || mInfo == NULL)
    //return(NULL);


  /*
  ** Let's look what kind of message we have to convert to IDMEF
  ** to call the right Subroutine.
  ** NOT NEEDED for our code. :-)
  *
  switch(mInfo.iSectType)
  {
      case ST_AUTH:
        return(BuildAuthMsg(cMsgIdmefData, MsgIdmefLen, LogFmt, mInfo));

      case ST_ROOT:
        return(BuildRootMsg(cMsgIdmefData, MsgIdmefLen, LogFmt, mInfo));

      case ST_READ:
        return(BuildReadMsg(cMsgIdmefData, MsgIdmefLen, LogFmt, mInfo));

      case ST_WRITE:
        return(BuildWriteMsg(cMsgIdmefData, MsgIdmefLen, LogFmt, mInfo));

      case ST_MONI:
        return(BuildMoniMsg(cMsgIdmefData, MsgIdmefLen, LogFmt, mInfo));

      case ST_APPS:
        return(BuildAppsMsg(cMsgIdmefData, MsgIdmefLen, LogFmt, mInfo));

      case ST_DEF:
        return(BuildDefMsg(cMsgIdmefData, MsgIdmefLen, LogFmt, mInfo));
  }

  return(-666);
  */

  return(_mice_mod_pop_aa_regex_BuildMsg(LogFmt, mInfo));
}


xmlNodePtr _mice_mod_pop_aa_regex_BuildMsg(LogFormat LogFmt, MatchInfo mInfo)
{
  xmlNodePtr MsgIDMEF;


  /*
  ** Build the IDMEF message
  */
  MsgIDMEF = _mice_mod_pop_aa_regex_BuildMsgTree(LogFmt, mInfo);


  //if(MsgIDMEF != NULL && _mice_mod_pop_aa_regex_iDebug)
    //validateCurrentDoc();


  /*
  ** Increment Alert ID
  */
  _mice_mod_pop_aa_regex_StaticInfo.ulAlertID++;

  return(MsgIDMEF);
}


xmlNodePtr _mice_mod_pop_aa_regex_BuildMsgTree(LogFormat LogFmt, MatchInfo mInfo)
{
  xmlNodePtr  MessageClass,
              AnalyzerClass,
              CreateTimeClass,
              DetectTimeClass,
              AnalyzerTimeClass,
              SourceClass,
              TargetClass,
              ClassificClass,
              AddDataClass;



  //if(mInfo == NULL)
    //return(NULL);


  /*
  ** Initialize the XML doc
  */
  if(!createCurrentDoc(XML_DEFAULT_VERSION))
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: createCurrentDoc returned 0\n");
    return(NULL);
  }


  /*
  ** Start constructing the IDMEF XML message
  */
  if(_mice_mod_pop_aa_regex_iDebug)
    log_mesg(WARN, "mice_mod_pop_aa_regex: building Analyzer Class");

  if((AnalyzerClass = _mice_mod_pop_aa_regex_BuildAnalyzer(LogFmt)) == NULL)
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: Problem building Analyzer node\n");
    return(NULL);
  }


  if(_mice_mod_pop_aa_regex_iDebug)
    log_mesg(WARN, "mice_mod_pop_aa_regex: building Source Class");

  if((SourceClass = _mice_mod_pop_aa_regex_BuildSource(LogFmt)) == NULL)
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: Problem building Source node\n");
    return(NULL);
  }


  if(_mice_mod_pop_aa_regex_iDebug)
    log_mesg(WARN, "mice_mod_pop_aa_regex: building Target Class");

  if((TargetClass = _mice_mod_pop_aa_regex_BuildTarget(LogFmt)) == NULL)
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: Problem building Target node\n");
    return(NULL);
  }


  /*
  ** Build full IDMEF Message
  */
  if(_mice_mod_pop_aa_regex_iDebug)
    log_mesg(WARN, "mice_mod_pop_aa_regex: building Message Class");

  MessageClass  = newIDMEF_Message
                  (
                    newAttribute("version",IDMEF_MESSAGE_VERSION),
                    newAlert
                    (
                      newSimpleElement("ident", intToString(_mice_mod_pop_aa_regex_StaticInfo.ulAlertID)),
                      AnalyzerClass,
                      newCreateTime(NULL),                /* Time values set here */
                      newDetectTime(NULL),
                      newAnalyzerTime(NULL),
                      SourceClass,
                      TargetClass,
                      newClassification
                      (
                        newAttribute("origin", "vendor-specific"),
                        newSimpleElement("name", mInfo.cRuleType),
                        newSimpleElement("url", "http://unkonwn.de"),
                        NULL
                      ),
                      newAdditionalData
                      (
                        newAttribute("meaning","Logline"),
                        newAttribute("type","string"),
                        newSimpleElement("value", LogFmt.cLogdata),    // XXX: or better raw data? have we everything encoded in IDMEF?
                        NULL
                      ),
                      NULL
                    ),
                    NULL
                  );


  return(MessageClass);
}


xmlNodePtr _mice_mod_pop_aa_regex_BuildAnalyzer(LogFormat LogFmt)
{
  xmlNodePtr  AnalyzerClass,
              NodeClass,
              AddressClass,
              ProcessClass;


  AnalyzerClass = newAnalyzer
                  (
                    newSimpleElement("analyzerid",_mice_mod_pop_aa_regex_StaticInfo.cAnalyzerID),
                    newSimpleElement("manufacturer",_mice_mod_pop_aa_regex_StaticInfo.cManufactur),
                    newSimpleElement("model",_mice_mod_pop_aa_regex_StaticInfo.cModel),
                    newSimpleElement("version",_mice_mod_pop_aa_regex_StaticInfo.cVersion),
                    newSimpleElement("class",_mice_mod_pop_aa_regex_StaticInfo.cClass),
                    newSimpleElement("ostype",_mice_mod_pop_aa_regex_StaticInfo.cOSType),
                    newSimpleElement("osversion",_mice_mod_pop_aa_regex_StaticInfo.cOSVersion),
                    NULL
                  );

  NodeClass     = newNode(NULL);
  AddressClass  = newAddress(NULL);
  ProcessClass  = newProcess(NULL);


  // Node Class
  setAttribute(NodeClass, newAttribute("category", "dns"));
  addElement(NodeClass, newSimpleElement("name", _mice_mod_pop_aa_regex_StaticInfo.cNodeName));

  // Address Class
  setAttribute(AddressClass, newAttribute("category", "ipv4-addr"));
  addElement(AddressClass, newSimpleElement("address", _mice_mod_pop_aa_regex_StaticInfo.cAddress));

  // Process Class
  addElement(ProcessClass, newSimpleElement("name", _mice_mod_pop_aa_regex_StaticInfo.cProcName));
  // XXX adding the PID causes a SEGV in parse_process() in idmefxml_parse.c
  //addElement(ProcessClass, newSimpleElement("pid", _mice_mod_pop_aa_regex_StaticInfo.cPID));


  // Put things together
  if(AddressClass->children != NULL)  // did we add a sub element to Address?
    addElement(NodeClass, AddressClass);
  else
    xmlFreeNode(AddressClass);

  if(NodeClass->children != NULL)     // did we add a sub element to Node?
    addElement(AnalyzerClass, NodeClass);
  else
    xmlFreeNode(NodeClass);

  if(ProcessClass->children != NULL)     // did we add a sub element to Process?
    addElement(AnalyzerClass, ProcessClass);
  else
    xmlFreeNode(ProcessClass);


  return(AnalyzerClass);
}


xmlNodePtr _mice_mod_pop_aa_regex_BuildSource(LogFormat LogFmt)
{
  xmlNodePtr  SourceClass,
              AddressClass,
              NodeClass,
              UserClass,
              UserIdClass,
              ProcessClass,
              ServiceClass;


  SourceClass   = newSource(NULL);
  NodeClass     = newNode(NULL);
  UserClass     = newUser(NULL);
  UserIdClass   = newUserId(NULL);
  ProcessClass  = newProcess(NULL);
  ServiceClass  = newService(NULL);


  /*
  ** Create Address Class
  */
  AddressClass  = newAddress
                  (
                    newSimpleElement("category", "ipv4-addr"),
                    newSimpleElement("address", LogFmt.cIP),
                    NULL
                  );


  /*
  ** Since the order in which we add things matters, we add the Address last.
  ** And in this case it's also the only class we add.
  */
  addElement(NodeClass, AddressClass);


  /*
  ** And now we add the Node Class to the Source Class
  */
  addElement(SourceClass, NodeClass);


  /*
  ** User Class
  */
  addElement(UserIdClass, newSimpleElement("name", "UNKNOWN"));
  //addElement(UserIdClass, newSimpleElement("number", "UNKNOWN"));
  addElement(UserClass, UserIdClass);
  addElement(SourceClass, UserClass);

  /*
  ** Process Class
  */
  addElement(ProcessClass, newSimpleElement("name", "UNKNOWN"));
  //addElement(ProcessClass, newSimpleElement("pid", "0"));
  //addElement(ProcessClass, newSimpleElement("path", "UNKNOWN"));
  //addElement(ProcessClass, newSimpleElement("arg", "UNKNOWN"));
  //addElement(ProcessClass, newSimpleElement("env", "UNKNOWN"));
  addElement(SourceClass, ProcessClass);

  /*
  ** Service Class
  */
  addElement(ServiceClass, newSimpleElement("name", "UNKNOWN"));
  //addElement(ServiceClass, newSimpleElement("port", "0"));
  //addElement(ServiceClass, newSimpleElement("portlist", "0"));
  //addElement(ServiceClass, newSimpleElement("protocol", "UNKNOWN"));
  addElement(SourceClass, ServiceClass);


  return(SourceClass);
}


xmlNodePtr _mice_mod_pop_aa_regex_BuildTarget(LogFormat LogFmt)
{
  xmlNodePtr  TargetClass,
              AddressClass,
              NodeClass,
              UserClass,
              UserIdClass,
              ProcessClass,
              ServiceClass,
              FilelistClass,
              FileClass;


  TargetClass   = newTarget(NULL);
  NodeClass     = newNode(NULL);
  UserClass     = newUser(NULL);
  UserIdClass   = newUserId(NULL);
  ProcessClass  = newProcess(NULL);
  ServiceClass  = newService(NULL);
  FilelistClass = newFileList(NULL);
  FileClass     = newFile(NULL);


  /*
  ** Create Address Class
  */
  AddressClass  = newAddress
                  (
                    newSimpleElement("category", "ipv4-addr"),
                    newSimpleElement("address", LogFmt.cIP),
                    NULL
                  );


  /*
  ** Since the order in which we add things matters, we add the Address last.
  ** And in this case it's also the only class we add.
  */
  addElement(NodeClass, AddressClass);


  /*
  ** And now we add the Node Class to the Source Class
  */
  addElement(TargetClass, NodeClass);


  /*
  ** User Class
  */
  addElement(UserIdClass, newSimpleElement("name", "UNKNOWN"));
  //addElement(UserIdClass, newSimpleElement("number", "UNKNOWN"));
  addElement(UserClass, UserIdClass);
  addElement(TargetClass, UserClass);

  /*
  ** Process Class
  */
  addElement(ProcessClass, newSimpleElement("name", "UNKNOWN"));
  //addElement(ProcessClass, newSimpleElement("pid", "0"));
  //addElement(ProcessClass, newSimpleElement("path", "UNKNOWN"));
  //addElement(ProcessClass, newSimpleElement("arg", "UNKNOWN"));
  //addElement(ProcessClass, newSimpleElement("env", "UNKNOWN"));
  addElement(TargetClass, ProcessClass);

  /*
  ** Service Class
  */
  addElement(ServiceClass, newSimpleElement("name", "UNKNOWN"));
  //addElement(ServiceClass, newSimpleElement("port", "0"));
  //addElement(ServiceClass, newSimpleElement("portlist", "0"));
  //addElement(ServiceClass, newSimpleElement("protocol", "UNKNOWN"));
  addElement(TargetClass, ServiceClass);

  /*
  ** FileList Class
  */
  //addElement(FileClass, newSimpleElement("name", "UNKNOWN"));
  //addElement(FilelistClass, FileClass);
  //addElement(TargetClass, FilelistClass);


  return(TargetClass);
}


/*
** Send it to another Agent
*/
int _mice_mod_pop_aa_regex_SendTo(char *cAddress, char *cPort, char *cData, size_t DataLen, char *cKey)
{
  int             iSock,
                  iCnt;

  size_t          KeySize = 16,
                  DataStrLen;

  CipherIdmefMsg  Message;

  IdmefMsgFormat  *MsgPtr;



  if(_mice_mod_pop_aa_regex_iDebug)
    log_mesg(WARN, "mice_mod_pop_aa_regex: entering _mice_mod_pop_aa_regex_SendTo: Address: %s, Port = %s, Data = %s, Datalen = %u, Key = %s", cAddress, cPort, cData, DataLen, cKey);


  DataStrLen = strlen(cData);

  if(DataLen < 1 || cData == NULL)
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: No Data! (%d)", DataLen);
    return(-99);
  }
  if(DataLen > MAX_IDMEFMSGSIZE)
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: Generated IDMEF Message is bigger then allowed (%d > %d)", DataLen, MAX_IDMEFMSGSIZE);
    return(-100);
  }
  if(DataStrLen != DataLen)
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: Generated IDMEF Message is unequal to DataLen (%d != %d)", strlen(cData), DataLen);
    return(-101);
  }
  if(DataStrLen == 0)
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: Generated IDMEF Message has zero length");
    return(-102);
  }


  /*
  ** Let's calc the check sum and store everything in the right slot
  */
  memset(&Message, 0, sizeof(Message));
  Message.CipherTextLen = sizeof(IdmefMsgFormat);
  MsgPtr = ((IdmefMsgFormat *) Message.cCipherText);
  memcpy((char *) MsgPtr->cIdmefMsg, cData, DataLen);
  MsgPtr->sChkSum = 0;
  MsgPtr->sChkSum = in_chksum((u_short *) Message.cCipherText, Message.CipherTextLen);

  if(_mice_mod_pop_aa_regex_iDebug)
    log_mesg(WARN, "mice_mod_pop_aa_regex: Checksum = %d", MsgPtr->sChkSum);


  /*
  ** Init the Crypto Stuff
  */
  if(_mice_mod_pop_aa_regex_StaticInfo.iEnc == TRUE && cKey != NULL && strlen(cKey) > 0)
  {
    if(_mice_mod_pop_aa_regex_iDebug)
      log_mesg(WARN, "mice_mod_pop_aa_regex: start encrypting our message");

    // Check DataLen
    if(DataLen > sizeof(Message.cCipherText)-1)
    {
      log_mesg(WARN, "mice_mod_pop_aa_regex: Error DataLen to big! Please split it up.\n");
      return(-1);
    }

    // IV
    if(_mice_mod_pop_aa_regex_iDebug)
      log_mesg(WARN, "mice_mod_pop_aa_regex: alloc memory for IV");

    Message.IVLen = mcrypt_enc_get_iv_size(_mice_mod_pop_aa_regex_CryptModule);

    if(Message.IVLen != sizeof(Message.IV))
    {
      log_mesg(WARN, "mice_mod_pop_aa_regex: IV Length is not equal to 16! Please check if 'Twofish' Crypto Algo. is enabled.");
      return(-2);
    }

    // Put random Data in IV.
    if(_mice_mod_pop_aa_regex_iDebug)
      log_mesg(WARN, "mice_mod_pop_aa_regex: fill IV with random data");

    memset(Message.IV, 0, Message.IVLen);
    srand(time(0));
    for(iCnt = 0; iCnt < Message.IVLen; iCnt++)
      Message.IV[iCnt] = rand();


    // Init the Module
    if(_mice_mod_pop_aa_regex_iDebug)
      log_mesg(WARN, "mice_mod_pop_aa_regex: init crypt module (Key = %s)", cKey);

    if(mcrypt_generic_init(_mice_mod_pop_aa_regex_CryptModule, cKey, KeySize, Message.IV) < 0)
    {
      log_mesg(WARN, "mice_mod_pop_aa_regex: Error while initializing Crypto Module\n");
      return(-3);
    }

    /* Test Module
    if(mcrypt_enc_self_test(_mice_mod_pop_aa_regex_CryptModule))
    {
      log_mesg(WARN, "mice_mod_pop_aa_regex: Error occured while doing Selftest on Crypto Module\n");
      return(-4);
    }
    */

    /*
    ** Encrypt Data
    ** We don't need a 100% unbreakable Ciphertext, because the Information we try to
    ** protect isn't very valueable. Encryption is just used to hide Data from the
    ** Eyes of the Attacker, so s/he doesn't know what's been logged in Realtime.
    ** XXX but what's about inserting information to confuse the detection engine?
    ** XXX and what about copy-and-paste attacks?
    */
    for(iCnt = 0; iCnt < Message.CipherTextLen; iCnt++)
      mcrypt_generic(_mice_mod_pop_aa_regex_CryptModule, &Message.cCipherText[iCnt], 1);

    if(mcrypt_generic_deinit(_mice_mod_pop_aa_regex_CryptModule) < 0)
    {
      log_mesg(WARN, "mice_mod_pop_aa_regex: Error while clearing Crypto Module\n");
      return(-5);
    }



    /*
    ** Decrypt it for testing
    *
    if(_mice_mod_pop_aa_regex_iDebug)
      log_mesg(WARN, "mice_mod_pop_aa_regex: Debug: Decrypt Data");
    for(iCnt = 0; iCnt < Message.CipherTextLen; iCnt++)
      mdecrypt_generic(_mice_mod_pop_aa_regex_CryptModule, &Message.cCipherText[iCnt], 1);
    if(_mice_mod_pop_aa_regex_iDebug > 1)
      log_mesg(WARN,  "mice_mod_pop_aa_regex: Decrypt-Test: %s", MsgPtr->cIdmefMsg);
    */

  }
  else  // NO encryption
  {
    if(_mice_mod_pop_aa_regex_iDebug)
      log_mesg(WARN, "mice_mod_pop_aa_regex: DONT encrypt our message");

    Message.IVLen = 0;
  }



  /*
  ** Send away!
  ** Should we open it once every time? XXX
  */
  if(_mice_mod_pop_aa_regex_iDebug)
    log_mesg(WARN, "mice_mod_pop_aa_regex: open TCP connection to %s:%s", cAddress, cPort);

  if( (iSock = tcp_open(cAddress, NULL, atoi(cPort))) < 0 )
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: Error while opening Socket to Remote Host.\n");
    return(-9);
  }


  if(_mice_mod_pop_aa_regex_iDebug)
    log_mesg(WARN, "mice_mod_pop_aa_regex: send data over TCP connection");

  if(writen(iSock, (char *) &Message, sizeof(Message)) < 0)
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: Error while sending Data to Remote Host. Try to reopen Connection...\n");
    close(iSock);
    if((iSock = tcp_open(cAddress, NULL, atoi(cPort))) < 0)
    {
      log_mesg(WARN, "mice_mod_pop_aa_regex: Error while opening Socket to Remote Host.\n");
      return(-10);
    }
    if(writen(iSock, (char *) &Message, sizeof(Message)) < 0)
    {
      log_mesg(WARN, "mice_mod_pop_aa_regex: Error while sending Data to Remote Host. Abort!\n");
      close(iSock);
      return(-11);
    }
  }

  close(iSock);

  // XXX use mcrypt_module_close() to enhance speed and do init just once
/*  if(_mice_mod_pop_aa_regex_StaticInfo.iEnc == TRUE && cKey != NULL && strlen(cKey) > 0)
  {
    free(cKey);
    //mcrypt_generic_end(_mice_mod_pop_aa_regex_CryptModule);
    mcrypt_module_close(_mice_mod_pop_aa_regex_CryptModule);
  }

*/
  return(0);
}


/*
** Read Config File and set global Var.s
*/
int _mice_mod_pop_aa_regex_HandleConfFile(char *cConfFile)
{
  int              iCfgCount;
  int              iCnt;
  struct stat      StatBuf;


  _mice_mod_pop_aa_regex_CfgHostInfo.iSectionNr  = -1;
  _mice_mod_pop_aa_regex_CfgIdmefInfo.iSectionNr = -1;
  _mice_mod_pop_aa_regex_CfgAuth.iSectionNr      = -1;
  _mice_mod_pop_aa_regex_CfgRoot.iSectionNr      = -1;
  _mice_mod_pop_aa_regex_CfgRead.iSectionNr      = -1;
  _mice_mod_pop_aa_regex_CfgWrite.iSectionNr     = -1;
  _mice_mod_pop_aa_regex_CfgMon.iSectionNr       = -1;
  _mice_mod_pop_aa_regex_CfgApps.iSectionNr      = -1;
  _mice_mod_pop_aa_regex_CfgExpl.iSectionNr      = -1;
  _mice_mod_pop_aa_regex_CfgFw.iSectionNr        = -1;
  _mice_mod_pop_aa_regex_CfgDefault.iSectionNr   = -1;


  if(lstat(cConfFile, &StatBuf) < 0)
  {
    log_mesg(WARN_SYS, "mice_mod_pop_aa_regex: Error while trying lstat(%s) | Syserror", cConfFile);
    return(-1);
  }

  if((iCfgCount = cfgParse(cConfFile, _mice_mod_pop_aa_regex_CfgIni, CFG_INI)) < 0)
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: Error while parsing Config File %s\n", cConfFile);
    return(-2);
  }

  if(iCfgCount != SECT_MAXSECT)
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: Error while parsing Config File %s | Sections Read: %d | Sections Expect: %d", cConfFile, iCfgCount, SECT_MAXSECT);
    return(-3);
  }

  for(iCnt = 0; iCnt < iCfgCount; iCnt++)
  {
    if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_HOST))
      _mice_mod_pop_aa_regex_CfgHostInfo.iSectionNr  = iCnt;

    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_IDMEF))
      _mice_mod_pop_aa_regex_CfgIdmefInfo.iSectionNr = iCnt;

    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_AUTH))
      _mice_mod_pop_aa_regex_CfgAuth.iSectionNr      = iCnt;

    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_ROOT))
      _mice_mod_pop_aa_regex_CfgRoot.iSectionNr      = iCnt;

    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_READ))
      _mice_mod_pop_aa_regex_CfgRead.iSectionNr      = iCnt;

    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_WRITE))
      _mice_mod_pop_aa_regex_CfgWrite.iSectionNr     = iCnt;

    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_MONI))
      _mice_mod_pop_aa_regex_CfgMon.iSectionNr       = iCnt;

    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_APPS))
      _mice_mod_pop_aa_regex_CfgApps.iSectionNr      = iCnt;

    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_EXPL))
      _mice_mod_pop_aa_regex_CfgExpl.iSectionNr      = iCnt;

    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_FW))
      _mice_mod_pop_aa_regex_CfgFw.iSectionNr   = iCnt;

    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_DEF))
      _mice_mod_pop_aa_regex_CfgDefault.iSectionNr   = iCnt;

    else
    {
      log_mesg(WARN, "mice_mod_pop_aa_regex: Error in Config File %s | Unknown Section: %s", cConfFile, cfgSectionNumberToName(iCnt));
      return(-4);
    }
  }

  if( _mice_mod_pop_aa_regex_CfgHostInfo.iSectionNr   == -1 || _mice_mod_pop_aa_regex_CfgIdmefInfo.iSectionNr == -1  || _mice_mod_pop_aa_regex_CfgAuth.iSectionNr   == -1
      || _mice_mod_pop_aa_regex_CfgRoot.iSectionNr    == -1 || _mice_mod_pop_aa_regex_CfgRead.iSectionNr      == -1  || _mice_mod_pop_aa_regex_CfgWrite.iSectionNr  == -1
      || _mice_mod_pop_aa_regex_CfgMon.iSectionNr     == -1 || _mice_mod_pop_aa_regex_CfgApps.iSectionNr      == -1  || _mice_mod_pop_aa_regex_CfgExpl.iSectionNr   == -1
      || _mice_mod_pop_aa_regex_CfgFw.iSectionNr      == -1 || _mice_mod_pop_aa_regex_CfgDefault.iSectionNr   == -1
    )
  {
    log_mesg(WARN, "mice_mod_pop_aa_regex: Error in Config File %s, Section is missing!\n", cConfFile);
    return(-5);
  }

  return(0);
}

