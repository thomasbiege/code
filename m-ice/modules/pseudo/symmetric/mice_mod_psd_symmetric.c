/***************************************************************************
                          mice_mod_psd_symmetric.c  -  description
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

#include "mice_mod_psd_symmetric.h"



/*
** Configure Stuff
*/
char        **_mice_mod_psd_symmetric_CfgKey;
int         *_mice_mod_psd_symmetric_CfgUser;
int         *_mice_mod_psd_symmetric_CfgGroup;

int         _mice_mod_psd_symmetric_iSectKeys;
int         _mice_mod_psd_symmetric_iSectAccounting;

static char   *PsdKey, *decodedPsdKey;
static size_t decodedPsdKeyLen;
static uid_t  UserID;
static gid_t  GroupID;
#define       UPPRERLIMIT 65532

cfgStruct   _mice_mod_psd_symmetric_CfgIni[] =
{
  {"KEY"      ,CFG_STRING       ,&_mice_mod_psd_symmetric_CfgKey },
  {"USER"     ,CFG_INT          ,&_mice_mod_psd_symmetric_CfgUser  },
  {"GROUP"    ,CFG_INT          ,&_mice_mod_psd_symmetric_CfgGroup },  
  {NULL       ,CFG_END          ,NULL                              }
};


/*
** Function Declaration
*/
int _mice_mod_psd_symmetric_HandleConfFile(char *cConfFile);


/*
** Module Functions
*/
int mice_mod_psd_symmetric_LTX_init(char *cConfFile)
{
 
  log_open("mice_mod_psd_symmetric", LOG_PID, LOG_USER);

  
  _mice_mod_psd_symmetric_HandleConfFile(cConfFile);

  
  /* XXX: create hash table with accounts and pseudonyms */

  
  /* make some often used values easier accessible */
  PsdKey  = _mice_mod_psd_symmetric_CfgKey[_mice_mod_psd_symmetric_iSectKeys];
  if(PsdKey == NULL)
  {
    log_mesg(WARN, "Error: invalid ASCII pseudonymisation key\n");
    return(-1);
  }
  UserID  = (uid_t) _mice_mod_psd_symmetric_CfgUser[_mice_mod_psd_symmetric_iSectAccounting];
  GroupID = (gid_t) _mice_mod_psd_symmetric_CfgGroup[_mice_mod_psd_symmetric_iSectAccounting];


  /* set pseudo- key before init */
  if((decodedPsdKey = psd_set_key(PsdKey, &decodedPsdKeyLen)) == NULL)
  {
    log_mesg(WARN, "Error: psd_set_key(%s)\n", PsdKey);
    return(-2);
  }
     
  /* init. pseudonymisation framework */
  if(psd_init() < 0)
  {
    log_mesg(WARN, "Error: psd_init()\n");
    return(-3);
  }

  return(0);
}

int mice_mod_psd_symmetric_LTX_func(LogFormat *LogFmt, u_int uiFileType)
{
  char  *pseudonym;
  char  *identifier;
  long  pseudonym_num;
  long  identifier_num;

  
  if(LogFmt == NULL)
    return(-1);

    
  /* start looking through LogFormat structure for identifying artefacts */
  switch(LogFmt->uiFileType)
  {
    /*
    ** SCSLOG DATA
    */
    case FTF_SCSLOG:
      /*
      ** first check the uid limit
      ** we just pseudonymize human user accounts
      */
      if(LogFmt->logtype.scslog.UID < UserID)
      {
        LogFmt->uiPseudonymized = FALSE;
        break;
      }
      LogFmt->uiPseudonymized = TRUE;
      
      /*
      ** programname
      */
      if( (identifier = LogFmt->logtype.scslog.cProgram) != NULL)
      {
        if( (pseudonym = psd_deidentify(identifier)) == NULL)
        {
          log_mesg(WARN, "Error:  psd_deidentify(identifier = %s)\n", identifier);
          return(-100);
        }
        if(strlen(pseudonym) >= sizeof(identifier))
        {
          log_mesg(WARN, "Error:  pseudonym (%s -> %s) too large\n", identifier, pseudonym);
          free(pseudonym);
          return(-101);
        }
        /* replace identifier with pseudonym */
        memcpy(identifier, pseudonym, sizeof(identifier)-1);
      }
      /*
      ** process ID
      */
      identifier_num = (long) LogFmt->logtype.scslog.PID;
      pseudonym_num = psd_deidentify_num(identifier_num, decodedPsdKey, decodedPsdKeyLen);

      if(pseudonym_num > (2^(sizeof(LogFmt->logtype.scslog.PID)*8)))
      {
        log_mesg(WARN, "Error:  pseudonym_num (%ld -> %ld) too large\n", identifier_num, pseudonym_num);
        return(-103);
      }
      /* replace identifier with pseudonym */
      LogFmt->logtype.scslog.PID = pseudonym_num;
      
      /*
      ** user ID
      */
      identifier_num = (long) LogFmt->logtype.scslog.UID;
      pseudonym_num = psd_deidentify_num(identifier_num, decodedPsdKey, decodedPsdKeyLen);

      if(pseudonym_num > (2^(sizeof(LogFmt->logtype.scslog.UID)*8)))
      {
        log_mesg(WARN, "Error:  pseudonym_num (%ld -> %ld) too large\n", identifier_num, pseudonym_num);
        return(-105);
      }
      /* replace identifier with pseudonym */
      LogFmt->logtype.scslog.UID = pseudonym_num;

      /*
      ** effective user ID
      */
      identifier_num = (long) LogFmt->logtype.scslog.EUID;
      pseudonym_num = psd_deidentify_num(identifier_num, decodedPsdKey, decodedPsdKeyLen);

      if(pseudonym_num > (2^(sizeof(LogFmt->logtype.scslog.EUID)*8)))
      {
        log_mesg(WARN, "Error:  pseudonym_num (%ld -> %ld) too large\n", identifier_num, pseudonym_num);
        return(-107);
      }
      /* replace identifier with pseudonym */
      LogFmt->logtype.scslog.EUID = pseudonym_num;

      break;

    /*
    ** FIREWALL LOGS
    */
    case FTF_FIREWALL:
      LogFmt->uiPseudonymized = TRUE;
      
      /*
      ** MAC address
      */
      if( (identifier = LogFmt->logtype.firewall.cMAC) != NULL)
      {
        if( (pseudonym = psd_deidentify(identifier)) == NULL)
        {
          log_mesg(WARN, "Error:  psd_deidentify(identifier = %s)\n", identifier);
          return(-200);
        }
        if(strlen(pseudonym) >= sizeof(identifier))
        {
          log_mesg(WARN, "Error:  pseudonym (%s -> %s) too large\n", identifier, pseudonym);
          free(pseudonym);
          return(-201);
        }
        /* replace identifier with pseudonym */
        memcpy(identifier, pseudonym, sizeof(identifier)-1);
      }
      /*
      ** Source IP address
      */
      if( (identifier = LogFmt->logtype.firewall.cSource) != NULL)
      {
        if( (pseudonym = psd_deidentify(identifier)) == NULL)
        {
          log_mesg(WARN, "Error:  psd_deidentify(identifier = %s)\n", identifier);
          return(-202);
        }
        if(strlen(pseudonym) >= sizeof(identifier))
        {
          log_mesg(WARN, "Error:  pseudonym (%s -> %s) too large\n", identifier, pseudonym);
          free(pseudonym);
          return(-203);
        }
        /* replace identifier with pseudonym */
        memcpy(identifier, pseudonym, sizeof(identifier)-1);
      }
      /*
      ** destination IP address
      */
      if( (identifier = LogFmt->logtype.firewall.cDestination) != NULL)
      {
        if( (pseudonym = psd_deidentify(identifier)) == NULL)
        {
          log_mesg(WARN, "Error:  psd_deidentify(identifier = %s)\n", identifier);
          return(-204);
        }
        if(strlen(pseudonym) >= sizeof(identifier))
        {
          log_mesg(WARN, "Error:  pseudonym (%s -> %s) too large\n", identifier, pseudonym);
          free(pseudonym);
          return(-205);
        }
        /* replace identifier with pseudonym */
        memcpy(identifier, pseudonym, sizeof(identifier)-1);
      }

      break;

#ifdef HAVE_LIBLAUSSRV
    /*
    ** LAUS DATA
    */
    case FTF_LAUS:
      /*
      ** first check the uid/gid limit
      ** we just pseudonymize human user accounts
      */
      if(LogFmt->logtype.laus.msg.msg_rgid < GroupID &&
         LogFmt->logtype.laus.msg.msg_ruid < UserID)
      {
        LogFmt->uiPseudonymized = FALSE;
        break;
      }
      LogFmt->uiPseudonymized = TRUE;

      /*
      ** IDs in aud_message header
      */
      identifier_num = (long) LogFmt->logtype.laus.msg.msg_audit_id;
      pseudonym_num = psd_deidentify_num(identifier_num, decodedPsdKey, decodedPsdKeyLen);

      if(pseudonym_num > (2^(sizeof(LogFmt->logtype.laus.msg.msg_audit_id)*8)))
      {
        log_mesg(WARN, "Error:  pseudonym_num (%ld -> %ld) too large\n", identifier_num, pseudonym_num);
        return(-301);
      }
      /* replace identifier with pseudonym */
      LogFmt->logtype.laus.msg.msg_audit_id = pseudonym_num;


      identifier_num = (long) LogFmt->logtype.laus.msg.msg_login_uid;
      pseudonym_num = psd_deidentify_num(identifier_num, decodedPsdKey, decodedPsdKeyLen);

      if(pseudonym_num > (2^(sizeof(LogFmt->logtype.laus.msg.msg_login_uid)*8)))
      {
        log_mesg(WARN, "Error:  pseudonym_num (%ld -> %ld) too large\n", identifier_num, pseudonym_num);
        return(-303);
      }
      /* replace identifier with pseudonym */
      LogFmt->logtype.laus.msg.msg_login_uid = pseudonym_num;


      identifier_num = (long) LogFmt->logtype.laus.msg.msg_euid;
      pseudonym_num = psd_deidentify_num(identifier_num, decodedPsdKey, decodedPsdKeyLen);

      if(pseudonym_num > (2^(sizeof(LogFmt->logtype.laus.msg.msg_euid)*8)))
      {
        log_mesg(WARN, "Error:  pseudonym_num (%ld -> %ld) too large\n", identifier_num, pseudonym_num);
        return(-305);
      }
      /* replace identifier with pseudonym */
      LogFmt->logtype.laus.msg.msg_euid = pseudonym_num;


      identifier_num = (long) LogFmt->logtype.laus.msg.msg_ruid;
      pseudonym_num = psd_deidentify_num(identifier_num, decodedPsdKey, decodedPsdKeyLen);

      if(pseudonym_num > (2^(sizeof(LogFmt->logtype.laus.msg.msg_ruid)*8)))
      {
        log_mesg(WARN, "Error:  pseudonym_num (%ld -> %ld) too large\n", identifier_num, pseudonym_num);
        return(-307);
      }
      /* replace identifier with pseudonym */
      LogFmt->logtype.laus.msg.msg_ruid = pseudonym_num;


      identifier_num = (long) LogFmt->logtype.laus.msg.msg_suid;
      pseudonym_num = psd_deidentify_num(identifier_num, decodedPsdKey, decodedPsdKeyLen);

      if(pseudonym_num > (2^(sizeof(LogFmt->logtype.laus.msg.msg_suid)*8)))
      {
        log_mesg(WARN, "Error:  pseudonym_num (%ld -> %ld) too large\n", identifier_num, pseudonym_num);
        return(-309);
      }
      /* replace identifier with pseudonym */
      LogFmt->logtype.laus.msg.msg_suid = pseudonym_num;


      identifier_num = (long) LogFmt->logtype.laus.msg.msg_fsuid;
      pseudonym_num = psd_deidentify_num(identifier_num, decodedPsdKey, decodedPsdKeyLen);

      if(pseudonym_num > (2^(sizeof(LogFmt->logtype.laus.msg.msg_fsuid)*8)))
      {
        log_mesg(WARN, "Error:  pseudonym_num (%ld -> %ld) too large\n", identifier_num, pseudonym_num);
        return(-311);
      }
      /* replace identifier with pseudonym */
      LogFmt->logtype.laus.msg.msg_fsuid = pseudonym_num;

      /*
      ** aud_msg_login header
      */
      identifier_num = (long) LogFmt->logtype.laus.type.msg_login.uid;
      pseudonym_num = psd_deidentify_num(identifier_num, decodedPsdKey, decodedPsdKeyLen);

      if(pseudonym_num > (2^(sizeof(LogFmt->logtype.laus.type.msg_login.uid)*8)))
      {
        log_mesg(WARN, "Error:  pseudonym_num (%ld -> %ld) too large\n", identifier_num, pseudonym_num);
        return(-321);
      }
      /* replace identifier with pseudonym */
      LogFmt->logtype.laus.type.msg_login.uid = pseudonym_num;


      if( (identifier = LogFmt->logtype.laus.type.msg_login.hostname) != NULL)
      {
        if( (pseudonym = psd_deidentify(identifier)) == NULL)
        {
          log_mesg(WARN, "Error:  psd_deidentify(identifier = %s)\n", identifier);
          return(-322);
        }
        if(strlen(pseudonym) >= sizeof(identifier))
        {
          log_mesg(WARN, "Error:  pseudonym (%s -> %s) too large\n", identifier, pseudonym);
          free(pseudonym);
          return(-323);
        }
        /* replace identifier with pseudonym */
        memcpy(identifier, pseudonym, sizeof(identifier)-1);
      }


      if( (identifier = LogFmt->logtype.laus.type.msg_login.address) != NULL)
      {
        if( (pseudonym = psd_deidentify(identifier)) == NULL)
        {
          log_mesg(WARN, "Error:  psd_deidentify(identifier = %s)\n", identifier);
          return(-324);
        }
        if(strlen(pseudonym) >= sizeof(identifier))
        {
          log_mesg(WARN, "Error:  pseudonym (%s -> %s) too large\n", identifier, pseudonym);
          free(pseudonym);
          return(-325);
        }
        /* replace identifier with pseudonym */
        memcpy(identifier, pseudonym, sizeof(identifier)-1);
      }
                  
      break;
#endif
  }

  return(0);
}

/* not used, but anyway... ;-) */
int mice_mod_psd_symmetric_LTX_close(void)
{
  /* deinit. pseudonymisation framework */
  if(psd_deinit() < 0)
  {
    log_mesg(WARN, "Error: psd_deinit()\n");
    return(-1);
  }

  return(0);
}



/*
** Handle Config File
*/
int _mice_mod_psd_symmetric_HandleConfFile(char *cConfFile)
{
  int             iCfgCount;
  int             iCnt;
  struct stat     StatBuf;

  
  _mice_mod_psd_symmetric_iSectKeys = -1;
  _mice_mod_psd_symmetric_iSectAccounting = -1;

  if(lstat(cConfFile, &StatBuf) < 0)
  {
    log_mesg(WARN_SYS, "mice_mod_psd_symmetric: Error while trying lstat(%s) | Syserror", cConfFile);
    return(-1);
  }

  if((iCfgCount = cfgParse(cConfFile, _mice_mod_psd_symmetric_CfgIni, CFG_INI)) < 0)
  {
    log_mesg(WARN, "mice_mod_psd_symmetric: Error while parsing Config File %s\n", cConfFile);
    return(-2);
  }

  if(iCfgCount != SECT_MAXSECT)
  {
    log_mesg(WARN, "mice_mod_psd_symmetric: Error while parsing Config File %s | Sections Read: %d | Sections Expect: %d", cConfFile, iCfgCount, SECT_MAXSECT);
    return(-3);
  }

  for(iCnt = 0; iCnt < iCfgCount; iCnt++)
  {
    if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_KEYS))
      _mice_mod_psd_symmetric_iSectKeys = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_ACCT))
      _mice_mod_psd_symmetric_iSectAccounting = iCnt;
    else
    {
      log_mesg(WARN, "mice_mod_psd_symmetric: Error in Config File %s | Unknown Section: %s", cConfFile, cfgSectionNumberToName(iCnt));
      return(-4);
    }
  }

  if(_mice_mod_psd_symmetric_iSectKeys == -1 || _mice_mod_psd_symmetric_iSectAccounting == -1)
  {
    log_mesg(WARN, "mice_mod_psd_symmetric: Error in Config File %s, Section is missing!\n", cConfFile);
    return(-5);
  }

  return(0);
}

