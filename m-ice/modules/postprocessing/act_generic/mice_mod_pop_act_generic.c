/***************************************************************************
                          mice_mod_pop_act_generic.c  -  description
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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>


/*
** Get LibIDMEF from http://www.silicondefense.com/idwg/
*/
#include <libidmef/idmefxml.h>
#include <libidmef/idmefxml_parse.h>

#include <libxml/xmlversion.h>


#include <mice.h>
#include "mice_mod_pop_act_generic.h"
#include "idmef-mesg-format.h"
#include "rid-mesg-format.h"
#include "parsecfg.h"



#define TRUE              1
#define FALSE             0


// Debug
int _mice_mod_pop_act_generic_iDebug = FALSE;


// Structure to keep track of ReactionID->AlertID Relation
typedef struct
{
  int     *AlertIDList;
  size_t  NumMembers;
} RidAid;

// Structure to keep track of ReactionID->PipeName Relation
typedef struct
{
  int     iRID;
  char    *cPipe;
} RidPipe;

// Structure to keep track of AnalyzerID->MatchFile Relation
typedef struct
{
  char    *cAnaID;
  char    *cAnaMF;
} AnaMFile;

// Match AID to member in AID Desc. Array.
typedef struct
{
  char    *cAID;
  u_long  ulAIDHash;    // not used
  int     iAIDDescPtr;
} AID;

// Important Stuff from Matchfile
typedef struct
{
  char    **sAIDValList;
  char    **sAIDDescList;
  int     AIDEntries;

  int     *iAID_1;
  int     AID_1Entries;

  int     *iAID_2;
  int     AID_2Entries;

  int     *iAID_3;
  int     AID_3Entries;

  int     *iAID_4;
  int     AID_4Entries;

  int     *iAID_5;
  int     AID_5Entries;

  int     *iAID_6;
  int     AID_6Entries;

  int     *iAID_7;
  int     AID_7Entries;

  int     *iAID_8;
  int     AID_8Entries;

  int     *iAID_9;
  int     AID_9Entries;

  int     *iAID_10;
  int     AID_10Entries;

} MFInfo;


// Globals to keep track of important and related Informations
RidAid    *stRidAid;
size_t    RidAidEntries;

RidPipe   *stRidPipe;
size_t    RidPipeEntries;

AnaMFile  *stAnaMFile;
size_t    AnaMFileEntries;

MFInfo    *stMFInfo;
size_t    MFInfoEntries;



/*
** Configure File
*/

int _mice_mod_pop_act_generic_CfgDone = FALSE;

struct
{
  int     iSectionNr;
  cfgList **aRID;
} _mice_mod_pop_act_generic_CfgRID;

struct
{
  int     iSectionNr;
  cfgList **aPipe;
} _mice_mod_pop_act_generic_CfgPipe;

struct
{
  int     iSectionNr;
  cfgList **aAnaID;
} _mice_mod_pop_act_generic_CfgAnaID;

struct
{
  int     iSectionNr;
  cfgList **aAnaMF;
} _mice_mod_pop_act_generic_CfgAnaMF;

struct
{
  int     iSectionNr;
  char    **cDTDFile;
} _mice_mod_pop_act_generic_CfgIdmef;

struct
{
  int     iSectionNr;
  char    **cModPath;
  char    **cPipePath;
  char    **cPIDPath;
  char    **cMFPath;
  char    **cUser;
  char    **cGroup;
} _mice_mod_pop_act_generic_CfgMisc;



cfgStruct    _mice_mod_pop_act_generic_CfgIni[] =
{
  // Reaction ID
  {"RID"          ,CFG_STRING_LIST  ,&_mice_mod_pop_act_generic_CfgRID.aRID         },

  // Pipe Name
  {"PIPE"         ,CFG_STRING_LIST  ,&_mice_mod_pop_act_generic_CfgPipe.aPipe       },

  // Analyzer ID
  {"ANAID"        ,CFG_STRING_LIST  ,&_mice_mod_pop_act_generic_CfgAnaID.aAnaID     },

  // Analyzer Matchfile
  {"MF"           ,CFG_STRING_LIST  ,&_mice_mod_pop_act_generic_CfgAnaMF.aAnaMF     },

  // IDMEF
  {"DTDFile"      ,CFG_STRING       ,&_mice_mod_pop_act_generic_CfgIdmef.cDTDFile   },

  // Misc
  {"MOD_PATH"     ,CFG_STRING       ,&_mice_mod_pop_act_generic_CfgMisc.cModPath    },
  {"PIPE_PATH"    ,CFG_STRING       ,&_mice_mod_pop_act_generic_CfgMisc.cPipePath   },
  {"PID_PATH"     ,CFG_STRING       ,&_mice_mod_pop_act_generic_CfgMisc.cPIDPath    },
  {"MATCH_PATH"   ,CFG_STRING       ,&_mice_mod_pop_act_generic_CfgMisc.cMFPath     },
  {"USER"         ,CFG_STRING       ,&_mice_mod_pop_act_generic_CfgMisc.cUser       },
  {"GROUP"        ,CFG_STRING       ,&_mice_mod_pop_act_generic_CfgMisc.cGroup      },

  // The End
  {NULL           ,CFG_END          ,NULL                                       }
};


/*
** Match File
*/
struct
{
  int     iSectionNr;
  cfgList **aAID;
} _mice_mod_pop_act_generic_MfAID;

struct
{
  int     iSectionNr;
  cfgList **aDesc;
} _mice_mod_pop_act_generic_MfDesc;

struct
{
  int     iSectionNr;
  cfgList **aAID;
} _mice_mod_pop_act_generic_MfRID_1;

struct
{
  int     iSectionNr;
  cfgList **aAID;
} _mice_mod_pop_act_generic_MfRID_2;

struct
{
  int     iSectionNr;
  cfgList **aAID;
} _mice_mod_pop_act_generic_MfRID_3;

struct
{
  int     iSectionNr;
  cfgList **aAID;
} _mice_mod_pop_act_generic_MfRID_4;

struct
{
  int     iSectionNr;
  cfgList **aAID;
} _mice_mod_pop_act_generic_MfRID_5;

struct
{
  int     iSectionNr;
  cfgList **aAID;
} _mice_mod_pop_act_generic_MfRID_6;

struct
{
  int     iSectionNr;
  cfgList **aAID;
} _mice_mod_pop_act_generic_MfRID_7;

struct
{
  int     iSectionNr;
  cfgList **aAID;
} _mice_mod_pop_act_generic_MfRID_8;

struct
{
  int     iSectionNr;
  cfgList **aAID;
} _mice_mod_pop_act_generic_MfRID_9;

struct
{
  int     iSectionNr;
  cfgList **aAID;
} _mice_mod_pop_act_generic_MfRID_10;



cfgStruct    _mice_mod_pop_act_generic_MfIni[] =
{
  // Alert ID
  {"AID"          ,CFG_STRING_LIST  ,&_mice_mod_pop_act_generic_MfAID.aAID    },

  // Alert ID Description
  {"AID_DESC"     ,CFG_STRING_LIST  ,&_mice_mod_pop_act_generic_MfDesc.aDesc  },

  // Reaction ID 1
  {"AID_1"        ,CFG_STRING_LIST  ,&_mice_mod_pop_act_generic_MfRID_1.aAID  },

  // Reaction ID 2
  {"AID_2"        ,CFG_STRING_LIST  ,&_mice_mod_pop_act_generic_MfRID_2.aAID  },

  // Reaction ID 3
  {"AID_3"        ,CFG_STRING_LIST  ,&_mice_mod_pop_act_generic_MfRID_3.aAID  },

  // Reaction ID 4
  {"AID_4"        ,CFG_STRING_LIST  ,&_mice_mod_pop_act_generic_MfRID_4.aAID  },

  // Reaction ID 5
  {"AID_5"        ,CFG_STRING_LIST  ,&_mice_mod_pop_act_generic_MfRID_5.aAID  },

  // Reaction ID 6
  {"AID_6"        ,CFG_STRING_LIST  ,&_mice_mod_pop_act_generic_MfRID_6.aAID  },

  // Reaction ID 7
  {"AID_7"        ,CFG_STRING_LIST  ,&_mice_mod_pop_act_generic_MfRID_7.aAID  },

  // Reaction ID 8
  {"AID_8"        ,CFG_STRING_LIST  ,&_mice_mod_pop_act_generic_MfRID_8.aAID  },

  // Reaction ID 9
  {"AID_9"        ,CFG_STRING_LIST  ,&_mice_mod_pop_act_generic_MfRID_9.aAID  },

  // Reaction ID 10
  {"AID_10"       ,CFG_STRING_LIST  ,&_mice_mod_pop_act_generic_MfRID_10.aAID },

  // The End
  {NULL           ,CFG_END          ,NULL                                 }
};


/*
** Function Declaration
*/
int _mice_mod_pop_act_generic_HandleConfFile  (char *cConfFile);
int _mice_mod_pop_act_generic_ParseMatchFile  (char *cMatchFile);
int _mice_mod_pop_act_generic_ProcessReaction (char *cIDMEFmsg, int iRID, char *cAID, char *cAIDDesc);



/***************************************************************************************
**
** p u b l i c   M o d u l e   F u n c t i o n s
**
***************************************************************************************/


/*
** Init
*/
size_t mice_mod_pop_act_generic_LTX_init(char *cConfFile)
{
  register int    iCnt,
                  iCnt_AID;

  struct stat     StatBuf;

  struct passwd   *PwdPtr;

  struct group    *GrpPtr;

  cfgList         *LstRID,
                  *LstPipe,
                  *LstAnaID,
                  *LstAnaMF,
                  *LstMfAID,
                  *LstMfDesc,
                  *LstMfRID;


  //log_open("mice_mod_pop_act_generic", LOG_PID, LOG_USER);


  if(_mice_mod_pop_act_generic_CfgDone != FALSE)
  {
    log_mesg(WARN, "mice_mod_pop_act_generic: Do NOT call init function twice, call close function inbetween");
    return(-1);
  }

/*
  if(_mice_mod_pop_act_generic_iDebug)
  {
    log_mesg(WARN, "mice_mod_pop_act_generic: SLEEP");
    sleep(10);
  }
*/

  /*
  ** Parse Config File
  */
  if(_mice_mod_pop_act_generic_iDebug)
    log_mesg(WARN, "mice_mod_pop_act_generic: parse config file");

  if(_mice_mod_pop_act_generic_HandleConfFile(cConfFile) < 0)
    return(-1);


  /*
  ** Get Passwd and Group Entry
  */
  if(_mice_mod_pop_act_generic_iDebug)
    log_mesg(WARN, "mice_mod_pop_act_generic: Loockup User %s and Group %s", _mice_mod_pop_act_generic_CfgMisc.cUser[_mice_mod_pop_act_generic_CfgMisc.iSectionNr], _mice_mod_pop_act_generic_CfgMisc.cGroup[_mice_mod_pop_act_generic_CfgMisc.iSectionNr]);

  if( !(PwdPtr = getpwnam(_mice_mod_pop_act_generic_CfgMisc.cUser[_mice_mod_pop_act_generic_CfgMisc.iSectionNr])) || !(GrpPtr = getgrnam(_mice_mod_pop_act_generic_CfgMisc.cGroup[_mice_mod_pop_act_generic_CfgMisc.iSectionNr])) )
  {
    log_mesg(FATAL, "mice_mod_pop_act_generic: Unknown user (%s) or group (%s) entry!", _mice_mod_pop_act_generic_CfgMisc.cUser[_mice_mod_pop_act_generic_CfgMisc.iSectionNr], _mice_mod_pop_act_generic_CfgMisc.cGroup[_mice_mod_pop_act_generic_CfgMisc.iSectionNr]);
    return(-333);
  }


  /*
  ** Fill structures
  */
  if(_mice_mod_pop_act_generic_iDebug)
    log_mesg(WARN, "mice_mod_pop_act_generic: Fill Structures");

  for(  LstRID  = _mice_mod_pop_act_generic_CfgRID.aRID    [_mice_mod_pop_act_generic_CfgRID.iSectionNr],
        LstPipe = _mice_mod_pop_act_generic_CfgPipe.aPipe  [_mice_mod_pop_act_generic_CfgPipe.iSectionNr],
        stRidPipe = NULL,
        RidPipeEntries = 0;
          LstRID  != NULL &&
          LstPipe != NULL;
        LstRID  = LstRID->next,
        LstPipe = LstPipe->next,
        RidPipeEntries++
     )
  {
    if( (stRidPipe = (RidPipe *) realloc(stRidPipe, (RidPipeEntries+1) * sizeof(RidPipe))) == NULL)
    {
      log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while allocating Memory for RidPipe structure| Syserror");
      return(-2);
    }

    stRidPipe[RidPipeEntries].iRID   = atoi(LstRID->str);
    asprintf(&stRidPipe[RidPipeEntries].cPipe, "%s/%s", _mice_mod_pop_act_generic_CfgMisc.cPipePath[_mice_mod_pop_act_generic_CfgMisc.iSectionNr], LstPipe->str);
  }

  if(RidPipeEntries == 0)
  {
    log_mesg(WARN, "mice_mod_pop_act_generic: No Entries for Reaction ID and/or Reaction Pipe found! Please, check Config File.\n");
    return(-5);
  }
  RidPipeEntries--;


  if(LstRID != NULL)
  {
    log_mesg(WARN, "mice_mod_pop_act_generic: Too much RID Entries! Please, check Config File.\n");
    return(-10);
  }

  if(LstPipe != NULL)
  {
    log_mesg(WARN, "mice_mod_pop_act_generic: Too much Pipe Entries! Please, check Config File.\n");
    return(-11);
  }


  /*
  ** Read Analyzer ID and corresponding Matchfile
  */
  for(  LstAnaID  = _mice_mod_pop_act_generic_CfgAnaID.aAnaID   [_mice_mod_pop_act_generic_CfgAnaID.iSectionNr],
        LstAnaMF  = _mice_mod_pop_act_generic_CfgAnaMF.aAnaMF   [_mice_mod_pop_act_generic_CfgAnaMF.iSectionNr],
        stAnaMFile = NULL,
        AnaMFileEntries = 0;
          LstAnaID  != NULL &&
          LstAnaMF  != NULL;
        LstAnaID  = LstAnaID->next,
        LstAnaMF  = LstAnaMF->next,
        AnaMFileEntries++
     )
  {
    if( (stAnaMFile = (AnaMFile *) realloc(stAnaMFile, (AnaMFileEntries+1) * sizeof(AnaMFile))) == NULL)
    {
      log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while allocating Memory for AnaMFile structure| Syserror");
      return(-20);
    }

    if( (stAnaMFile[AnaMFileEntries].cAnaID = calloc(strlen(LstAnaID->str)+1, sizeof(char)) ) == NULL)
    {
      log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while allocating Memory for AnaMFile structure| Syserror");
      return(-20);
    }

    strcpy(stAnaMFile[AnaMFileEntries].cAnaID, LstAnaID->str);

    if( (stAnaMFile[AnaMFileEntries].cAnaMF = calloc(strlen(_mice_mod_pop_act_generic_CfgMisc.cMFPath[_mice_mod_pop_act_generic_CfgMisc.iSectionNr])+strlen(LstAnaMF->str)+2, sizeof(char)) ) == NULL)
    {
      log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while allocating Memory for AnaMFile structure| Syserror");
      return(-20);
    }

    sprintf(stAnaMFile[AnaMFileEntries].cAnaMF, "%s/%s",  _mice_mod_pop_act_generic_CfgMisc.cMFPath[_mice_mod_pop_act_generic_CfgMisc.iSectionNr], LstAnaMF->str);
  }

  if(AnaMFileEntries == 0)
  {
    log_mesg(WARN, "mice_mod_pop_act_generic: No Entries for Analyzer ID and/or Analyzer Matchfile found! Please, check Config File.\n");
    return(-21);
  }
  AnaMFileEntries--;


  if(LstAnaID != NULL)
  {
    log_mesg(WARN, "mice_mod_pop_act_generic: Too much Analyzer ID Entries! Please, check Config File.\n");
    return(-22);
  }

  if(LstAnaMF != NULL)
  {
    log_mesg(WARN, "mice_mod_pop_act_generic: Too much Analyzer Matchfile Entries! Please, check Config File.\n");
    return(-23);
  }


  /*
  ** Parse every Match File
  */
  if(_mice_mod_pop_act_generic_iDebug)
    log_mesg(WARN, "mice_mod_pop_act_generic: parse match file");


  for(MFInfoEntries = 0, stMFInfo = NULL; MFInfoEntries <= AnaMFileEntries; MFInfoEntries++)
  {
    if(_mice_mod_pop_act_generic_ParseMatchFile(stAnaMFile[MFInfoEntries].cAnaMF) < 0)
      return(-30);

    if( (stMFInfo = (MFInfo *) realloc(stMFInfo, (MFInfoEntries+1) * sizeof(MFInfo))) == NULL)
    {
      log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while allocating Memory for MFInfo structure | Syserror");
      return(-31);
    }

    /*
    ** Alert ID and corresponding Description
    */
    for(
        LstMfAID  = _mice_mod_pop_act_generic_MfAID.aAID    [_mice_mod_pop_act_generic_MfAID.iSectionNr],
        LstMfDesc = _mice_mod_pop_act_generic_MfDesc.aDesc  [_mice_mod_pop_act_generic_MfDesc.iSectionNr],
        stMFInfo[MFInfoEntries].sAIDValList  = NULL,
        stMFInfo[MFInfoEntries].sAIDDescList = NULL,
        stMFInfo[MFInfoEntries].AIDEntries   = 0;
          LstMfAID  != NULL &&
          LstMfDesc != NULL;
        LstMfAID  = LstMfAID->next,
        LstMfDesc = LstMfDesc->next,
        stMFInfo[MFInfoEntries].AIDEntries++
       )
    {

      /*
      ** Alloc mem for AID
      */
      if( (stMFInfo[MFInfoEntries].sAIDValList = (char **) realloc(stMFInfo[MFInfoEntries].sAIDValList, (stMFInfo[MFInfoEntries].AIDEntries+1) * sizeof(char *))) == NULL)
      {
        log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while allocating Memory for AID Array | Syserror");
        return(-50);
      }

      if( (stMFInfo[MFInfoEntries].sAIDValList[stMFInfo[MFInfoEntries].AIDEntries] = (char *) calloc(strlen(LstMfAID->str)+1, sizeof(char))) == NULL)
      {
        log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while allocating Memory for AID String | Syserror");
        return(-51);
      }

      memcpy(stMFInfo[MFInfoEntries].sAIDValList[stMFInfo[MFInfoEntries].AIDEntries], LstMfAID->str, strlen(LstMfAID->str));


      /*
      ** Alloc mem for AID Desc.
      */
      if( (stMFInfo[MFInfoEntries].sAIDDescList = (char **) realloc(stMFInfo[MFInfoEntries].sAIDDescList, (stMFInfo[MFInfoEntries].AIDEntries+1) * sizeof(char *))) == NULL)
      {
        log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while allocating Memory for AID Desc. Array | Syserror");
        return(-50);
      }

      if( (stMFInfo[MFInfoEntries].sAIDDescList[stMFInfo[MFInfoEntries].AIDEntries] = (char *) calloc(strlen(LstMfDesc->str)+1, sizeof(char))) == NULL)
      {
        log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while allocating Memory for AID Desc. String | Syserror");
        return(-51);
      }

      memcpy(stMFInfo[MFInfoEntries].sAIDDescList[stMFInfo[MFInfoEntries].AIDEntries], LstMfDesc->str, strlen(LstMfDesc->str));
    }

    if(stMFInfo[MFInfoEntries].AIDEntries == 0)
    {
      log_mesg(WARN, "mice_mod_pop_act_generic: No Entries for AID and AID Description in Matchfile '%s' found! Please, check Mathfile.\n", stAnaMFile[MFInfoEntries].cAnaMF);
      return(-33);
    }
    stMFInfo[MFInfoEntries].AIDEntries--;

    if(LstMfAID != NULL)
    {
      log_mesg(WARN, "mice_mod_pop_act_generic: Too much AID Entries in Matchfile '%s' found! Please, check Matchfile.\n", stAnaMFile[MFInfoEntries].cAnaMF);
      return(-34);
    }
    if(LstMfDesc != NULL)
    {
      log_mesg(WARN, "mice_mod_pop_act_generic: Too much AID Description Entries in Matchfile '%s' found! Please, check Matchfile.\n", stAnaMFile[MFInfoEntries].cAnaMF);
      return(-35);
    }


    /*
    ** Read AIDs for RID 1
    */
    for(
        LstMfRID  = _mice_mod_pop_act_generic_MfRID_1.aAID[_mice_mod_pop_act_generic_MfRID_1.iSectionNr],
        stMFInfo[MFInfoEntries].iAID_1 = NULL,
        stMFInfo[MFInfoEntries].AID_1Entries = 0;
          LstMfRID  != NULL;
        LstMfRID  = LstMfRID->next,
        stMFInfo[MFInfoEntries].AID_1Entries++
       )
    {
      if( (stMFInfo[MFInfoEntries].iAID_1 = (int *) realloc(stMFInfo[MFInfoEntries].iAID_1, (stMFInfo[MFInfoEntries].AID_1Entries+1) * sizeof(int))) == NULL)
      {
        log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while allocating Memory for AID Array | Syserror");
        return(-50);
      }

      stMFInfo[MFInfoEntries].iAID_1[stMFInfo[MFInfoEntries].AID_1Entries] = -1;
      for(iCnt_AID = 0; iCnt_AID <= stMFInfo[MFInfoEntries].AIDEntries; iCnt_AID++)
        if(!strcasecmp(stMFInfo[MFInfoEntries].sAIDValList[iCnt_AID], LstMfRID->str))
          stMFInfo[MFInfoEntries].iAID_1[stMFInfo[MFInfoEntries].AID_1Entries] = iCnt_AID;  // we just save the index
    }
    stMFInfo[MFInfoEntries].AID_1Entries--; // -1 indicates no entries.

    /*
    ** Read AIDs for RID 2
    */
    for(
        LstMfRID  = _mice_mod_pop_act_generic_MfRID_2.aAID[_mice_mod_pop_act_generic_MfRID_2.iSectionNr],
        stMFInfo[MFInfoEntries].iAID_2 = NULL,
        stMFInfo[MFInfoEntries].AID_2Entries = 0;
          LstMfRID  != NULL;
        LstMfRID  = LstMfRID->next,
        stMFInfo[MFInfoEntries].AID_2Entries++
       )
    {
      if( (stMFInfo[MFInfoEntries].iAID_2 = (int *) realloc(stMFInfo[MFInfoEntries].iAID_2, (stMFInfo[MFInfoEntries].AID_2Entries+1) * sizeof(int))) == NULL)
      {
        log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while allocating Memory for AID Array | Syserror");
        return(-50);
      }

      stMFInfo[MFInfoEntries].iAID_2[stMFInfo[MFInfoEntries].AID_2Entries] = -1;
      for(iCnt_AID = 0; iCnt_AID <= stMFInfo[MFInfoEntries].AIDEntries; iCnt_AID++)
        if(!strcasecmp(stMFInfo[MFInfoEntries].sAIDValList[iCnt_AID], LstMfRID->str))
          stMFInfo[MFInfoEntries].iAID_2[stMFInfo[MFInfoEntries].AID_2Entries] = iCnt_AID;
    }
    stMFInfo[MFInfoEntries].AID_2Entries--; // -1 indicates no entries.

    /*
    ** Read AIDs for RID 3
    */
    for(
        LstMfRID  = _mice_mod_pop_act_generic_MfRID_3.aAID[_mice_mod_pop_act_generic_MfRID_3.iSectionNr],
        stMFInfo[MFInfoEntries].iAID_3 = NULL,
        stMFInfo[MFInfoEntries].AID_3Entries = 0;
          LstMfRID  != NULL;
        LstMfRID  = LstMfRID->next,
        stMFInfo[MFInfoEntries].AID_3Entries++
       )
    {
      if( (stMFInfo[MFInfoEntries].iAID_3 = (int *) realloc(stMFInfo[MFInfoEntries].iAID_3, (stMFInfo[MFInfoEntries].AID_3Entries+1) * sizeof(int))) == NULL)
      {
        log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while allocating Memory for AID Array | Syserror");
        return(-50);
      }

      stMFInfo[MFInfoEntries].iAID_3[stMFInfo[MFInfoEntries].AID_3Entries] = -1;
      for(iCnt_AID = 0; iCnt_AID <= stMFInfo[MFInfoEntries].AIDEntries; iCnt_AID++)
        if(!strcasecmp(stMFInfo[MFInfoEntries].sAIDValList[iCnt_AID], LstMfRID->str))
          stMFInfo[MFInfoEntries].iAID_3[stMFInfo[MFInfoEntries].AID_3Entries] = iCnt_AID;
    }
    stMFInfo[MFInfoEntries].AID_3Entries--; // -1 indicates no entries.

    /*
    ** Read AIDs for RID 4
    */
    for(
        LstMfRID  = _mice_mod_pop_act_generic_MfRID_4.aAID[_mice_mod_pop_act_generic_MfRID_4.iSectionNr],
        stMFInfo[MFInfoEntries].iAID_4 = NULL,
        stMFInfo[MFInfoEntries].AID_4Entries = 0;
          LstMfRID  != NULL;
        LstMfRID  = LstMfRID->next,
        stMFInfo[MFInfoEntries].AID_4Entries++
       )
    {
      if( (stMFInfo[MFInfoEntries].iAID_4 = (int *) realloc(stMFInfo[MFInfoEntries].iAID_4, (stMFInfo[MFInfoEntries].AID_4Entries+1) * sizeof(int))) == NULL)
      {
        log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while allocating Memory for AID Array | Syserror");
        return(-50);
      }

      stMFInfo[MFInfoEntries].iAID_4[stMFInfo[MFInfoEntries].AID_4Entries] = -1;
      for(iCnt_AID = 0; iCnt_AID <= stMFInfo[MFInfoEntries].AIDEntries; iCnt_AID++)
        if(!strcasecmp(stMFInfo[MFInfoEntries].sAIDValList[iCnt_AID], LstMfRID->str))
          stMFInfo[MFInfoEntries].iAID_4[stMFInfo[MFInfoEntries].AID_4Entries] = iCnt_AID;
    }
    stMFInfo[MFInfoEntries].AID_4Entries--; // -1 indicates no entries.

    /*
    ** Read AIDs for RID 5
    */
    for(
        LstMfRID  = _mice_mod_pop_act_generic_MfRID_5.aAID[_mice_mod_pop_act_generic_MfRID_5.iSectionNr],
        stMFInfo[MFInfoEntries].iAID_5 = NULL,
        stMFInfo[MFInfoEntries].AID_5Entries = 0;
          LstMfRID  != NULL;
        LstMfRID  = LstMfRID->next,
        stMFInfo[MFInfoEntries].AID_5Entries++
       )
    {
      if( (stMFInfo[MFInfoEntries].iAID_5 = (int *) realloc(stMFInfo[MFInfoEntries].iAID_5, (stMFInfo[MFInfoEntries].AID_5Entries+1) * sizeof(int))) == NULL)
      {
        log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while allocating Memory for AID Array | Syserror");
        return(-50);
      }

      stMFInfo[MFInfoEntries].iAID_5[stMFInfo[MFInfoEntries].AID_5Entries] = -1;
      for(iCnt_AID = 0; iCnt_AID <= stMFInfo[MFInfoEntries].AIDEntries; iCnt_AID++)
        if(!strcasecmp(stMFInfo[MFInfoEntries].sAIDValList[iCnt_AID], LstMfRID->str))
          stMFInfo[MFInfoEntries].iAID_5[stMFInfo[MFInfoEntries].AID_5Entries] = iCnt_AID;
    }
    stMFInfo[MFInfoEntries].AID_5Entries--; // -1 indicates no entries.

    /*
    ** Read AIDs for RID 6
    */
    for(
        LstMfRID  = _mice_mod_pop_act_generic_MfRID_6.aAID[_mice_mod_pop_act_generic_MfRID_6.iSectionNr],
        stMFInfo[MFInfoEntries].iAID_6 = NULL,
        stMFInfo[MFInfoEntries].AID_6Entries = 0;
          LstMfRID  != NULL;
        LstMfRID  = LstMfRID->next,
        stMFInfo[MFInfoEntries].AID_6Entries++
       )
    {
      if( (stMFInfo[MFInfoEntries].iAID_6 = (int *) realloc(stMFInfo[MFInfoEntries].iAID_6, (stMFInfo[MFInfoEntries].AID_6Entries+1) * sizeof(int))) == NULL)
      {
        log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while allocating Memory for AID Array | Syserror");
        return(-50);
      }

      stMFInfo[MFInfoEntries].iAID_6[stMFInfo[MFInfoEntries].AID_6Entries] = -1;
      for(iCnt_AID = 0; iCnt_AID <= stMFInfo[MFInfoEntries].AIDEntries; iCnt_AID++)
        if(!strcasecmp(stMFInfo[MFInfoEntries].sAIDValList[iCnt_AID], LstMfRID->str))
          stMFInfo[MFInfoEntries].iAID_6[stMFInfo[MFInfoEntries].AID_6Entries] = iCnt_AID;
    }
    stMFInfo[MFInfoEntries].AID_6Entries--; // -1 indicates no entries.

    /*
    ** Read AIDs for RID 7
    */
    for(
        LstMfRID  = _mice_mod_pop_act_generic_MfRID_7.aAID[_mice_mod_pop_act_generic_MfRID_7.iSectionNr],
        stMFInfo[MFInfoEntries].iAID_7 = NULL,
        stMFInfo[MFInfoEntries].AID_7Entries = 0;
          LstMfRID  != NULL;
        LstMfRID  = LstMfRID->next,
        stMFInfo[MFInfoEntries].AID_7Entries++
       )
    {
      if( (stMFInfo[MFInfoEntries].iAID_7 = (int *) realloc(stMFInfo[MFInfoEntries].iAID_7, (stMFInfo[MFInfoEntries].AID_7Entries+1) * sizeof(int))) == NULL)
      {
        log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while allocating Memory for AID Array | Syserror");
        return(-50);
      }

      stMFInfo[MFInfoEntries].iAID_7[stMFInfo[MFInfoEntries].AID_7Entries] = -1;
      for(iCnt_AID = 0; iCnt_AID <= stMFInfo[MFInfoEntries].AIDEntries; iCnt_AID++)
        if(!strcasecmp(stMFInfo[MFInfoEntries].sAIDValList[iCnt_AID], LstMfRID->str))
          stMFInfo[MFInfoEntries].iAID_7[stMFInfo[MFInfoEntries].AID_7Entries] = iCnt_AID;
    }
    stMFInfo[MFInfoEntries].AID_7Entries--; // -1 indicates no entries.

    /*
    ** Read AIDs for RID 8
    */
    for(
        LstMfRID  = _mice_mod_pop_act_generic_MfRID_8.aAID[_mice_mod_pop_act_generic_MfRID_8.iSectionNr],
        stMFInfo[MFInfoEntries].iAID_8 = NULL,
        stMFInfo[MFInfoEntries].AID_8Entries = 0;
          LstMfRID  != NULL;
        LstMfRID  = LstMfRID->next,
        stMFInfo[MFInfoEntries].AID_8Entries++
       )
    {
      if( (stMFInfo[MFInfoEntries].iAID_8 = (int *) realloc(stMFInfo[MFInfoEntries].iAID_8, (stMFInfo[MFInfoEntries].AID_8Entries+1) * sizeof(int))) == NULL)
      {
        log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while allocating Memory for AID Array | Syserror");
        return(-50);
      }

      stMFInfo[MFInfoEntries].iAID_8[stMFInfo[MFInfoEntries].AID_8Entries] = -1;
      for(iCnt_AID = 0; iCnt_AID <= stMFInfo[MFInfoEntries].AIDEntries; iCnt_AID++)
        if(!strcasecmp(stMFInfo[MFInfoEntries].sAIDValList[iCnt_AID], LstMfRID->str))
          stMFInfo[MFInfoEntries].iAID_8[stMFInfo[MFInfoEntries].AID_8Entries] = iCnt_AID;
    }
    stMFInfo[MFInfoEntries].AID_8Entries--; // -1 indicates no entries.

    /*
    ** Read AIDs for RID 9
    */
    for(
        LstMfRID  = _mice_mod_pop_act_generic_MfRID_9.aAID[_mice_mod_pop_act_generic_MfRID_9.iSectionNr],
        stMFInfo[MFInfoEntries].iAID_9 = NULL,
        stMFInfo[MFInfoEntries].AID_9Entries = 0;
          LstMfRID  != NULL;
        LstMfRID  = LstMfRID->next,
        stMFInfo[MFInfoEntries].AID_9Entries++
       )
    {
      if( (stMFInfo[MFInfoEntries].iAID_9 = (int *) realloc(stMFInfo[MFInfoEntries].iAID_9, (stMFInfo[MFInfoEntries].AID_9Entries+1) * sizeof(int))) == NULL)
      {
        log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while allocating Memory for AID Array | Syserror");
        return(-50);
      }

      stMFInfo[MFInfoEntries].iAID_9[stMFInfo[MFInfoEntries].AID_9Entries] = -1;
      for(iCnt_AID = 0; iCnt_AID <= stMFInfo[MFInfoEntries].AIDEntries; iCnt_AID++)
        if(!strcasecmp(stMFInfo[MFInfoEntries].sAIDValList[iCnt_AID], LstMfRID->str))
          stMFInfo[MFInfoEntries].iAID_9[stMFInfo[MFInfoEntries].AID_9Entries] = iCnt_AID;
    }
    stMFInfo[MFInfoEntries].AID_9Entries--; // -1 indicates no entries.

    /*
    ** Read AIDs for RID 10
    */
    for(
        LstMfRID  = _mice_mod_pop_act_generic_MfRID_10.aAID[_mice_mod_pop_act_generic_MfRID_10.iSectionNr],
        stMFInfo[MFInfoEntries].iAID_10 = NULL,
        stMFInfo[MFInfoEntries].AID_10Entries = 0;
          LstMfRID  != NULL;
        LstMfRID  = LstMfRID->next,
        stMFInfo[MFInfoEntries].AID_10Entries++
       )
    {
      if( (stMFInfo[MFInfoEntries].iAID_10 = (int *) realloc(stMFInfo[MFInfoEntries].iAID_10, (stMFInfo[MFInfoEntries].AID_10Entries+1) * sizeof(int))) == NULL)
      {
        log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while allocating Memory for AID Array | Syserror");
        return(-50);
      }

      stMFInfo[MFInfoEntries].iAID_10[stMFInfo[MFInfoEntries].AID_10Entries] = -1;
      for(iCnt_AID = 0; iCnt_AID <= stMFInfo[MFInfoEntries].AIDEntries; iCnt_AID++)
        if(!strcasecmp(stMFInfo[MFInfoEntries].sAIDValList[iCnt_AID], LstMfRID->str))
          stMFInfo[MFInfoEntries].iAID_10[stMFInfo[MFInfoEntries].AID_10Entries] = iCnt_AID;
    }
    stMFInfo[MFInfoEntries].AID_10Entries--; // -1 indicates no entries.


  } // for(parsing every match file)

  if(MFInfoEntries == 0)
  {
    log_mesg(WARN, "mice_mod_pop_act_generic: No Entries for Analyzer Matchfile found! Please, check Matchfile.\n");
    return(-40);
  }
  MFInfoEntries--;



  /*
  ** IDMEF Init Stuff
  */
  if(_mice_mod_pop_act_generic_iDebug)
    log_mesg(WARN, "mice_mod_pop_act_generic: init IDMEF");

  if(_mice_mod_pop_act_generic_iDebug)
    log_mesg(WARN, "mice_mod_pop_act_generic: xmlSubstituteEntitiesDefault(0);");
  xmlSubstituteEntitiesDefault(0);

  if(_mice_mod_pop_act_generic_iDebug)
    log_mesg(WARN, "mice_mod_pop_act_generic: globalsInit");
  globalsInit(_mice_mod_pop_act_generic_CfgIdmef.cDTDFile[_mice_mod_pop_act_generic_CfgIdmef.iSectionNr]);


  /*
  ** Create Named Pipes
  */
  for(iCnt = 0; iCnt <= RidPipeEntries; iCnt++)
  {
    if(stat(stRidPipe[iCnt].cPipe, &StatBuf) == 0)
    {
      if(!S_ISFIFO(StatBuf.st_mode))
      {
        log_mesg(WARN, "mice_mod_pop_act_generic: %s isn't a FIFO", stRidPipe[iCnt].cPipe);
        return(-200);
      }
      if(StatBuf.st_uid != PwdPtr->pw_uid)
      {
        log_mesg(WARN, "mice_mod_pop_act_generic: %s doesn't belong to UID %d", stRidPipe[iCnt].cPipe, PwdPtr->pw_uid);
        return(-201);
      }
      if(StatBuf.st_gid != GrpPtr->gr_gid)
      {
        log_mesg(WARN, "mice_mod_pop_act_generic: %s doesn't belong to GID %d", stRidPipe[iCnt].cPipe, GrpPtr->gr_gid);
        return(-202);
      }
    }
    else
    {
      if(mkfifo(stRidPipe[iCnt].cPipe, 0600) != 0)
      {
        log_mesg(WARN_SYS, "Error: mkfifo(%s, 0600) | Syserror", stRidPipe[iCnt].cPipe);
        return(-300);
      }
      /* XXX: hmmm.. we are not root here. :-\ */
      if(chown(stRidPipe[iCnt].cPipe, PwdPtr->pw_uid, GrpPtr->gr_gid) != 0)
      {
        log_mesg(WARN_SYS, "Error: chown(%s, %d, %d) | Syserror", stRidPipe[iCnt].cPipe, PwdPtr->pw_uid, GrpPtr->gr_gid);
        return(-301);
      }
    }
  }

  _mice_mod_pop_act_generic_CfgDone = TRUE;

  if(_mice_mod_pop_act_generic_iDebug)
    log_mesg(WARN, "mice_mod_pop_act_generic: return");

  return(MAX_IDMEFMSGSIZE+1);
}



/*
** Main Function
*/
int mice_mod_pop_act_generic_LTX_func(char *cData, size_t DataSize)
{
  register int  iCnt_Matchfile,
                iCnt_Alert,
                iCnt_Classification,
                iCnt_AID;

  IDMEFmessage  *IDMEFmsg;



  if(_mice_mod_pop_act_generic_CfgDone != TRUE)
  {
    log_mesg(WARN, "mice_mod_pop_act_generic: Error! You have to call mice_mod_pop_act_generic_LTX_init() first!\n");
    return(-1);
  }


  /*
  ** Initialization function for the XML parser. This is not reentrant.
  ** Call once before processing in case of use in multithreaded programs
  */
  if(_mice_mod_pop_act_generic_iDebug)
    log_mesg(WARN, "mice_mod_pop_act_generic: xmlInitParser");

  xmlInitParser();

  if(_mice_mod_pop_act_generic_iDebug)
    log_mesg(WARN, "mice_mod_pop_act_generic: get_idmef_message");

  IDMEFmsg = 0;
  if( (IDMEFmsg = get_idmef_message(cData, MAX_IDMEFMSGSIZE+1)) == 0)
  {
    log_mesg(WARN, "mice_mod_pop_act_generic: Error while generating IDMEF Message!\n");
    return(-3);
  }


  /* XXX
  ** The Search Algorithm and the Organisation of the Information is
  ** NOT very sophisticated and could be improved. :)
  */
  if(_mice_mod_pop_act_generic_iDebug)
    log_mesg(WARN, "mice_mod_pop_act_generic: Start Searching in %d Matchfile(s) for %d Alerts...", MFInfoEntries+1, IDMEFmsg->nalerts);

  for(iCnt_Matchfile = 0; iCnt_Matchfile <= MFInfoEntries; iCnt_Matchfile++)
  {
    for(iCnt_Alert = 0; iCnt_Alert < IDMEFmsg->nalerts; iCnt_Alert++)
    {
      for(iCnt_Classification = 0; iCnt_Classification < IDMEFmsg->alerts[iCnt_Alert]->nclassifications; iCnt_Classification++)
      {
        if(_mice_mod_pop_act_generic_iDebug == TRUE+TRUE)
        {
          log_mesg(WARN, "mice_mod_pop_act_generic: Check Classificationname: %s", IDMEFmsg->alerts[iCnt_Alert]->classifications[iCnt_Classification]->name);
          log_mesg(WARN, "mice_mod_pop_act_generic: AID_1 Entries = %d", stMFInfo[iCnt_Matchfile].AID_1Entries);
        }


        // Check for RID 1
        for(iCnt_AID = 0; iCnt_AID <= stMFInfo[iCnt_Matchfile].AID_1Entries; iCnt_AID++)
        {
          if(stMFInfo[iCnt_Matchfile].iAID_1[iCnt_AID] == -1) // no entry
            continue;

          // Should we react on this AlertID?
          if(_mice_mod_pop_act_generic_iDebug == TRUE+TRUE+TRUE)
          {
            log_mesg(WARN, "mice_mod_pop_act_generic: Cnt = %d | Index = %d ", iCnt_AID, stMFInfo[iCnt_Matchfile].iAID_1[iCnt_AID]);
            log_mesg(WARN, "mice_mod_pop_act_generic: RID 1: %s", stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_1[iCnt_AID]]);
          }

          if( !strcasecmp(IDMEFmsg->alerts[iCnt_Alert]->classifications[iCnt_Classification]->name, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_1[iCnt_AID]]) )
            _mice_mod_pop_act_generic_ProcessReaction(cData, RID_1, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_1[iCnt_AID]], stMFInfo[iCnt_Matchfile].sAIDDescList[stMFInfo[iCnt_Matchfile].iAID_1[iCnt_AID]]);
        }

        // Check for RID 2
        for(iCnt_AID = 0; iCnt_AID <= stMFInfo[iCnt_Matchfile].AID_2Entries; iCnt_AID++)
        {
          if(stMFInfo[iCnt_Matchfile].iAID_2[iCnt_AID] == -1) // no entry
            continue;

          // Should we react on this AlertID?
          if(_mice_mod_pop_act_generic_iDebug == TRUE+TRUE+TRUE)
          {
            log_mesg(WARN, "mice_mod_pop_act_generic: Cnt = %d | Index = %d ", iCnt_AID, stMFInfo[iCnt_Matchfile].iAID_2[iCnt_AID]);
            log_mesg(WARN, "mice_mod_pop_act_generic: RID 2: %s", stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_2[iCnt_AID]]);
          }

          if( !strcasecmp(IDMEFmsg->alerts[iCnt_Alert]->classifications[iCnt_Classification]->name, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_2[iCnt_AID]]) )
            _mice_mod_pop_act_generic_ProcessReaction(cData, RID_2, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_2[iCnt_AID]], stMFInfo[iCnt_Matchfile].sAIDDescList[stMFInfo[iCnt_Matchfile].iAID_2[iCnt_AID]]);
        }

        // Check for RID 3
        for(iCnt_AID = 0; iCnt_AID <= stMFInfo[iCnt_Matchfile].AID_3Entries; iCnt_AID++)
        {
          if(stMFInfo[iCnt_Matchfile].iAID_3[iCnt_AID] == -1) // no entry
            continue;

          // Should we react on this AlertID?
          if(_mice_mod_pop_act_generic_iDebug == TRUE+TRUE+TRUE)
          {
            log_mesg(WARN, "mice_mod_pop_act_generic: Cnt = %d | Index = %d ", iCnt_AID, stMFInfo[iCnt_Matchfile].iAID_3[iCnt_AID]);
            log_mesg(WARN, "mice_mod_pop_act_generic: RID 3: %s", stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_3[iCnt_AID]]);
          }

          if( !strcasecmp(IDMEFmsg->alerts[iCnt_Alert]->classifications[iCnt_Classification]->name, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_3[iCnt_AID]]) )
            _mice_mod_pop_act_generic_ProcessReaction(cData, RID_3, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_3[iCnt_AID]], stMFInfo[iCnt_Matchfile].sAIDDescList[stMFInfo[iCnt_Matchfile].iAID_3[iCnt_AID]]);
        }

        // Check for RID 4
        for(iCnt_AID = 0; iCnt_AID <= stMFInfo[iCnt_Matchfile].AID_4Entries; iCnt_AID++)
        {
          if(stMFInfo[iCnt_Matchfile].iAID_4[iCnt_AID] == -1) // no entry
            continue;

          // Should we react on this AlertID?
          if(_mice_mod_pop_act_generic_iDebug == TRUE+TRUE+TRUE)
          {
            log_mesg(WARN, "mice_mod_pop_act_generic: Cnt = %d | Index = %d ", iCnt_AID, stMFInfo[iCnt_Matchfile].iAID_4[iCnt_AID]);
            log_mesg(WARN, "mice_mod_pop_act_generic: RID 4: %s", stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_4[iCnt_AID]]);
          }

          if( !strcasecmp(IDMEFmsg->alerts[iCnt_Alert]->classifications[iCnt_Classification]->name, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_4[iCnt_AID]]) )
            _mice_mod_pop_act_generic_ProcessReaction(cData, RID_4, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_4[iCnt_AID]], stMFInfo[iCnt_Matchfile].sAIDDescList[stMFInfo[iCnt_Matchfile].iAID_4[iCnt_AID]]);
        }

        // Check for RID 5
        for(iCnt_AID = 0; iCnt_AID <= stMFInfo[iCnt_Matchfile].AID_5Entries; iCnt_AID++)
        {
          if(stMFInfo[iCnt_Matchfile].iAID_5[iCnt_AID] == -1) // no entry
            continue;

          // Should we react on this AlertID?
          if(_mice_mod_pop_act_generic_iDebug == TRUE+TRUE+TRUE)
          {
            log_mesg(WARN, "mice_mod_pop_act_generic: Cnt = %d | Index = %d ", iCnt_AID, stMFInfo[iCnt_Matchfile].iAID_5[iCnt_AID]);
            log_mesg(WARN, "mice_mod_pop_act_generic: RID 5: %s", stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_5[iCnt_AID]]);
          }

          if( !strcasecmp(IDMEFmsg->alerts[iCnt_Alert]->classifications[iCnt_Classification]->name, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_5[iCnt_AID]]) )
            _mice_mod_pop_act_generic_ProcessReaction(cData, RID_5, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_5[iCnt_AID]], stMFInfo[iCnt_Matchfile].sAIDDescList[stMFInfo[iCnt_Matchfile].iAID_5[iCnt_AID]]);
        }

        // Check for RID 6
        for(iCnt_AID = 0; iCnt_AID <= stMFInfo[iCnt_Matchfile].AID_6Entries; iCnt_AID++)
        {
          if(stMFInfo[iCnt_Matchfile].iAID_5[iCnt_AID] == -1) // no entry
            continue;

          // Should we react on this AlertID?
          if(_mice_mod_pop_act_generic_iDebug == TRUE+TRUE+TRUE)
          {
            log_mesg(WARN, "mice_mod_pop_act_generic: Cnt = %d | Index = %d ", iCnt_AID, stMFInfo[iCnt_Matchfile].iAID_6[iCnt_AID]);
            log_mesg(WARN, "mice_mod_pop_act_generic: RID 6: %s", stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_6[iCnt_AID]]);
          }

          if( !strcasecmp(IDMEFmsg->alerts[iCnt_Alert]->classifications[iCnt_Classification]->name, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_6[iCnt_AID]]) )
            _mice_mod_pop_act_generic_ProcessReaction(cData, RID_6, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_6[iCnt_AID]], stMFInfo[iCnt_Matchfile].sAIDDescList[stMFInfo[iCnt_Matchfile].iAID_6[iCnt_AID]]);
        }

        // Check for RID 7
        for(iCnt_AID = 0; iCnt_AID <= stMFInfo[iCnt_Matchfile].AID_7Entries; iCnt_AID++)
        {
          if(stMFInfo[iCnt_Matchfile].iAID_6[iCnt_AID] == -1) // no entry
            continue;

          // Should we react on this AlertID?
          if(_mice_mod_pop_act_generic_iDebug == TRUE+TRUE+TRUE)
          {
            log_mesg(WARN, "mice_mod_pop_act_generic: Cnt = %d | Index = %d ", iCnt_AID, stMFInfo[iCnt_Matchfile].iAID_7[iCnt_AID]);
            log_mesg(WARN, "mice_mod_pop_act_generic: RID 7: %s", stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_7[iCnt_AID]]);
          }

          if( !strcasecmp(IDMEFmsg->alerts[iCnt_Alert]->classifications[iCnt_Classification]->name, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_7[iCnt_AID]]) )
            _mice_mod_pop_act_generic_ProcessReaction(cData, RID_7, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_7[iCnt_AID]], stMFInfo[iCnt_Matchfile].sAIDDescList[stMFInfo[iCnt_Matchfile].iAID_7[iCnt_AID]]);
        }

        // Check for RID 8
        for(iCnt_AID = 0; iCnt_AID <= stMFInfo[iCnt_Matchfile].AID_8Entries; iCnt_AID++)
        {
          if(stMFInfo[iCnt_Matchfile].iAID_8[iCnt_AID] == -1) // no entry
            continue;

          // Should we react on this AlertID?
          if(_mice_mod_pop_act_generic_iDebug == TRUE+TRUE+TRUE)
          {
            log_mesg(WARN, "mice_mod_pop_act_generic: Cnt = %d | Index = %d ", iCnt_AID, stMFInfo[iCnt_Matchfile].iAID_8[iCnt_AID]);
            log_mesg(WARN, "mice_mod_pop_act_generic: RID 8: %s", stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_8[iCnt_AID]]);
          }

          if( !strcasecmp(IDMEFmsg->alerts[iCnt_Alert]->classifications[iCnt_Classification]->name, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_8[iCnt_AID]]) )
            _mice_mod_pop_act_generic_ProcessReaction(cData, RID_8, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_8[iCnt_AID]], stMFInfo[iCnt_Matchfile].sAIDDescList[stMFInfo[iCnt_Matchfile].iAID_8[iCnt_AID]]);
        }

        // Check for RID 9
        for(iCnt_AID = 0; iCnt_AID <= stMFInfo[iCnt_Matchfile].AID_9Entries; iCnt_AID++)
        {
          if(stMFInfo[iCnt_Matchfile].iAID_9[iCnt_AID] == -1) // no entry
            continue;

          // Should we react on this AlertID?
          if(_mice_mod_pop_act_generic_iDebug == TRUE+TRUE+TRUE)
          {
            log_mesg(WARN, "mice_mod_pop_act_generic: Cnt = %d | Index = %d ", iCnt_AID, stMFInfo[iCnt_Matchfile].iAID_9[iCnt_AID]);
            log_mesg(WARN, "mice_mod_pop_act_generic: RID 9: %s", stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_9[iCnt_AID]]);
          }

          if( !strcasecmp(IDMEFmsg->alerts[iCnt_Alert]->classifications[iCnt_Classification]->name, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_9[iCnt_AID]]) )
            _mice_mod_pop_act_generic_ProcessReaction(cData, RID_9, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_9[iCnt_AID]], stMFInfo[iCnt_Matchfile].sAIDDescList[stMFInfo[iCnt_Matchfile].iAID_9[iCnt_AID]]);
        }

        // Check for RID 10
        for(iCnt_AID = 0; iCnt_AID <= stMFInfo[iCnt_Matchfile].AID_10Entries; iCnt_AID++)
        {
          if(stMFInfo[iCnt_Matchfile].iAID_10[iCnt_AID] == -1) // no entry
            continue;

          // Should we react on this AlertID?
          if(_mice_mod_pop_act_generic_iDebug == TRUE+TRUE+TRUE)
          {
            log_mesg(WARN, "mice_mod_pop_act_generic: Cnt = %d | Index = %d ", iCnt_AID, stMFInfo[iCnt_Matchfile].iAID_10[iCnt_AID]);
            log_mesg(WARN, "mice_mod_pop_act_generic: RID 10: %s", stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_10[iCnt_AID]]);
          }

          if( !strcasecmp(IDMEFmsg->alerts[iCnt_Alert]->classifications[iCnt_Classification]->name, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_10[iCnt_AID]]) )
            _mice_mod_pop_act_generic_ProcessReaction(cData, RID_10, stMFInfo[iCnt_Matchfile].sAIDValList[stMFInfo[iCnt_Matchfile].iAID_10[iCnt_AID]], stMFInfo[iCnt_Matchfile].sAIDDescList[stMFInfo[iCnt_Matchfile].iAID_10[iCnt_AID]]);
        }
      }
    }
  }

  free_message(IDMEFmsg);
  return(0);
}



/*
** Close
*/
int mice_mod_pop_act_generic_LTX_close(void)
{
  // libidmef
  clearCurrentDoc();

  // XXX: free memory :-(

  return(0);
}



/**************************************************************************************
**
** private Sub Routines
**
**************************************************************************************/


int _mice_mod_pop_act_generic_ProcessReaction (char *cIDMEFmsg, int iRID, char *cAID, char *cAIDDesc)
{
  char          *cRIDfifo;

  int           iRIDfd;

  RIDMsgFormat  RIDmsg;


  if(_mice_mod_pop_act_generic_iDebug)
    log_mesg(WARN, "mice_mod_pop_act_generic: Process AID %s for RID %d with Desc = %s", cAID, iRID, cAIDDesc);

  if(iRID > RidPipeEntries+1)
  {
    log_mesg(WARN, "mice_mod_pop_act_generic: Error: RID (%d) is bigger then RidPipeEntries (%d)", iRID, RidPipeEntries);
    return(-1);
  }

  if(iRID < 1)
  {
    log_mesg(WARN, "mice_mod_pop_act_generic: Error: RID (%d) is too small", iRID, RidPipeEntries);
    return(-1);
  }

  // XXX Lengthcheck and give warning if exeeded

  /*
  ** Build Reaction Message
  */
  memcpy(RIDmsg.cIdmefMsg     , cIDMEFmsg , MAX_IDMEFMSGSIZE);
  memcpy(RIDmsg.cAlertID      , cAID      , RIDMSG_MAX_ALERTID);
  memcpy(RIDmsg.cAlertIDDesc  , cAIDDesc  , RIDMSG_MAX_ALERTDESC);
  RIDmsg.iRID = iRID;


  /*
  ** Write Reaction Message to corresponding FIFO
  */
  cRIDfifo = stRidPipe[iRID-1].cPipe;

  // XXX should we open it in the ini phase?

  if(_mice_mod_pop_act_generic_iDebug)
    log_mesg(WARN, "mice_mod_pop_act_generic: open FIFO %s", cRIDfifo);

  if( (iRIDfd = open(cRIDfifo, O_WRONLY)) < 0)
  {
    log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while opening FIFO '%s' | Syserror", cRIDfifo);
    return(-10);
  }

  if(_mice_mod_pop_act_generic_iDebug)
    log_mesg(WARN, "mice_mod_pop_act_generic: write to FIFO %s", cRIDfifo);

  if(write(iRIDfd, (char *) &RIDmsg, sizeof(RIDMsgFormat)) < 0)
  {
    log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while writing to FIFO '%s' | Syserror", cRIDfifo);
    close(iRIDfd);
    return(-11);
  }

  close(iRIDfd);
  return(0);
}


/*
** Read Config File and set global Var.s
*/
int _mice_mod_pop_act_generic_HandleConfFile(char *cConfFile)
{
  int               iCfgCount;
  int               iCnt;
  struct stat       StatBuf;


  _mice_mod_pop_act_generic_CfgRID.iSectionNr   = -1;
  _mice_mod_pop_act_generic_CfgPipe.iSectionNr  = -1;
  _mice_mod_pop_act_generic_CfgAnaID.iSectionNr = -1;
  _mice_mod_pop_act_generic_CfgAnaMF.iSectionNr = -1;
  _mice_mod_pop_act_generic_CfgIdmef.iSectionNr = -1;
  _mice_mod_pop_act_generic_CfgMisc.iSectionNr  = -1;


  if(lstat(cConfFile, &StatBuf) < 0)
  {
    log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while trying lstat(%s) | Syserror", cConfFile);
    return(-1);
  }

  if((iCfgCount = cfgParse(cConfFile, _mice_mod_pop_act_generic_CfgIni, CFG_INI)) < 0)
  {
    log_mesg(WARN, "mice_mod_pop_act_generic: Error while parsing Config File %s\n", cConfFile);
    return(-2);
  }

  if(iCfgCount != SECT_MAXSECT)
  {
    log_mesg(WARN, "mice_mod_pop_act_generic: Error while parsing Config File %s | Sections Read: %d | Sections Expect: %d", cConfFile, iCfgCount, SECT_MAXSECT);
    return(-3);
  }

  for(iCnt = 0; iCnt < iCfgCount; iCnt++)
  {
    if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_RID))
      _mice_mod_pop_act_generic_CfgRID.iSectionNr  = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_PIPE))
      _mice_mod_pop_act_generic_CfgPipe.iSectionNr = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_ANAID))
      _mice_mod_pop_act_generic_CfgAnaID.iSectionNr      = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_MATCH))
      _mice_mod_pop_act_generic_CfgAnaMF.iSectionNr      = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_IDMEF))
      _mice_mod_pop_act_generic_CfgIdmef.iSectionNr      = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_MISC))
      _mice_mod_pop_act_generic_CfgMisc.iSectionNr     = iCnt;
    else
    {
      log_mesg(WARN, "mice_mod_pop_act_generic: Error in Config File %s | Unknown Section: %s", cConfFile, cfgSectionNumberToName(iCnt));
      return(-4);
    }
  }

  if( _mice_mod_pop_act_generic_CfgRID.iSectionNr == -1   || _mice_mod_pop_act_generic_CfgPipe.iSectionNr == -1   || _mice_mod_pop_act_generic_CfgAnaID.iSectionNr == -1 ||
      _mice_mod_pop_act_generic_CfgAnaMF.iSectionNr == -1 || _mice_mod_pop_act_generic_CfgIdmef.iSectionNr == -1  || _mice_mod_pop_act_generic_CfgMisc.iSectionNr == -1
    )
  {
    log_mesg(WARN, "mice_mod_pop_act_generic: Error in Config File %s, Section is missing!\n", cConfFile);
    return(-5);
  }

  return(0);
}

/*
** Read Match File and set global Var.s
*/
int _mice_mod_pop_act_generic_ParseMatchFile(char *cMatchFile)
{
  int               iCfgCount;
  int               iCnt;
  struct stat       StatBuf;


  _mice_mod_pop_act_generic_MfAID.iSectionNr    = -1;
  _mice_mod_pop_act_generic_MfDesc.iSectionNr   = -1;
  _mice_mod_pop_act_generic_MfRID_1.iSectionNr  = -1;
  _mice_mod_pop_act_generic_MfRID_2.iSectionNr  = -1;
  _mice_mod_pop_act_generic_MfRID_3.iSectionNr  = -1;
  _mice_mod_pop_act_generic_MfRID_4.iSectionNr  = -1;
  _mice_mod_pop_act_generic_MfRID_5.iSectionNr  = -1;
  _mice_mod_pop_act_generic_MfRID_6.iSectionNr  = -1;
  _mice_mod_pop_act_generic_MfRID_7.iSectionNr  = -1;
  _mice_mod_pop_act_generic_MfRID_8.iSectionNr  = -1;
  _mice_mod_pop_act_generic_MfRID_9.iSectionNr  = -1;
  _mice_mod_pop_act_generic_MfRID_10.iSectionNr = -1;


  if(lstat(cMatchFile, &StatBuf) < 0)
  {
    log_mesg(WARN_SYS, "mice_mod_pop_act_generic: Error while trying lstat(%s) | Syserror", cMatchFile);
    return(-1);
  }

  if((iCfgCount = cfgParse(cMatchFile, _mice_mod_pop_act_generic_MfIni, CFG_INI)) < 0)
  {
    log_mesg(WARN, "mice_mod_pop_act_generic: Error while parsing Match File %s\n", cMatchFile);
    return(-2);
  }

  if(iCfgCount != SECT_MF_MAXSECT)
  {
    log_mesg(WARN, "mice_mod_pop_act_generic: Error while parsing Match File %s | Sections Read: %d | Sections Expect: %d", cMatchFile, iCfgCount, SECT_MAXSECT);
    return(-3);
  }

  for(iCnt = 0; iCnt < iCfgCount; iCnt++)
  {
    if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_MF_AID))
      _mice_mod_pop_act_generic_MfAID.iSectionNr    = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_MF_DESC))
      _mice_mod_pop_act_generic_MfDesc.iSectionNr   = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_MF_RID1))
      _mice_mod_pop_act_generic_MfRID_1.iSectionNr  = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_MF_RID2))
      _mice_mod_pop_act_generic_MfRID_2.iSectionNr  = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_MF_RID3))
      _mice_mod_pop_act_generic_MfRID_3.iSectionNr  = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_MF_RID4))
      _mice_mod_pop_act_generic_MfRID_4.iSectionNr  = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_MF_RID5))
      _mice_mod_pop_act_generic_MfRID_5.iSectionNr  = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_MF_RID6))
      _mice_mod_pop_act_generic_MfRID_6.iSectionNr  = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_MF_RID7))
      _mice_mod_pop_act_generic_MfRID_7.iSectionNr  = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_MF_RID8))
      _mice_mod_pop_act_generic_MfRID_8.iSectionNr  = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_MF_RID9))
      _mice_mod_pop_act_generic_MfRID_9.iSectionNr  = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_MF_RID10))
      _mice_mod_pop_act_generic_MfRID_10.iSectionNr  = iCnt;
    else
    {
      log_mesg(WARN, "mice_mod_pop_act_generic: Error in Match File %s | Unknown Section: %s", cMatchFile, cfgSectionNumberToName(iCnt));
      return(-4);
    }
  }

  if( _mice_mod_pop_act_generic_MfAID.iSectionNr == -1    || _mice_mod_pop_act_generic_MfDesc.iSectionNr == -1  || _mice_mod_pop_act_generic_MfRID_1.iSectionNr == -1   ||
      _mice_mod_pop_act_generic_MfRID_2.iSectionNr == -1  || _mice_mod_pop_act_generic_MfRID_3.iSectionNr == -1 || _mice_mod_pop_act_generic_MfRID_4.iSectionNr == -1   ||
      _mice_mod_pop_act_generic_MfRID_5.iSectionNr == -1  || _mice_mod_pop_act_generic_MfRID_6.iSectionNr == -1 || _mice_mod_pop_act_generic_MfRID_7.iSectionNr == -1   ||
      _mice_mod_pop_act_generic_MfRID_8.iSectionNr == -1  || _mice_mod_pop_act_generic_MfRID_9.iSectionNr == -1 || _mice_mod_pop_act_generic_MfRID_10.iSectionNr == -1
    )
  {
    log_mesg(WARN, "mice_mod_pop_act_generic: Error in Match File %s, Section is missing!\n", cMatchFile);
    return(-5);
  }

  return(0);
}

