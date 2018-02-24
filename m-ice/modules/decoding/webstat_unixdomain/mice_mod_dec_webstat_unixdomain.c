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

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <mice.h>
#include "mice_mod_dec_webstat_unixdomain.h"
#include "webstat_response_format.h"
#include "parsecfg.h"


#define TRUE              1
#define FALSE             0



int   _mice_mod_dec_webstat_unixdomain_iDebug = FALSE;

char  *_mice_mod_dec_webstat_unixdomain_cProgname;


/*
** Configure Stuff
*/
int _mice_mod_dec_webstat_unixdomain_CfgDone = FALSE;

struct
{
  int     iSectionNr;
  char    **cPath;
} _mice_mod_dec_webstat_unixdomain_CfgUDS;



cfgStruct    _mice_mod_dec_webstat_unixdomain_CfgIni[] =
{
  // Unix Domain Info
  {"PATH"       ,CFG_STRING       ,&_mice_mod_dec_webstat_unixdomain_CfgUDS.cPath },

  // The End
  {NULL         ,CFG_END          ,NULL                                           }
};



/*
** Function Declaration
*/
int _mice_mod_dec_webstat_unixdomain_HandleConfFile(char *cConfFile);



/***************************************************************************************
**
** p u b l i c   M o d u l e   F u n c t i o n s
**
***************************************************************************************/


/*
** Init
*/
size_t mice_mod_dec_webstat_unixdomain_LTX_init(char *ConfFile)
{
  _mice_mod_dec_webstat_unixdomain_cProgname = "BufferDaemon/mice_mod_dec_webstat_unixdomain";

  if(_mice_mod_dec_webstat_unixdomain_CfgDone != FALSE)
  {
    log_mesg(WARN, "mice_mod_dec_webstat_unixdomain: Do NOT call init function twice, call close function inbetween");
    return(-1);
  }

  _mice_mod_dec_webstat_unixdomain_CfgDone = TRUE;

  return(WSP_MAX_MSG); // return the max. size of bytes the caller must accept for a message
}



/*
** Main Function
*/
char *mice_mod_dec_webstat_unixdomain_LTX_func(char *cData, size_t DataSize)
{
  if(_mice_mod_dec_webstat_unixdomain_CfgDone != TRUE)
  {
    log_mesg(WARN, "mice_mod_dec_webstat_unixdomain: Error! You have to call mice_mod_dec_webstat_unixdomain_LTX_init() first!\n");
    return(NULL);
  }


  return(cData);
}



/*
** Close
*/
int mice_mod_dec_webstat_unixdomain_LTX_close(void)
{

  _mice_mod_dec_webstat_unixdomain_CfgDone = FALSE;

  return(0);
}



/*
** Read Config File and set global Var.s
*/
int _mice_mod_dec_webstat_unixdomain_HandleConfFile(char *cConfFile)
{
  int              iCfgCount;
  int              iCnt;
  struct stat      StatBuf;


  _mice_mod_dec_webstat_unixdomain_CfgUDS.iSectionNr  = -1;

  if(lstat(cConfFile, &StatBuf) < 0)
  {
    log_mesg(WARN_SYS, "mice_mod_dec_webstat_unixdomain: Error while trying lstat(%s) | Syserror", cConfFile);
    return(-1);
  }

  if((iCfgCount = cfgParse(cConfFile, _mice_mod_dec_webstat_unixdomain_CfgIni, CFG_INI)) < 0)
  {
    log_mesg(WARN, "mice_mod_dec_webstat_unixdomain: Error while parsing Config File %s\n", cConfFile);
    return(-2);
  }

  if(iCfgCount != SECT_MAXSECT)
  {
    log_mesg(WARN, "mice_mod_dec_webstat_unixdomain: Error while parsing Config File %s | Sections Read: %d | Sections Expect: %d", cConfFile, iCfgCount, SECT_MAXSECT);
    return(-3);
  }

  for(iCnt = 0; iCnt < iCfgCount; iCnt++)
  {
    if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_UDS))
      _mice_mod_dec_webstat_unixdomain_CfgUDS.iSectionNr  = iCnt;
    else
    {
      log_mesg(WARN, "mice_mod_dec_webstat_unixdomain: Error in Config File %s | Unknown Section: %s", cConfFile, cfgSectionNumberToName(iCnt));
      return(-4);
    }
  }

  if( _mice_mod_dec_webstat_unixdomain_CfgUDS.iSectionNr == -1 )
  {
    log_mesg(WARN, "mice_mod_dec_webstat_unixdomain: Error in Config File %s, Section is missing!\n", cConfFile);
    return(-5);
  }

  return(0);
}

