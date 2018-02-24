/***************************************************************************
                          mice_mod_psd_empty.c  -  description
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

#include "mice_mod_psd_empty.h"




/*
** Configure Stuff
*/
char        **_mice_mod_psd_empty_CfgDummy;

int         _mice_mod_psd_empty_iSectPseudonymizer;

cfgStruct   _mice_mod_psd_empty_CfgIni[] =
{
  {"DUMMY"      ,CFG_STRING       ,&_mice_mod_psd_empty_CfgDummy },
  {NULL         ,CFG_END          ,NULL           }
};


/*
** Function Declaration
*/
int _mice_mod_psd_empty_HandleConfFile(char *cConfFile);


/*
** Module Functions
*/
int mice_mod_psd_empty_LTX_init(char *cConfFile)
{
  //log_open("mice_mod_psd_empty", LOG_PID, LOG_USER);

  //_mice_mod_psd_empty_HandleConfFile(cConfFile);

  return(0);
}

int mice_mod_psd_empty_LTX_func(LogFormat *LogFmt, u_int uiFileType)
{
  return(0);
}

/* not used, but anyway... ;-) */
int mice_mod_psd_empty_LTX_close(void)
{
  return(0);
}



/*
** Handle Config File
*/
int _mice_mod_psd_empty_HandleConfFile(char *cConfFile)
{
  int             iCfgCount;
  int             iCnt;
  struct stat     StatBuf;

  _mice_mod_psd_empty_iSectPseudonymizer = -1;

  if(lstat(cConfFile, &StatBuf) < 0)
  {
    log_mesg(WARN_SYS, "mice_mod_psd_empty: Error while trying lstat(%s) | Syserror", cConfFile);
    return(-1);
  }

  if((iCfgCount = cfgParse(cConfFile, _mice_mod_psd_empty_CfgIni, CFG_INI)) < 0)
  {
    log_mesg(WARN, "mice_mod_psd_empty: Error while parsing Config File %s\n", cConfFile);
    return(-2);
  }

  if(iCfgCount != SECT_MAXSECT)
  {
    log_mesg(WARN, "mice_mod_psd_empty: Error while parsing Config File %s | Sections Read: %d | Sections Expect: %d", cConfFile, iCfgCount, SECT_MAXSECT);
    return(-3);
  }

  for(iCnt = 0; iCnt < iCfgCount; iCnt++)
  {
    if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_PSEUDO))
      _mice_mod_psd_empty_iSectPseudonymizer = iCnt;
    else
    {
      log_mesg(WARN, "mice_mod_psd_empty: Error in Config File %s | Unknown Section: %s", cConfFile, cfgSectionNumberToName(iCnt));
      return(-4);
    }
  }

  if(_mice_mod_psd_empty_iSectPseudonymizer == -1)
  {
    log_mesg(WARN, "mice_mod_psd_empty: Error in Config File %s, Section is missing!\n", cConfFile);
    return(-5);
  }

  return(0);
}

