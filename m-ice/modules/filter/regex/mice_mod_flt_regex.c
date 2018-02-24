/***************************************************************************
                          mice_mod_flt_regex.c  -  description
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

#include "mice_mod_flt_regex.h"



/*
** RegEx stuff
*/
struct re_pattern_buffer    *_mice_mod_flt_regex_RegExBuf = NULL;


/*
** Configure Stuff
*/
cfgList    **_mice_mod_flt_regex_CfgRules;

int          _mice_mod_flt_regex_iSectFilterRules;

cfgStruct    _mice_mod_flt_regex_CfgIni[] =
{
  // Filter Rule Section
  {"RULE"     ,CFG_STRING_LIST  ,&_mice_mod_flt_regex_CfgRules       },
  {NULL       ,CFG_END          ,NULL                 }
};


/*
** Function Declaration
*/
int    _mice_mod_flt_regex_HandleConfFile(char *cConfFile);


/*
** Module Functions
*/
int mice_mod_flt_regex_LTX_init(char *ConfFile)
{
  //log_open("mice_mod_flt_regex", LOG_PID, LOG_USER);


  if(_mice_mod_flt_regex_HandleConfFile(ConfFile) < 0)
    return(-1);

  re_syntax_options=RE_SYNTAX_POSIX_EGREP;

  if(_mice_mod_flt_regex_RegExBuf != NULL)
    mice_mod_flt_regex_LTX_close();

  if((_mice_mod_flt_regex_RegExBuf = (struct re_pattern_buffer *) malloc(sizeof(struct re_pattern_buffer))) == NULL)
  {
    log_mesg(WARN_SYS, "mice_mod_flt_regex: Error while allocating Memory for _mice_mod_flt_regex_RegExBuf | Syserror");
    return(-2);
  }

  if((_mice_mod_flt_regex_RegExBuf->fastmap = (char *) malloc(FASTMAPSIZE)) == NULL)
  {
    log_mesg(WARN_SYS, "mice_mod_flt_regex: Error while allocating Memory for _mice_mod_flt_regex_RegExBuf->fastmap | Syserror");
    return(-3);
  }

  _mice_mod_flt_regex_RegExBuf->translate = (char *) 0;
  _mice_mod_flt_regex_RegExBuf->buffer    = NULL;
  _mice_mod_flt_regex_RegExBuf->allocated = 0;

  return(0);
}


int mice_mod_flt_regex_LTX_func(LogFormat *LogFmt, u_int uiFileType)
{
  cfgList *TmpList;
  

  if(uiFileType != FTF_FILE)
  {
    log_mesg(WARN, "mice_mod_flt_regex: Warning: Can not filter non-ascii data\n");
    return(-1);
  }
  
  if(_mice_mod_flt_regex_iSectFilterRules != (SECT_MAXSECT-1))
  {
    log_mesg(WARN, "mice_mod_flt_regex: Error! You have to call mice_mod_flt_regex_LTX_init() first!\n");
    return(-1);
  }

  for(TmpList = _mice_mod_flt_regex_CfgRules[_mice_mod_flt_regex_iSectFilterRules]; TmpList != NULL; TmpList = TmpList->next)
  {
    if(re_compile_pattern(TmpList->str, strlen(TmpList->str), _mice_mod_flt_regex_RegExBuf) != 0 )
    {
      log_mesg(WARN, "mice_mod_flt_regex: Error while compiling Regular Expression '%s'. Skipped...\n", TmpList->str);
      continue;
    }

    _mice_mod_flt_regex_RegExBuf->regs_allocated = REGS_FIXED;

    if(re_match(_mice_mod_flt_regex_RegExBuf, LogFmt->cLogdata, strlen(LogFmt->cLogdata), 0, NULL) >= 0)
      break;
  }

  if(TmpList != NULL)
  {
    /*
    ** We find a matching Pattern.
    ** Let's skip this Logentry, because it the User wants to filter it out.
    */
    return(1);
  }

  return(0);
}

/* not used, but anyway... ;-) */
int mice_mod_flt_regex_LTX_close(void)
{
  free(_mice_mod_flt_regex_RegExBuf->fastmap);
  free(_mice_mod_flt_regex_RegExBuf);

  return(0);
}



/*
** Handle Config File
*/
int _mice_mod_flt_regex_HandleConfFile(char *cConfFile)
{
  int             iCfgCount;
  int             iCnt;
  struct stat     StatBuf;

  _mice_mod_flt_regex_iSectFilterRules = -1;

  if(lstat(cConfFile, &StatBuf) < 0)
  {
    log_mesg(WARN_SYS, "mice_mod_flt_regex: Error while trying lstat(%s) | Syserror", cConfFile);
    return(-1);
  }

  if((iCfgCount = cfgParse(cConfFile, _mice_mod_flt_regex_CfgIni, CFG_INI)) < 0)
  {
    log_mesg(WARN, "mice_mod_flt_regex: Error while parsing Config File %s\n", cConfFile);
    return(-2);
  }

  if(iCfgCount != SECT_MAXSECT)
  {
    log_mesg(WARN, "mice_mod_flt_regex: Error while parsing Config File %s | Sections Read: %d | Sections Expect: %d", cConfFile, iCfgCount, SECT_MAXSECT);
    return(-3);
  }

  for(iCnt = 0; iCnt < iCfgCount; iCnt++)
  {
    if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_FILTER))
      _mice_mod_flt_regex_iSectFilterRules = iCnt;
    else
    {
      log_mesg(WARN, "mice_mod_flt_regex: Error in Config File %s | Unknown Section: %s", cConfFile, cfgSectionNumberToName(iCnt));
      return(-4);
    }
  }

  if(_mice_mod_flt_regex_iSectFilterRules == -1)
  {
    log_mesg(WARN, "mice_mod_flt_regex: Error in Config File %s, Section is missing!\n", cConfFile);
    return(-5);
  }

  return(0);
}

