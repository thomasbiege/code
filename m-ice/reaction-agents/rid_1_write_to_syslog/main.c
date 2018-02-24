#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>

/*
** Get LibIDMEF from http://www.silicondefense.com/idwg/index.htm
*/
#include <libidmef/idmefxml.h>
#include <libidmef/idmefxml_parse.h>

#include <libxml/xmlversion.h>

#include <mice.h>
#include "rid-mesg-format.h"
#include "parsecfg.h"


#define TRUE              1
#define FALSE             0

#define CONFFILE         "/etc/M-ICE/rid_1_write_to_syslog.conf"

#define SECT_PIPE         "PIPE_NAME"
#define SECT_MAXSECT      1

struct
{
  int     iSectionNr;
  char    **cPipe;
} CfgPipe;


cfgStruct CfgIni[] =
{
  // Pipe Name
  {"PIPE"         ,CFG_STRING       ,&CfgPipe.cPipe },

  // The End
  {NULL           ,CFG_END          ,NULL           }
};



int HandleConfFile(char *cConfFile);

int main(void)
{
  FILE          *streamFifo;
  RIDMsgFormat  RIDmsg;


  log_open("rid_1_write_to_syslog", LOG_PID, LOG_NOTICE);

  if(HandleConfFile(CONFFILE) < 0)
    log_mesg(FATAL, "M-ICE Syslog: Error while parsing Config File");

  if( (streamFifo = fopen(CfgPipe.cPipe[CfgPipe.iSectionNr], "r")) == NULL)
    log_mesg(FATAL, "M-ICE Syslog: Error while opening FIFO '%s'", CfgPipe.cPipe[CfgPipe.iSectionNr]);

  while(TRUE)
  {
    clearerr(streamFifo);
    if(fread((char *) &RIDmsg, sizeof(RIDMsgFormat), 1, streamFifo) != 1)
    {
      if(ferror(streamFifo))
        log_mesg(WARN_SYS, "M-ICE Syslog: Error while reading from FIFO | Syserror");

      sleep(2);
      continue;
    }

    log_mesg(WARN, "M-ICE Syslog: AlertID = %s | AlertID Description = %s", RIDmsg.cAlertID, RIDmsg.cAlertIDDesc);
  }

  exit(0);
}

/*
** Read Config File and set global Var.s
*/
int HandleConfFile(char *cConfFile)
{
  int               iCfgCount;
  int               iCnt;
  struct stat       StatBuf;


  CfgPipe.iSectionNr  = -1;


  if(lstat(cConfFile, &StatBuf) < 0)
  {
    log_mesg(WARN_SYS, "M-ICE Syslog: Error while trying lstat(%s) | Syserror", cConfFile);
    return(-1);
  }

  if((iCfgCount = cfgParse(cConfFile, CfgIni, CFG_INI)) < 0)
  {
    log_mesg(WARN, "M-ICE Syslog: Error while parsing Config File %s\n", cConfFile);
    return(-2);
  }

  if(iCfgCount != SECT_MAXSECT)
  {
    log_mesg(WARN, "M-ICE Syslog: Error while parsing Config File %s | Sections Read: %d | Sections Expect: %d", cConfFile, iCfgCount, SECT_MAXSECT);
    return(-3);
  }

  for(iCnt = 0; iCnt < iCfgCount; iCnt++)
  {
    if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_PIPE))
      CfgPipe.iSectionNr = iCnt;
    else
    {
      log_mesg(WARN, "M-ICE Syslog: Error in Config File %s | Unknown Section: %s", cConfFile, cfgSectionNumberToName(iCnt));
      return(-4);
    }
  }

  if(CfgPipe.iSectionNr == -1)
  {
    log_mesg(WARN, "M-ICE Syslog: Error in Config File %s, Section is missing!\n", cConfFile);
    return(-5);
  }

  return(0);
}
