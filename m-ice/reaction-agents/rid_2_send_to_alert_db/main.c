#include <stdio.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <mysql/mysql.h>

#include <libidmef/idmefxml.h>
#include <libidmef/idmefxml_parse.h>

#include <libxml/xmlversion.h>

#include <mice.h>
#include "rid-mesg-format.h"
#include "parsecfg.h"


#define TRUE              1
#define FALSE             0


// Config
#define CONFFILE         "/etc/M-ICE/rid_2_send_to_alert_db.conf"

#define SECT_PIPE         "PIPE_NAME"
#define SECT_SQL          "MYSQL_SERVER"
#define SECT_MAXSECT      2

struct
{
  int     iSectionNr;
  char    **cPipe;
} CfgPipe;

struct
{
  int     iSectionNr;
  char    **cHostname;
  int     *iPort;
  char    **cUser;
  char    **cPassword;
  char    **cDBName;
  int     *iMaxErr;
} CfgSQL;


cfgStruct CfgIni[] =
{
  // Pipe Name
  {"PIPE"         ,CFG_STRING      ,&CfgPipe.cPipe    },

  // MySQL Server Section
  {"HOSTNAME"     ,CFG_STRING      ,&CfgSQL.cHostname },
  {"PORT"         ,CFG_INT         ,&CfgSQL.iPort     },
  {"USER"         ,CFG_STRING      ,&CfgSQL.cUser     },
  {"PASSWORD"     ,CFG_STRING      ,&CfgSQL.cPassword },
  {"DBNAME"       ,CFG_STRING      ,&CfgSQL.cDBName   },
  {"MAXERR"       ,CFG_INT         ,&CfgSQL.iMaxErr   },

  // The End
  {NULL           ,CFG_END         ,NULL              }
};


MYSQL *mysqlSock;
u_int uiMaxErrCnt = 0;

char *cQueryFormat = "INSERT INTO alert_entry (alertid, alertdesc, classification, date, time, analyzerid, " \
                     "source_address, source_user, source_process, source_service, target_address, target_user, target_process, target_service, " \
                     "idmefmsg, signature) "\
                     "VALUES ('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s')";

int HandleConfFile(char *cConfFile);


/*
** MAIN
*/
int main(void)
{
  char          cQuery[16*1024] = {0},
                cQuotedIdmefMsg[2*MAX_IDMEFMSGSIZE+1] = {0},
                cDate[30] = {0},
                cTime[30] = {0};

  u_int         uiQuotedIdmefMsgLen;

  FILE          *streamFifo;

  time_t        Time;

  struct tm     *TimePtr;

  RIDMsgFormat  RIDmsg;

  IDMEFmessage  *IDMEFmsg;



  if(HandleConfFile(CONFFILE) < 0)
    log_mesg(FATAL, "M-ICE AlertDB: Error while parsing Config File");

  if( (streamFifo = fopen(CfgPipe.cPipe[CfgPipe.iSectionNr], "r")) == NULL)
    log_mesg(FATAL, "M-ICE AlertDB: Error while opening FIFO '%s'", CfgPipe.cPipe);


  /*
  ** Initialization function for the XML parser. This is not reentrant.
  ** Call once before processing in case of use in multithreaded programs
  */
  //xmlInitParser();


  // Connect to MySQL Server
  if( (mysqlSock = mysql_init(NULL)) == NULL)
    log_mesg(FATAL, "M-ICE AlertDB: Error: Connection to MySQL Server [%s:%d] Database '%s' failed\n", CfgSQL.cHostname[CfgSQL.iSectionNr], CfgSQL.iPort[CfgSQL.iSectionNr], CfgSQL.cDBName[CfgSQL.iSectionNr]);

  if(mysql_real_connect(mysqlSock, CfgSQL.cHostname[CfgSQL.iSectionNr], CfgSQL.cUser[CfgSQL.iSectionNr], CfgSQL.cPassword[CfgSQL.iSectionNr], CfgSQL.cDBName[CfgSQL.iSectionNr], CfgSQL.iPort[CfgSQL.iSectionNr], NULL, 0) == 0)
  {
    if(mysql_errno(mysqlSock))
      log_mesg(FATAL, "M-ICE AlertDB: Error: mysql_real_connect() | MySQL_Error: %s\n", mysql_error(mysqlSock));

    log_mesg(FATAL, "M-ICE AlertDB: Error: Failed to logon to Database '%s'\n", CfgSQL.cDBName[CfgSQL.iSectionNr]);
  }

  // Read an Process Data
  uiMaxErrCnt = 0;

  while(TRUE)
  {
    clearerr(streamFifo);
    if(fread((char *) &RIDmsg, sizeof(RIDMsgFormat), 1, streamFifo) != 1)
    {
      if(ferror(streamFifo))
      {
        log_mesg(WARN_SYS, "M-ICE AlertDB: Error while reading from FIFO | Syserror");

        //uiMaxErrCnt++;
        //if(uiMaxErrCnt >= CfgSQL.iMaxErr[CfgSQL.iSectionNr])
          //log_mesg(FATAL, "M-ICE AlertDB: MAXERR Cnt. reached!");
      }

      sleep(2);
      continue;
    }


    if(uiMaxErrCnt >= CfgSQL.iMaxErr[CfgSQL.iSectionNr])
    {
      log_mesg(WARN, "M-ICE AlertDB: MAXERR Cnt. reached!");
      break;
    }


    // Security Checks: only for untrusted data: AdditionalData Class free(!!!) nicht vergessen
    uiQuotedIdmefMsgLen = mysql_real_escape_string(mysqlSock, cQuotedIdmefMsg, RIDmsg.cIdmefMsg, (u_int) strlen(RIDmsg.cIdmefMsg));
    //memcpy(cQuotedIdmefMsg, RIDmsg.cIdmefMsg, sizeof(cQuotedIdmefMsg)-1);
    //uiQuotedIdmefMsgLen = strlen(cQuotedIdmefMsg);

    if(uiQuotedIdmefMsgLen > strlen(RIDmsg.cIdmefMsg))
      log_mesg(WARN, "M-ICE AlertDB: IMPORTANT WARNING! The IDMEF Message includes SQL Commands, that could be an Attack! All dangerous Commands have been quoted to allow Secure Logging in the MySQL Database.");

    // The Log Line becames too long
    if(uiQuotedIdmefMsgLen > sizeof(cQuery) - strlen(cQueryFormat - (sizeof(RIDMsgFormat)-sizeof(RIDmsg.cIdmefMsg))))
      log_mesg(WARN, "M-ICE AlertDB: IMPORTANT WARNING! The quoted IDMEF MEssage is too long to send it to the MySQL Server. The String will be truncated!\n");


    // Parse IDMEF Message
    IDMEFmsg = 0;
    if( (IDMEFmsg = get_idmef_message(RIDmsg.cIdmefMsg, strlen(RIDmsg.cIdmefMsg))) == 0)
    {
      log_mesg(WARN, "M-ICE AlertDB: Error while generating IDMEF Message! Skipping Reaction Message!!!\n");
      continue;
    }


    if(time(&Time) == ((time_t)-1))
    {
      log_mesg(WARN, "M-ICE AlertDB: Error while calling time(2)\n");
      strncpy(cDate, "ERROR", sizeof(cDate)-1);
      strncpy(cTime, "ERROR", sizeof(cTime)-1);
    }
    else
    {
      char dummy[10];
      TimePtr = localtime(&Time);
      if(TimePtr->tm_year < 100)
        snprintf(dummy, sizeof(dummy), "19%d", TimePtr->tm_year);
      else // XXX: we just handle years < 21XX hope it's enough ;)
        snprintf(dummy, sizeof(dummy), "20%02d", TimePtr->tm_year-100);

      snprintf(cDate, sizeof(cDate), "%s/%02d/%02d", dummy, TimePtr->tm_mon+1, TimePtr->tm_mday);
      snprintf(cTime, sizeof(cTime), "%02d:%02d:%02d", TimePtr->tm_hour, TimePtr->tm_min, TimePtr->tm_sec);
    }


    // Replace empty Entries in IDMEF Message
    // XXX Could cause SEGV due to missing SubClasses
    /*
    if(IDMEFmsg->alerts[0]->classifications[0]->name == NULL)
      IDMEFmsg->alerts[0]->classifications[0]->name = "UNKNOWN\0";

    if(IDMEFmsg->alerts[0]->analyzer->analyzerid == NULL)
      IDMEFmsg->alerts[0]->analyzer->analyzerid = "UNKNOWN\0";

    if(IDMEFmsg->alerts[0]->sources[0]->node->addresses[0]->address == NULL)
      IDMEFmsg->alerts[0]->sources[0]->node->addresses[0]->address = "UNKNOWN\0";

    if(IDMEFmsg->alerts[0]->sources[0]->user->userids[0]->name == NULL)
      IDMEFmsg->alerts[0]->sources[0]->user->userids[0]->name = "UNKNOWN\0";

    if(IDMEFmsg->alerts[0]->sources[0]->process->name == NULL)
      IDMEFmsg->alerts[0]->sources[0]->process->name = "UNKNOWN\0";

    if(IDMEFmsg->alerts[0]->sources[0]->service->name == NULL)
      IDMEFmsg->alerts[0]->sources[0]->service->name = "UNKNOWN\0";

    if(IDMEFmsg->alerts[0]->targets[0]->node->addresses[0]->address == NULL)
      IDMEFmsg->alerts[0]->targets[0]->node->addresses[0]->address = "UNKNOWN\0";

    if(IDMEFmsg->alerts[0]->targets[0]->user->userids[0]->name == NULL)
      IDMEFmsg->alerts[0]->targets[0]->user->userids[0]->name = "UNKNOWN\0";

    if(IDMEFmsg->alerts[0]->targets[0]->process->name == NULL)
      IDMEFmsg->alerts[0]->targets[0]->process->name = "UNKNOWN\0";

    if(IDMEFmsg->alerts[0]->targets[0]->service->name == NULL)
      IDMEFmsg->alerts[0]->targets[0]->service->name = "UNKNOWN\0";
    */

    // Build MYSQL Query and send it away.
    snprintf(cQuery, sizeof(cQuery), cQueryFormat, RIDmsg.cAlertID
                                                 , RIDmsg.cAlertIDDesc
                                                 , IDMEFmsg->alerts[0]->classifications[0]->name
                                                 , cDate
                                                 , cTime
                                                 , IDMEFmsg->alerts[0]->analyzer->analyzerid
                                                 , IDMEFmsg->alerts[0]->sources[0]->node->addresses[0]->address
                                                 , IDMEFmsg->alerts[0]->sources[0]->user->userids[0]->name
                                                 , IDMEFmsg->alerts[0]->sources[0]->process->name
                                                 , IDMEFmsg->alerts[0]->sources[0]->service->name
                                                 , IDMEFmsg->alerts[0]->targets[0]->node->addresses[0]->address
                                                 , IDMEFmsg->alerts[0]->targets[0]->user->userids[0]->name
                                                 , IDMEFmsg->alerts[0]->targets[0]->process->name
                                                 , IDMEFmsg->alerts[0]->targets[0]->service->name
                                                 , cQuotedIdmefMsg
                                                 , "not supported" );


    log_mesg(WARN, "M-ICE AlertDB: Send MYSQL Query\n");
    if(mysql_query(mysqlSock, cQuery))
    {
      uiMaxErrCnt++;
      log_mesg(WARN, "M-ICE AlertDB: Error: mysql_query(%s) | MySQL_Error: %s\n", cQuery, mysql_error(mysqlSock));
    }

    if(uiMaxErrCnt > 0)
      uiMaxErrCnt--;

    free_message(IDMEFmsg);
    memset((char *) &RIDmsg, 0, sizeof(RIDmsg));
  }


  mysql_close(mysqlSock);
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
  CfgSQL.iSectionNr   = -1;


  if(lstat(cConfFile, &StatBuf) < 0)
  {
    log_mesg(WARN_SYS, "M-ICE AlertDB: Error while trying lstat(%s) | Syserror", cConfFile);
    return(-1);
  }

  if((iCfgCount = cfgParse(cConfFile, CfgIni, CFG_INI)) < 0)
  {
    log_mesg(WARN, "M-ICE AlertDB: Error while parsing Config File %s\n", cConfFile);
    return(-2);
  }

  if(iCfgCount != SECT_MAXSECT)
  {
    log_mesg(WARN, "M-ICE AlertDB: Error while parsing Config File %s | Sections Read: %d | Sections Expect: %d", cConfFile, iCfgCount, SECT_MAXSECT);
    return(-3);
  }

  for(iCnt = 0; iCnt < iCfgCount; iCnt++)
  {
    if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_PIPE))
      CfgPipe.iSectionNr = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_SQL))
      CfgSQL.iSectionNr = iCnt;
    else
    {
      log_mesg(WARN, "M-ICE AlertDB: Error in Config File %s | Unknown Section: %s", cConfFile, cfgSectionNumberToName(iCnt));
      return(-4);
    }
  }

  if(CfgPipe.iSectionNr == -1 || CfgSQL.iSectionNr == -1)
  {
    log_mesg(WARN, "M-ICE AlertDB: Error in Config File %s, Section is missing!\n", cConfFile);
    return(-5);
  }

  return(0);
}
