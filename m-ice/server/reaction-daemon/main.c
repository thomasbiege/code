/***************************************************************************
                          main.c  -  description
                             -------------------
    copyright            : (C) 2002 by Thomas Biege
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

#define  _GNU_SOURCE    // for asprintf()
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <pthread.h>
#include <errno.h>
#include <netinet/in.h>


#include <ltdl.h>

#include <mcrypt.h>


#include <mice.h>
#include "parsecfg.h"
#include "checksum.h"
#include "reactiondaemon.h"
#include "reaction-mesg-format.h"


/*
** Defines
*/
#define REPLAYATTACK_DELAYWINDOW	((time_t) 1)
#define USAGE(id)   log_mesg(id, "usage: %s [-d] [-f <config file>]\n\n", cProgname);



typedef struct sockaddr_in  saddr_in;
typedef struct sockaddr     saddr;




/*
** Global Variables
*/
char      *cProgname;
char      cPath[PATH_MAX+NAME_MAX+1];
pid_t     MainPID;

static volatile sig_atomic_t  iDebug;

typedef struct
{
  pthread_t   TID;
  int         iCliSock;
  saddr_in    CliAddrIn;
  socklen_t   CliAddrLen;
} stCliInfo;

struct stReactionTable
{
  struct stReactionTable *prev;

  u_int             FID;

  int               iNumArg;

  char              *cModName;

  lt_dlhandle       dlHandle;
  const lt_dlinfo   *dlInfo;
  int               (*InitPtr)(char *);
  int               (*FuncPtr)(char *, size_t);
  int               (*ClosePtr)(void);

  struct stReactionTable *next;

} *RctTab;

u_int   RctTabEntries;


/*
** Configure Stuff
*/
char      *cConfFile;

struct
{
  int     iSectNr;
  cfgList **FID;
} CfgFuncID;

struct
{
  int     iSectNr;
  cfgList **Name;
} CfgRctMod;

struct
{
  int     iSectNr;
  cfgList **Name;
} CfgRctFile;

struct
{
  int     iSectNr;
  char    **IP;
  int      *Port;
} CfgNetwork;

struct
{
  int     iSectNr;
  char    **RawKey;
  char    **CryptMod;
  char    **Chroot;
} CfgSecurity;

struct
{
  int     iSectNr;
  char    **PidPath;
  char    **ModPath;
  char    **Backlog;
} CfgMisc;


cfgStruct CfgIni[] =
{
  // Function ID Section
  {"FID"            ,CFG_STRING_LIST  ,&CfgFuncID.FID         },

  // Reaction Module Section
  {"RCT_MOD"        ,CFG_STRING_LIST  ,&CfgRctMod.Name        },

  // Reaction Module Config Section
  {"RCT_FILE"       ,CFG_STRING_LIST  ,&CfgRctFile.Name       },

  // Network Section
  {"IP"             ,CFG_STRING       ,&CfgNetwork.IP         },
  {"PORT"           ,CFG_INT          ,&CfgNetwork.Port       },

  // Security Section
  {"PASSWORD"       ,CFG_STRING       ,&CfgSecurity.RawKey    },
  {"CRYPTMOD"       ,CFG_STRING       ,&CfgSecurity.CryptMod  },
  {"CHROOT"         ,CFG_STRING       ,&CfgSecurity.Chroot    },

  // Misc Section
  {"PIDPATH"        ,CFG_STRING       ,&CfgMisc.PidPath       },
  {"MODPATH"        ,CFG_STRING       ,&CfgMisc.ModPath       },
  {"BACKLOG"        ,CFG_INT          ,&CfgMisc.Backlog       },

  {NULL             ,CFG_END          ,NULL                   }
};


void  voidSigChild(int id);
void  voidSigHup(int id);
void  voidSigUsr1_2(int id);
void  voidSigTermination(int id);
void  voidCfgFatalFunc(cfgErrorCode ErrCode, const char *Str1 , int iDummy, const char *Str2);
void  voidCleanUp(void);
void  *voidHandleClientRequest(void *vArg);  // Thread

int   intInitRctTab(void);
int   intAbrakadabra(void);
int   intHandleConfFile(int Syslog);

int   intHandleExec(stExecMsg Exc);
int   intHandleShow(stShowMsg Shw);
int   intHandleCheck(stCheckMsg Chk);



/*******************************************************************
*
* M A I N
*
*******************************************************************/

int main(int argc, char *argv[])
{
  int                 iOpt,
                      iOn,
                      iSock;

  uid_t               eUID = geteuid();
  uid_t               rUID = getuid();
  gid_t               eGID = getegid();
  gid_t               rGID = getgid();

  saddr_in            SAddrIn;

  stCliInfo           CliInfo,
                      *CliInfoPtr;



  cProgname = "ReactionDaemon";  // argv[0];


  /*
  ** First let's check, that we didn't run
  ** set[gu]id, because this code was not designed to be set[gu]id
  ** and I don't like it! *eg*
  */
  if(rUID != eUID || rGID != eGID)
    err_mesg(FATAL, "%s: Do NOT run me as set[ug]id app, it's NOT neccessary and I do NOT like it! Run me as root. :-)\n", cProgname);


  /*
  ** Read Commanline Options.
  */
  cConfFile   = PATHCONFFILE;

  iDebug = 0;

  opterr = 0;
  while((iOpt = getopt(argc, argv, "f:d")) != EOF)
  {
    switch(iOpt)
    {
      case 'f':	if(optarg == NULL || optarg[0] == '-')
                USAGE(FATAL)
                if((cConfFile = strdup((const char *)optarg)) == NULL)
                  err_mesg(FATAL_SYS, "%s: strdup(CONFILE)\nSyserror", cProgname);
                break;
      case 'd': iDebug++;
                break;
      default:  USAGE(FATAL)
    }
  }


  /*
  ** Init. libltdl
  */
  if(lt_dlinit())
    err_mesg(FATAL_SYS, "%s: Error while trying to initialize libltdl\nSyserror", cProgname);


  /*
  ** Open Syslog
  */
  log_open(cProgname, LOG_PID, LOG_DAEMON); // XXX: CfgSyslogFac[iSectMisc]);


  log_mesg(WARN, "%s: Starting...", cProgname);


  /*
  ** Parse Conf File
  */
  intHandleConfFile(FALSE);


  /*
  ** Daemon Spell
  */
  if(intAbrakadabra() < 0)
    err_mesg(FATAL_SYS, "%s: main: Fatal: Something is wrong with my Magic Formula *+~#'§%**\nSyserror", cProgname);

  MainPID = getpid();


  /*
  ** Creat PID Files
  */
  if(CfgMisc.PidPath[CfgMisc.iSectNr] == NULL)
    err_mesg(FATAL, "%s: You did not set the PIDPATH!", cProgname);

  snprintf(cPath, sizeof(cPath), "%s/%s", CfgMisc.PidPath[CfgMisc.iSectNr], PIDMAIN);
  if(make_pidfile(cPath, 1) < 0)
    err_mesg(FATAL, "%s: main: Fatal: Error while creating pid file!\n", cProgname);


  /*
  ** Setting Parse Error Function.
  ** This will print an Error Message to Syslog not Stderr
  ** We need this for Runtime Reconfiguration via SIGHUP.
  */
  cfgSetFatalFunc(voidCfgFatalFunc);


  /*
  ** Install new Signal Handler
  */
  if(iDebug)
    log_mesg(WARN, "%s: Debug: Install Signal Handlers", cProgname);

  //if(set_signal(SIGCHLD, voidSigChild) != 0)
    //log_mesg(FATAL_SYS, "%s: set_signal(SIGCHLD) | Syserror", cProgname);

  //if(set_signal(SIGHUP, voidSigHup) != 0)
    //log_mesg(FATAL_SYS, "%s: set_signal(SIGHUP) | Syserror", cProgname);

  if(set_signal(SIGUSR1, voidSigUsr1_2) != 0)
    log_mesg(FATAL_SYS, "%s: set_signal(SIGUSR1) | Syserror", cProgname);
  if(set_signal(SIGUSR2, voidSigUsr1_2) != 0)
    log_mesg(FATAL_SYS, "%s: set_signal(SIGUSR2) | Syserror", cProgname);

  /*
  if(set_signal(SIGINT, voidSigTermination) != 0)
    log_mesg(FATAL_SYS, "%s: set_signal(SIGINT) | Syserror", cProgname);
  if(set_signal(SIGQUIT, voidSigTermination) != 0)
    log_mesg(FATAL_SYS, "%s: set_signal(SIGQUIT) | Syserror", cProgname);
  if(set_signal(SIGTERM, voidSigTermination) != 0)
    log_mesg(FATAL_SYS, "%s: set_signal(SIGTERM) | Syserror", cProgname);
  */


  /*
  ** Install Clean Up Routine
  */
  if(atexit(voidCleanUp) != 0)
    log_mesg(FATAL_SYS, "%s: atexit(voidCleanUp) | Syserror", cProgname);


  /*
  ** Init Reaction Table
  */
  if( intInitRctTab() < 0)
    log_mesg(FATAL, "%s: Error while initializing Reaction Table!", cProgname);


  /*
  ** Network Stuff
  */
  if( (iSock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    log_mesg(FATAL_SYS, "%s: Error while creating Socket | Syserror", cProgname);

  if( setsockopt(iSock, SOL_SOCKET, SO_REUSEADDR, &iOn, sizeof(iOn)) < 0 )
    log_mesg(FATAL_SYS, "%s: Error while setting Option SO_REUSEADDR for Server Socket!\n", cProgname);

  memset((char *)&SAddrIn, 0, sizeof(saddr));
  SAddrIn.sin_family      = AF_INET;
  SAddrIn.sin_addr.s_addr = htonl(name_resolve(CfgNetwork.IP[CfgNetwork.iSectNr]));
  SAddrIn.sin_port        = htons(CfgNetwork.Port[CfgNetwork.iSectNr]);

  if(iDebug)
    log_mesg(WARN, "%s: Setting up Network: %s:%d", cProgname, host_lookup(ntohl(SAddrIn.sin_addr.s_addr)), ntohs(SAddrIn.sin_port));


  if(bind(iSock, (saddr *) &SAddrIn, sizeof(SAddrIn)) != 0)
    log_mesg(FATAL_SYS, "%s: Error while binding Socket to %s:%d | Syserror", cProgname, CfgNetwork.IP[CfgNetwork.iSectNr], CfgNetwork.Port[CfgNetwork.iSectNr]);

  if(listen(iSock, (int) CfgMisc.Backlog[CfgMisc.iSectNr]) != 0)
    log_mesg(FATAL_SYS, "%s: Error while start listening for Socket %s:%d | Syserror", cProgname, CfgNetwork.IP[CfgNetwork.iSectNr], CfgNetwork.Port[CfgNetwork.iSectNr]);



  /*********************************************************************
  *  We are done with Initialisation Phase, now let's start accepting  *
  *  Client Requests                                                   *
  *********************************************************************/
  CliInfo.CliAddrLen = sizeof(struct sockaddr_in);
  while(TRUE)
  {
    /*
    ** Wait for Client Request
    */
    log_mesg(WARN, "%s: Waiting for Client Requests...", cProgname);

    if( (CliInfo.iCliSock = accept(iSock, (saddr *) &CliInfo.CliAddrIn, &CliInfo.CliAddrLen)) == -1)
    {
      log_mesg(WARN_SYS, "%s: Warning: accept() fails! | Syserror", cProgname);
      continue;
    }

    if(iDebug)
      log_mesg(WARN, "%s: Debug: Accepted Client Request", cProgname);

    /*
    ** Create Thread, which handles Client Data.
    */
    if( (CliInfoPtr = (stCliInfo *) calloc(1, sizeof(CliInfo))) == NULL)
    {
      log_mesg(WARN_SYS, "%s: Warning: calloc() fails! | Syserror", cProgname);
      close(CliInfo.iCliSock);
      continue;
    }

    if( pthread_create(&CliInfo.TID, NULL, voidHandleClientRequest, (void *) CliInfoPtr) )
      log_mesg(WARN_SYS, "%s: Error: Unable creat HandleClientRequest Thread | Syserror", cProgname);

    sleep(REPLAYATTACK_DELAYWINDOW+1);
  }

  return(EXIT_SUCCESS);
}



/********************************************************
*
* S U B R O U T I N E S
*
********************************************************/

/*
** Handle Client Request - Thread
*/
void  *voidHandleClientRequest(void *vArg)
{
  char            *cProgname,
                  CliMsg[sizeof(stCipherRctMsg)],
                  SrvMsg[sizeof(stCipherRctMsg)],
                  *cKey;

  short           sChkSum_Orig,
                  sChkSum_New;

  int             iSockErrno,
                  iSockErrnoSize = sizeof(iSockErrno),
                  iRetVal,
                  iCnt;
  const int       iOn,
                  iKeySize = 16;

  size_t          ElemRead;
  time_t          CurrentTimestamp = time(NULL) - REPLAYATTACK_DELAYWINDOW; // replay attack delay window

  FILE            *streamSock;

  MCRYPT          CryptoModule;

  stCliInfo       CliInfo;

  stCipherRctMsg  *CipMsgPtr;
  stReactionMsg   *RctMsgPtr;
  // Client Messages
  stExecMsg       *ExcMsgPtr;
  stShowMsg       *ShwMsgPtr;
  stCheckMsg      *ChkMsgPtr;
  // Server Messages
  stRetvalMsg     *RetMsgPtr;
  stAllMsg        *AllMsgPtr;
  stSupportedMsg  *SupMsgPtr;


  cProgname = "ReactionDaemon/HandleClientRequest - Thread";

  memcpy((char *) &CliInfo, (char *) vArg, sizeof(stCliInfo));
  free(vArg);

  if(pthread_detach(pthread_self()))
  {
    log_mesg(WARN_SYS, "%s: Error: pthread_detach(pthread_self()) | Syserror", cProgname);
    close(CliInfo.iCliSock);
    pthread_exit(NULL);
  }

  log_mesg(WARN, "%s: Accept Connection from [%s:%d]", cProgname, host_lookup(CliInfo.CliAddrIn.sin_addr.s_addr), ntohs(CliInfo.CliAddrIn.sin_port));


  /*
  ** Check Access with libwrap!!!
  ** XXX: Added later
  */


  /*
  ** Set Socket Options
  */
  if( setsockopt(CliInfo.iCliSock, SOL_SOCKET, SO_KEEPALIVE, &iOn, sizeof(iOn)) < 0 )
  {
    close(CliInfo.iCliSock);
    log_mesg(WARN_SYS, "%s: Error: Setting Keepalive Option for Socket | Syserror", cProgname);
    pthread_exit(NULL);
  }


  /*
  ** Alloc Stream Handle
  */
  if( (streamSock = fdopen(CliInfo.iCliSock, "r")) == NULL)
  {
    close(CliInfo.iCliSock);
    log_mesg(WARN_SYS, "%s: Error: open Stream Handle | Syserror", cProgname);
    pthread_exit(NULL);
  }


  /*
  ** Open Crypto Module
  */
  if(iDebug)
    log_mesg(WARN, "%s: Debug: Init. Crypto Module\n", cProgname);

  if((cKey = calloc(1, iKeySize)) == NULL)
  {
    log_mesg(WARN_SYS, "%s: Error while allocating Memory for Twofish Key\n", cProgname);
    goto THREAD_EXIT;
  }

  memmove(cKey, CfgSecurity.RawKey[CfgSecurity.iSectNr], iKeySize);

  if(iDebug)
    log_mesg(WARN, "%s: Debug: Using Key: '%s'", cProgname, cKey);

  if(iDebug)
    log_mesg(WARN, "%s: Debug: init: mcrypt_open(%s)\n", cProgname, CfgSecurity.CryptMod[CfgSecurity.iSectNr]);

  if((CryptoModule = mcrypt_module_open(CfgSecurity.CryptMod[CfgSecurity.iSectNr], NULL, "cfb", NULL)) == MCRYPT_FAILED)
  {
    log_mesg(WARN, "%s: Error while trying to load Crypto Module '%s'\n", cProgname, CfgSecurity.CryptMod[CfgSecurity.iSectNr]);
    goto THREAD_EXIT;
  }



  /************************************************************************************
  **
  ** Reading Client Data
  **
  ************************************************************************************/
  memset(CliMsg, 0, sizeof(CliMsg));
  while( (ElemRead = fread(CliMsg, sizeof(CliMsg), 1, streamSock)) == 1 )
  {
    if(iDebug)
      log_mesg(WARN, "%s: Debug: Read Data from Client...\n", cProgname);


    CipMsgPtr = (stCipherRctMsg *) CliMsg;

    if(CipMsgPtr->CipherTextLen != sizeof(stReactionMsg))
    {
      log_mesg(WARN, "%s: Error: Length of received Messages does not match the expected Length!!!\n", cProgname);
      goto THREAD_EXIT;
    }


    /*
    ** Decrypt received Data
    */
    if(CipMsgPtr->IVLen != 0)
    {
      if(iDebug)
        log_mesg(WARN, "%s: Debug: Message IS encrypted!\n", cProgname);

      // We do a init for every packet, because the client may change the IV
      if(mcrypt_generic_init(CryptoModule, cKey, iKeySize, CipMsgPtr->IV) < 0)
      {
        log_mesg(WARN, "%s: Error while initializing Crypto Module\n", cProgname);
        goto THREAD_EXIT;
      }

      if(iDebug)
        log_mesg(WARN, "%s: Debug: Checksum for Ciphertext (%u) = %hu\n", cProgname, CipMsgPtr->CipherTextLen, in_chksum((u_short *) CipMsgPtr->cCipherText, CipMsgPtr->CipherTextLen));

      for(iCnt = 0; iCnt < CipMsgPtr->CipherTextLen; iCnt++)
        mdecrypt_generic(CryptoModule, &CipMsgPtr->cCipherText[iCnt], 1);

      if(mcrypt_generic_deinit(CryptoModule) < 0)
        log_mesg(WARN, "%s: Error while clearing Crypto Module!\n", cProgname);
    }
    else if(CipMsgPtr->IVLen == 0)
    {
      if(iDebug)
        log_mesg(WARN, "%s: Debug: Message is NOT encrypted!\n", cProgname);
    }

    RctMsgPtr = (stReactionMsg *) CipMsgPtr->cCipherText;


    /*
    ** Verify Checksum (CRC)
    */
    if(iDebug)
      log_mesg(WARN, "%s: Debug: Verify Checksum\n", cProgname);

    sChkSum_Orig        = RctMsgPtr->sChkSum;
    RctMsgPtr->sChkSum  = 0;
    sChkSum_New         = in_chksum((u_short *) CipMsgPtr->cCipherText, CipMsgPtr->CipherTextLen);

    if(iDebug)
      log_mesg(WARN, "%s: Debug: Checksum (Orig [%hu], New [%hu])\n", cProgname, sChkSum_Orig, sChkSum_New);

    if(sChkSum_Orig != sChkSum_New)
    {
      log_mesg(WARN, "%s: Checksum does not match. Close Connection to Client!\n", cProgname);
      goto THREAD_EXIT;
    }

    RctMsgPtr->sChkSum = sChkSum_Orig;


    /*
    ** Check Timestamp to avoid replay attacks
    */
    if(iDebug)
      log_mesg(WARN, "%s: Debug: Check Timestamp\n", cProgname);
    if((time_t) ntohl(RctMsgPtr->Timestamp) > CurrentTimestamp)
      CurrentTimestamp = (time_t) ntohl(RctMsgPtr->Timestamp);
    else
    {
      log_mesg(WARN, "%s: Timestamp (%d) is lower then current Timestamp (%d). Close Connection to Client!\n", cProgname, (time_t) ntohl(RctMsgPtr->Timestamp), CurrentTimestamp);
      goto THREAD_EXIT;
    }


    /*
    ** Check Mode and
    ** Process desired Action
    */
    if(iDebug)
      log_mesg(WARN, "%s: Debug: Check Message Mode\n", cProgname); // (%u | 0x%0.6x)\n", cProgname, (u_int) ntohl(RctMsgPtr->Mode));

    switch( (u_int) ntohl(RctMsgPtr->Mode) )
    {
      case MID_EXEC:
        if(iDebug)
          log_mesg(WARN, "%s: Debug: Mode: EXEC\n", cProgname);
        iRetVal = intHandleExec(RctMsgPtr->ModeData.Exec);
      break;

      case MID_SHOW: // XXX NOT SUPPORTED
        if(iDebug)
          log_mesg(WARN, "%s: Debug: Mode: SHOW\n", cProgname);
        iRetVal = intHandleShow(RctMsgPtr->ModeData.Show);
      break;

      case MID_CHECK: // XXX NOT SUPPORTED
        if(iDebug)
          log_mesg(WARN, "%s: Debug: Mode: CHECK\n", cProgname);
        iRetVal = intHandleCheck(RctMsgPtr->ModeData.Check);
      break;

      default:
        if(iDebug)
          log_mesg(WARN, "%s: Debug: Mode is invalid\n", cProgname);
        iRetVal = RID_UNKNOWNMODE;
    }


    /*
    ** Send Return Value back to Client
    */
    if(iDebug)
     log_mesg(WARN, "%s: Debug: Send answer back to Client\n", cProgname);
    memset(SrvMsg, 0, sizeof(SrvMsg));

    CipMsgPtr                 = (stCipherRctMsg *)  SrvMsg;
    RctMsgPtr                 = (stReactionMsg *)   CipMsgPtr->cCipherText;
    RetMsgPtr                 = (stRetvalMsg *)     &RctMsgPtr->ModeData.Retval;

    CipMsgPtr->CipherTextLen  = sizeof(stReactionMsg);
    CipMsgPtr->IVLen          = 0;

    RetMsgPtr->ret_val    = (int)     htonl(iRetVal);
    RctMsgPtr->Timestamp  = (time_t)  0; //htonl(CurrentTimestamp); leak as less as possible information from encrypted message
    RctMsgPtr->Mode       = (u_int)   htonl(MID_RETVAL);
    RctMsgPtr->sChkSum    = 0;
    RctMsgPtr->sChkSum    = in_chksum((u_short *) CipMsgPtr->cCipherText, sizeof(CipMsgPtr->cCipherText));

    if(iDebug)
     log_mesg(WARN, "%s: Debug: CheckSum = %hu\n", cProgname, RctMsgPtr->sChkSum);

    if(writen(CliInfo.iCliSock, SrvMsg, sizeof(SrvMsg)) != sizeof(SrvMsg))
    {
      log_mesg(WARN_SYS, "%s: Error: writen(SrvMsg) | Syserror\n", cProgname);
      break;
    }

    memset(CliMsg, 0, sizeof(CliMsg));
  }  // while(fread())


  /*
  ** Client Connection Error Handling
  */
  if(getsockopt(CliInfo.iCliSock, SOL_SOCKET, SO_ERROR, &iSockErrno, &iSockErrnoSize) < 0)
  {
    log_mesg(WARN_SYS, "%s: Error: getsockopt(SO_ERROR) | Syserror\n", cProgname);
    goto THREAD_EXIT;
  }

  switch(iSockErrno)
  {
    case ECONNRESET:
      log_mesg(WARN, "%s: Client [%s:%d] resets the Connection!\n", cProgname, host_lookup(CliInfo.CliAddrIn.sin_addr.s_addr), ntohs(CliInfo.CliAddrIn.sin_port));
      break;
    case ETIMEDOUT:
      log_mesg(WARN, "%s: Client [%s:%d] Connection timed out!\n", cProgname, host_lookup(CliInfo.CliAddrIn.sin_addr.s_addr), ntohs(CliInfo.CliAddrIn.sin_port));
      break;
    case EHOSTUNREACH:
      log_mesg(WARN, "%s: Client [%s:%d] Host is unreachable\n", cProgname, host_lookup(CliInfo.CliAddrIn.sin_addr.s_addr), ntohs(CliInfo.CliAddrIn.sin_port));
      break;
    default:
      if(feof(streamSock))
        log_mesg(WARN, "%s: Client [%s:%d] disconnected!\n", cProgname, host_lookup(CliInfo.CliAddrIn.sin_addr.s_addr), ntohs(CliInfo.CliAddrIn.sin_port));
      else
        log_mesg(WARN, "%s: Read invalid Message from Client [%s:%d]!\n", cProgname, host_lookup(CliInfo.CliAddrIn.sin_addr.s_addr), ntohs(CliInfo.CliAddrIn.sin_port));
  }

THREAD_EXIT:
  if(CryptoModule != NULL)
    if(mcrypt_module_close(CryptoModule) < 0)
      log_mesg(WARN, "%s: Error while closing Crypto Module!\n", cProgname);
  //if(cPassword != NULL)
    //free(cPassword);
  if(cKey != NULL)
    free(cKey);

  fclose(streamSock);
  pthread_exit(NULL);
}


int intHandleExec(stExecMsg Exc)
{
  char          cArg[MAX_ARGSTRG_SIZE+1];
  int           iRetVal = RID_UNKNOWNFUNC;
  register int  riCnt;


  memset(cArg, 0 , sizeof(cArg));
  memcpy(cArg, Exc.arg_fmt_string, sizeof(cArg)-1);

  for(riCnt = 0; riCnt <= RctTabEntries; riCnt++)
  {
    if(iDebug)
      log_mesg(WARN, "%s: Debug: (RctTab[riCnt = %d].FID = %d) == (Exc.function_id = %u)", cProgname, riCnt, RctTab[riCnt].FID, (u_int) ntohl(Exc.function_id));

    if(RctTab[riCnt].FID == (u_int) ntohl(Exc.function_id))
    {
      if(iDebug)
        log_mesg(WARN, "Debug: (*RctTab[%d].FuncPtr)(%s, %d)", riCnt, cArg, sizeof(cArg));
      if( (*RctTab[riCnt].FuncPtr)(cArg, sizeof(cArg) ) != -1)
      {
        if(iDebug)
          log_mesg(WARN, "Debug: RID_SUCCESS");
        iRetVal = RID_SUCCESS;
      }
      else
      {
        if(iDebug)
          log_mesg(WARN, "Debug: RID_ERROR");
        iRetVal = RID_ERROR;
      }
    }
  }

  return(iRetVal);
}

int intHandleShow(stShowMsg Shw)
{
  return(RID_ERROR);
}

int intHandleCheck(stCheckMsg Chk)
{
  return(RID_ERROR);
}


/*
** log conf parse error
*/
void  voidCfgFatalFunc(cfgErrorCode ErrCode, const char *Str1 , int iDummy, const char *Str2)
{
  log_mesg(WARN, "%s: Error while Parsing Config File\n", cProgname);
}

void voidSigChild(int id)
{
  pid_t PID;
  int iStatus;

  PID = wait(&iStatus);

  log_mesg(WARN, "%s: Process died! (PID = %d)", cProgname, PID);
}

void voidSigHup(int id)
{
  log_mesg(WARN, "%s: SigHup() received -> re-reading '%s' (not supported, sorry :-\\)", cProgname, cConfFile);

  //intHandleConfFile(TRUE);
}


void voidSigUsr1_2(int id)
{
  if(id == SIGUSR1 && iDebug < INT_MAX)
  {
    iDebug++;
    log_mesg(WARN, "%s: SIGUSR1 received - Debug = %i\n", cProgname, iDebug);
  }
  if(id == SIGUSR2 && iDebug > 0)
  {
    iDebug--;
    log_mesg(WARN, "%s: SIGUSR2 received - Debug = %i\n", cProgname, iDebug);
  }
}

void voidSigTermination(int id)
{

  log_mesg(WARN, "%s: SigTermination() triggered (PID = %d)\n", cProgname, getpid());

  exit(0);
}


/*
** Clean Up Routine
*/
void voidCleanUp(void)
{
  /*
  ** Stop using linltdl
  */
  if(lt_dlexit())
    log_mesg(FATAL_SYS, "%s: Error while trying to stop using libltdl | Syserror", cProgname);


  /*
  ** Close Syslog Sesion
  */
  closelog();

  /*
  ** Remove PID file
  */
  remove(cPath);

  _exit(0);
}


/*
** Become a Daemon
*/
int intAbrakadabra(void)
{
  pid_t pid;


  if( (pid = fork()) < 0)
    return(-1);
  else if(pid != 0)
    exit(0);        // terminate the original parent process


  // get a new session ID
  if(setsid() < 0)
    return(-1);

  chdir("/");     /* change working direc. */
  umask(0);       /* delete filecreatingmask */

  return(0);
}


/*
** Initialize Reaction Table
*/
int intInitRctTab(void)
{
  register int      iCnt;

  int               iInitRctModule;

  char              *cModPath;
  char              cModPathName[PATH_MAX+NAME_MAX+1];

  cfgList           *LstFID,
                    *LstRctMod,
                    *LstRctConf;


  if(iDebug)
    log_mesg(WARN, "%s: Debug: Start init RctTab\n", cProgname);

  cModPath = CfgMisc.ModPath[CfgMisc.iSectNr];

  for(LstFID      = CfgFuncID.FID[CfgFuncID.iSectNr],
      LstRctMod   = CfgRctMod.Name[CfgRctMod.iSectNr],
      LstRctConf  = CfgRctFile.Name[CfgRctFile.iSectNr],
      RctTabEntries = 0;
        LstFID      != NULL &&
        LstRctMod   != NULL &&
        LstRctConf  != NULL;
      LstFID      = LstFID->next,
      LstRctMod   = LstRctMod->next,
      LstRctConf  = LstRctConf->next,
      RctTabEntries++
     )
  {
    if( (RctTab = (struct stReactionTable *) realloc(RctTab, (RctTabEntries+1) * sizeof(struct stReactionTable))) == NULL)
    {
      log_mesg(WARN_SYS, "%s: Error while allocating new Memory for Reaction Table for Element %d | Syserror", cProgname, RctTabEntries+1);
      return(-1);
    }


    /*************************************************
    * Let's open and initialize our Reaction Modules *
    *************************************************/
    if(iDebug)
      log_mesg(WARN, "%s: Debug: Init. Reaction Module\n", cProgname);

    iInitRctModule = TRUE;


    RctTab[RctTabEntries].FID = (u_int) strtol(LstFID->str, NULL, 16);


    // Check for duplicate Modules
    asprintf(&RctTab[RctTabEntries].cModName, "%s", LstRctMod->str);

    for(iCnt = 0; iCnt < RctTabEntries; iCnt++)
    {
      if(!strcmp(RctTab[RctTabEntries].cModName, RctTab[iCnt].cModName))
      {
        // copy handles and pointers
        if(iDebug)
          log_mesg(WARN, "%s: Debug: Detected duplicate Enc Module '%s'\n", cProgname, RctTab[iCnt].cModName);

        RctTab[RctTabEntries].dlHandle = RctTab[iCnt].dlHandle;
        RctTab[RctTabEntries].dlInfo   = RctTab[iCnt].dlInfo;
        RctTab[RctTabEntries].InitPtr  = RctTab[iCnt].InitPtr;
        RctTab[RctTabEntries].FuncPtr  = RctTab[iCnt].FuncPtr;
        RctTab[RctTabEntries].ClosePtr = RctTab[iCnt].ClosePtr;

        iInitRctModule = FALSE;
      }
    }


    if(iInitRctModule == TRUE)
    {
      snprintf(cModPathName, sizeof(cModPathName), "%s/%s", cModPath, LstRctMod->str);
      if((RctTab[RctTabEntries].dlHandle = lt_dlopenext(cModPathName)) == NULL)
      {
        log_mesg(WARN, "%s: Error while opening Module '%s{.la,.so,.sl,...}' | DlError: %s\n", cProgname, cModPathName, lt_dlerror());
        return(-2);
      }

      log_mesg(WARN, "%s: Opened Module '%s'\n", cProgname, LstRctMod->str);

      /* Get Module Info (just supported by libtool >= 1.4.0) */
      if((RctTab[RctTabEntries].dlInfo = lt_dlgetinfo(RctTab[RctTabEntries].dlHandle)) == NULL)
      {
        log_mesg(WARN, "%s: Can not get Module Info | DlError: %s\n", cProgname, lt_dlerror());
        return(-3);
      }

      if(iDebug > 1)
      {
        if(RctTab[RctTabEntries].dlInfo->name)
          log_mesg(WARN, "%s: Module Name: %s\n", cProgname, RctTab[RctTabEntries].dlInfo->name);
        else
          log_mesg(WARN, "%s: Module is not a libtool module\n", cProgname);

        log_mesg(WARN, "%s: Module Filename: %s\n", cProgname, RctTab[RctTabEntries].dlInfo->filename);
        log_mesg(WARN, "%s: Module Reference Count: %i\n", cProgname, RctTab[RctTabEntries].dlInfo->ref_count);
      }


      /* Lookup Symbol Names in Module */
      if(iDebug)
        log_mesg(WARN, "%s: Debug: Lookup Symbols\n", cProgname);

      if((RctTab[RctTabEntries].InitPtr = (int(*)(char *))lt_dlsym(RctTab[RctTabEntries].dlHandle, SYMNAME_INIT)) == NULL)
      {
        log_mesg(WARN, "%s: Can not get Symbol Name | DlError: %s", cProgname, lt_dlerror());
        return(-4);
      }

      if((RctTab[RctTabEntries].FuncPtr = (int(*)(char *, size_t))lt_dlsym(RctTab[RctTabEntries].dlHandle, SYMNAME_FUNC)) == NULL)
      {
        log_mesg(WARN, "%s: Can not get Symbol Name | DlError: %s", cProgname, lt_dlerror());
        return(-5);
      }

      if((RctTab[RctTabEntries].ClosePtr = (int(*)(void))lt_dlsym(RctTab[RctTabEntries].dlHandle, SYMNAME_FUNC)) == NULL)
      {
        log_mesg(WARN, "%s: Can not get Symbol Name | DlError: %s", cProgname, lt_dlerror());
        return(-6);
      }


      /* Call Module's Init Function */
      if(iDebug)
        log_mesg(WARN, "%s: Debug: Call Encoding Modules INIT Function\n", cProgname);

      if( (RctTab[RctTabEntries].iNumArg = (*RctTab[RctTabEntries].InitPtr)(LstRctConf->str)) < 0 )
      {
        log_mesg(WARN, "%s: Error while calling Init Function '%s_LTX_%s' of Module '%s'\n", cProgname, RctTab[RctTabEntries].dlInfo->filename, SYMNAME_INIT, RctTab[RctTabEntries].dlInfo->filename);
        return(-7);
      }
    } // if(iInitRctModule == TRUE)

  } // for()


  if(RctTabEntries == 0)
  {
    log_mesg(WARN, "%s: No Entries for Encoding or Output Modules found! Please, check Config File.\n", cProgname);
    return(-30);
  }
  RctTabEntries--;

  if(LstFID != NULL)
  {
    log_mesg(WARN, "%s: Too much Function ID Entries! Please, check Config File.\n", cProgname);
    return(-31);
  }
  if(LstRctMod != NULL)
  {
    log_mesg(WARN, "%s: Too much Reaction Module Entries! Please, check Config File.\n", cProgname);
    return(-33);
  }
  if(LstRctConf != NULL)
  {
    log_mesg(WARN, "%s: Too much Reaction Config Entries! Please, check Config File.\n", cProgname);
    return(-34);
  }

  return(0);
}


/*
** Handle Config File
*/
int intHandleConfFile(int Syslog)
{
  int             iCfgCount;
  int             iCnt;
  struct stat     StatBuf;


  CfgFuncID.iSectNr   = -1;
  CfgRctMod.iSectNr   = -1;
  CfgRctFile.iSectNr  = -1;
  CfgNetwork.iSectNr  = -1;
  CfgSecurity.iSectNr = -1;
  CfgMisc.iSectNr     = -1;


  if(lstat(cConfFile, &StatBuf) < 0)
    LOG(Syslog, FATAL_SYS, "%s: Error while trying lstat(%s) | Syserror", cProgname, cConfFile);

  if((iCfgCount = cfgParse(cConfFile, CfgIni, CFG_INI)) < 0)
    LOG(Syslog, FATAL, "%s: Error while parsing Config File %s\n", cProgname, cConfFile);

  if(iCfgCount != MAXSECT)
    LOG(Syslog, FATAL, "%s: Error while parsing Config File %s | Sections Read: %d | Sections Expect: %d", cProgname, cConfFile, iCfgCount, MAXSECT);

  if(iDebug)
    LOG(Syslog, WARN, "%s: iCfgCount = %d\n", cProgname, iCfgCount);

  for(iCnt = 0; iCnt < iCfgCount; iCnt++)
  {
    if(iDebug)
      LOG(Syslog, WARN, "%s: [%s]", cProgname, cfgSectionNumberToName(iCnt));

    if(!strcasecmp(cfgSectionNumberToName(iCnt), FUNCID))
      CfgFuncID.iSectNr = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), RCTMOD))
      CfgRctMod.iSectNr = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), RCTMODCONF))
      CfgRctFile.iSectNr = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), NETWORK))
      CfgNetwork.iSectNr = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECURITY))
      CfgSecurity.iSectNr = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), MISC))
      CfgMisc.iSectNr = iCnt;
    else
      LOG(Syslog, FATAL, "%s: Error in Config File %s | Unknown Section: %s", cProgname, cConfFile, cfgSectionNumberToName(iCnt));
  }

  if(CfgRctMod.iSectNr == -1 || CfgRctFile.iSectNr == -1 || CfgNetwork.iSectNr == -1 || CfgSecurity.iSectNr == -1 || CfgMisc.iSectNr == -1)
    LOG(Syslog, FATAL, "%s: Error in Config File %s | A Section is missing!\n", cProgname, cConfFile);

  return(0);
}
