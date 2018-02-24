/***************************************************************************
                           main.c  -  description
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

#define  _GNU_SOURCE    // for asprintf()
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <errno.h>
extern int errno;

/*
** get libltdl/libtool from http://www.gnu.org/software/libtool
** Note from the Doc.:
** Note that libltdl is not threadsafe, i.e. a multithreaded application has to use a mutex for libltdl. It was reported that
** GNU/Linux's glibc 2.0's dlopen with RTLD_LAZY (which libltdl uses by default) is not thread-safe, but this problem is
** supposed to be fixed in glibc 2.1. On the other hand, RTLD_NOW was reported to introduce problems in multi-threaded
** applications on FreeBSD. Working around these problems is left as an exercise for the reader; contributions are certainly
** welcome
**
** XXX: What's about using thread_safe_flag_spec in libtool script???
*/
#include <ltdl.h>

#include <mice.h>
#include "parsecfg.h"
#include "bufferdaemon.h"


/*
** Defines
*/
#define USAGE(id)   log_mesg(id, "usage: %s [-d] [-f <config file>] [-u <user>] [-g <group>]\n\n", cProgname);


typedef struct sockaddr_in  saddr_in;
typedef struct sockaddr_un  saddr_un;
typedef struct sockaddr     saddr;




/*
** Global Variables
*/
char      *cProgname;
char      cPath[PATH_MAX+NAME_MAX+1];
pid_t     MainPID;

static volatile sig_atomic_t  iDebug;


/*
** In this double chained List we keep track of every
** Information we need to decode and process the Client
** Data.
*/
struct rb_info
{
  u_int           rb_pos_w;
  u_int           rb_pos_r;
  u_int           rb_overflow;
  u_int           rb_records;
  u_int           rb_maxring;
  pthread_mutex_t rb_mutex;
  char            *RB;
  size_t          RBSize;
};

struct mm_info
{
  int     MMFd;
  void    *MMAddr;
  size_t  MMSize;
};

enum CacheMethod
{
  Ringbuffered,
  MemMapped,
};

enum SocketType
{
  Unknown,
  IP,
  UnixDomain,
};

struct ProcessQueue
{
  struct ProcessQueue *prev;

  struct dec_info
  {
    enum SocketType   SockType;
    int               iSock;
    saddr_in          SAddrIn;
    saddr_un          SAddrUn;
    int               iCliSock;
    saddr_in          CliAddrIn;
    saddr_un          CliAddrUn;
    size_t            MsgSize;    // returned by init function, size of encoded msg, i.e. cipher text
    pthread_t         TID;        // Thread ID
    char              *cModName;  // Modulename to check for duplicates

    lt_dlhandle       dlHandle;   // dlopen handle for message decoding function
    const lt_dlinfo   *dlInfo;    // libtool 1.4
    size_t            (*InitPtr)(char *);
    char *            (*FuncPtr)(char *, size_t);
    int               (*ClosePtr)(void);
  } Decoding;

  struct pop_info
  {
    time_t            TimeInv;
    size_t            MsgSize;    // returned by init function, size of decoded msg, i.e. LogFormat
    pthread_t         TID;        // Thread ID
    char              *cModName;  // Modulename to check for duplicates

    lt_dlhandle       dlHandle;   // dlopen handle for message decoding function
    const lt_dlinfo   *dlInfo;    // libtool 1.4
    size_t            (*InitPtr)(char *);
    char *            (*FuncPtr)(char *, size_t);
    int               (*ClosePtr)(void);
  } Pop;

  enum CacheMethod  CMethod;
  struct rb_info    Ringbuffer;
  struct mm_info    MMap;

  struct ProcessQueue *next;

} *ProcQ;

u_int   ProcQEntries;
int     SocketMaxFd = -1;


/*
** Configure Stuff
*/
char      *cConfFile;

char      **CfgMMPath;
char      **CfgUser;
char      **CfgGroup;
char      **CfgPidPath;
char      **CfgChrootPath;
char      **CfgModPath;
int       *CfgPseudo;
int       *CfgMMSize;
int       *CfgRBSize;
int       *CfgBacklog;
cfgList   **CfgIPAddrList;
cfgList   **CfgPortNumList;
cfgList   **CfgDecModulesList;
cfgList   **CfgDecConfFileList;
cfgList   **CfgPopModulesList;
cfgList   **CfgPopConfFileList;
cfgList   **CfgTimeInvList;

int       iSectIP;
int       iSectPort;
int       iSectModPath;
int       iSectDecModules;
int       iSectDecConfFile;
int       iSectPopModules;
int       iSectPopConfFile;
int       iSectTimInv;
int       iSectCache;
int       iSectSec;
int       iSectMisc;

cfgStruct CfgIni[] =
{
  // Address Section
  {"BINDTO"      ,CFG_STRING_LIST  ,&CfgIPAddrList       },

  // Port Number Section
  {"PORT"        ,CFG_STRING_LIST  ,&CfgPortNumList      },

  // Module Search Path Section
  {"MODPATH"     ,CFG_STRING       ,&CfgModPath          },

  // Encoding Modules Section
  {"DEC_MOD"     ,CFG_STRING_LIST  ,&CfgDecModulesList   },

  // Encoding Module Config File Section
  {"DEC_FILE"    ,CFG_STRING_LIST  ,&CfgDecConfFileList  },

  // Output Modules Section
  {"POP_MOD"     ,CFG_STRING_LIST  ,&CfgPopModulesList   },

  // Output Module Config File Section
  {"POP_FILE"    ,CFG_STRING_LIST  ,&CfgPopConfFileList  },

  // Time Interval Section
  {"TIMEINV"     ,CFG_STRING_LIST  ,&CfgTimeInvList      },

  // Cache and Ringbuffer Section
  {"MMPATH"      ,CFG_STRING       ,&CfgMMPath           },
  {"MMSIZE"      ,CFG_INT          ,&CfgMMSize           },
  {"RBSIZE"      ,CFG_INT          ,&CfgRBSize           },

  // Security and Privacy Section
  {"PSEUDO"      ,CFG_BOOL         ,&CfgPseudo           },
  {"USER"        ,CFG_STRING       ,&CfgUser             },
  {"GROUP"       ,CFG_STRING       ,&CfgGroup            },
  {"CHROOT"      ,CFG_STRING       ,&CfgChrootPath       },

  // Misc Section
  {"PIDPATH"     ,CFG_STRING       ,&CfgPidPath          },
  {"BACKLOG"     ,CFG_INT          ,&CfgBacklog          },

  {NULL          ,CFG_END          ,NULL                 }
};


void  voidSigChild(int id);
void  voidSigHup(int id);
void  voidSigUsr1_2(int id);
void  voidSigTermination(int id);
void  voidSigRealTime(int id);
void  voidCfgFatalFunc(cfgErrorCode ErrCode, const char *Str1 , int iDummy, const char *Str2);
void  voidCleanUp(void);
void  *voidHandleClientRequest(void *vArg);  // Thread
void  *voidTimer(void *vArg);                // Thread

int   intInitProcQueue(void);
int   intAbrakadabra(void);
int   intHandleConfFile(int Syslog);

int   intRBWrite(struct rb_info *rbi, char *data, size_t datalen, int overwrite);
int   intRBRead(struct rb_info *rbi, char *data, size_t datalen, int release);



/*******************************************************************
*
* M A I N
*
*******************************************************************/

int main(int argc, char *argv[])
{
  int                 iOpt;
  int                 iCnt;
  int                 *iCntPtr;

  uid_t               eUID = geteuid();
  uid_t               rUID = getuid();
  gid_t               eGID = getegid();
  gid_t               rGID = getgid();
  fd_set              ReadFDSet;
  socklen_t           CliAddrLen;

  struct passwd       *PwdEnt;
  struct group        *GrpEnt;


  cProgname = "BufferDaemon";  // argv[0];


  /*
  ** First let's check, that we didn't run
  ** set[gu]id, because this code was not designed to be set[gu]id
  ** and I don't like it! *eg*
  */
  if(rUID != eUID || rGID != eGID)
    err_mesg( FATAL, "%s: Do NOT run me as set[ug]id app, it's NOT neccessary and I do NOT like it! Run me as root. :-)\n", cProgname);


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
                if((cConfFile = strdup(optarg)) == NULL)
                  err_mesg( FATAL_SYS, "%s: strdup(CONFILE)\nSyserror", cProgname);
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
    err_mesg( FATAL_SYS, "%s: Error while trying to initialize libltdl\nSyserror", cProgname);


  /*
  ** Open Syslog
  */
  log_open(cProgname, LOG_PID, LOG_DAEMON); // XXX: CfgSyslogFac[iSectMisc]);


  log_mesg( WARN, "%s: Starting...", cProgname);


  /*
  ** Parse Conf File
  ** Redo this when receiving SIGHUP
  ** Security: The Config File has to be in a secure Directory. The Directory and File have to be just
  **           writeable by root.
  **           I really love parsecfg.c but don't trust parsecfg.c to be bugfree, so this Code avoids
  **           to run set[ug]id.
  */
  intHandleConfFile(FALSE);


  /*
  ** Get Passwd and Group Entry
  */
  if(!(PwdEnt = getpwnam(CfgUser[iSectSec])) || !(GrpEnt = getgrnam(CfgGroup[iSectSec])))
    err_mesg( FATAL_SYS, "%s: main: Fatal: Can not get passwd/user (%s) or group (%s) entry!\nSyserror", cProgname, CfgUser[iSectSec], CfgGroup[iSectSec]);


  /*
  ** Daemon Spell
  */
  if(intAbrakadabra() < 0)
    err_mesg( FATAL_SYS, "%s: main: Fatal: Something is wrong with my Magic Formula *+~#'§%**\nSyserror", cProgname);

  MainPID = getpid();


  /*
  ** Creat PID Files
  */
  if(CfgPidPath[iSectMisc] == NULL)
    err_mesg( FATAL, "%s: You did not set the PIDPATH!", cProgname);

  snprintf(cPath, sizeof(cPath), "%s/%s", CfgPidPath[iSectMisc], PIDMAIN);
  if(make_pidfile(cPath, 1) < 0)
    err_mesg(FATAL_SYS, "%s: main: Fatal: Error while creating pid file! | Syserror\n", cProgname);


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
    log_mesg( WARN, "%s: Debug: Install Signal Handlers", cProgname);

  if(set_signal(SIGCHLD, voidSigChild) != 0)
    log_mesg( FATAL_SYS, "%s: set_signal(SIGCHLD) | Syserror", cProgname);

  if(set_signal(SIGHUP, voidSigHup) != 0)
    log_mesg( FATAL_SYS, "%s: set_signal(SIGHUP) | Syserror", cProgname);

  if(set_signal(SIGUSR1, voidSigUsr1_2) != 0)
    log_mesg( FATAL_SYS, "%s: set_signal(SIGUSR1) | Syserror", cProgname);
  if(set_signal(SIGUSR2, voidSigUsr1_2) != 0)
    log_mesg( FATAL_SYS, "%s: set_signal(SIGUSR2) | Syserror", cProgname);

  if(set_signal(SIGINT, voidSigTermination) != 0)
    log_mesg( FATAL_SYS, "%s: set_signal(SIGINT) | Syserror", cProgname);
  if(set_signal(SIGQUIT, voidSigTermination) != 0)
    log_mesg( FATAL_SYS, "%s: set_signal(SIGQUIT) | Syserror", cProgname);
  if(set_signal(SIGTERM, voidSigTermination) != 0)
    log_mesg( FATAL_SYS, "%s: set_signal(SIGTERM) | Syserror", cProgname);

  if(set_signal(SIGRTMIN+0, voidSigRealTime) != 0)
    log_mesg( FATAL_SYS, "%s: set_signal(SIGRTMIN+0) | Syserror", cProgname);
  if(set_signal(SIGRTMIN+1, voidSigRealTime) != 0)
    log_mesg( FATAL_SYS, "%s: set_signal(SIGRTMIN+1) | Syserror", cProgname);
  if(set_signal(SIGRTMIN+2, voidSigRealTime) != 0)
    log_mesg( FATAL_SYS, "%s: set_signal(SIGRTMIN+2) | Syserror", cProgname);


  /*
  ** Install Clean Up Routine
  */
  if(atexit(voidCleanUp) != 0)
    log_mesg( FATAL_SYS, "%s: atexit(voidCleanUp) | Syserror", cProgname);


  /*
  ** Init Process Queue
  */
  if(intInitProcQueue() < 0)
    log_mesg( FATAL, "%s: Error while initializing Process Queue!", cProgname);


  /*
  ** - Start Timer Threads
  ** - Add Sockets to "read filedesc. set"
  */
  FD_ZERO(&ReadFDSet);
  for(iCnt = 0; iCnt <= ProcQEntries; iCnt++)
  {
    if( (iCntPtr = (int *) calloc(1, sizeof(int))) == NULL)
      log_mesg(WARN_SYS, "%s: Error while allocating Memory for iCntPtr | Syserror", cProgname);
    else
    {
      *iCntPtr = iCnt;
      if( pthread_create(&ProcQ[iCnt].Pop.TID, NULL, voidTimer, (void *) iCntPtr) )
        log_mesg( FATAL_SYS, "%s: Error: Unable creat Timer Thread | Syserror", cProgname);

      if(iDebug)
        log_mesg( WARN, "%s: Debug: Add fdesc %i to read fdesc set", cProgname, ProcQ[iCnt].Decoding.iSock);

      FD_SET(ProcQ[iCnt].Decoding.iSock, &ReadFDSet);

      if(ProcQ[iCnt].Decoding.iSock > SocketMaxFd)
        SocketMaxFd = ProcQ[iCnt].Decoding.iSock;
    }
  }


  /*********************************************************************
  *  We are done with Initialisation Phase, now let's start accepting  *
  *  Client Requests                                                   *
  *********************************************************************/
  while(TRUE)
  {
    /*
    ** Wait for Client Request
    */
    if(select(SocketMaxFd+1, &ReadFDSet, NULL, NULL, NULL) <= 0)
    {
      if(iDebug)
        log_mesg( WARN_SYS, "%s: Debug: select() returned <= 0... reloop | Syserror", cProgname);
      continue;
    }

    if(iDebug > 1)
      log_mesg( WARN, "%s: Debug: select() returned", cProgname);

    for(iCnt = 0; iCnt <= ProcQEntries; iCnt++)
    {
      if(iDebug > 1)
        log_mesg( WARN, "%s: Debug: Check for fdesc %d", cProgname, ProcQ[iCnt].Decoding.iSock);

      if(!FD_ISSET(ProcQ[iCnt].Decoding.iSock, &ReadFDSet))
        continue;

      if(iDebug)
        log_mesg( WARN, "%s: Debug: Accept Client Request for fdesc %d", cProgname, ProcQ[iCnt].Decoding.iSock);

      // maybe I should use sockaddr to be more flexible and convert the datatypes later
      if(ProcQ[iCnt].Decoding.SockType == IP)
      {
        CliAddrLen = sizeof(saddr_in);
        if( (ProcQ[iCnt].Decoding.iCliSock = accept(ProcQ[iCnt].Decoding.iSock, (saddr *) &ProcQ[iCnt].Decoding.CliAddrIn, &CliAddrLen)) == -1)
        {
          log_mesg( WARN_SYS, "%s: Warning: accept() fails! | Syserror", cProgname);
          continue;
        }
      }
      else
      {
        CliAddrLen = sizeof(saddr_un);
        if( (ProcQ[iCnt].Decoding.iCliSock = accept(ProcQ[iCnt].Decoding.iSock, (saddr *) &ProcQ[iCnt].Decoding.CliAddrUn, &CliAddrLen)) == -1)
        {
          log_mesg( WARN_SYS, "%s: Warning: accept() fails! | Syserror", cProgname);
          continue;
        }
      }


      if(iDebug)
        log_mesg( WARN, "%s: Debug: Accepted Client Request with fdesc %d", cProgname, ProcQ[iCnt].Decoding.iCliSock);


      /*
      ** Create Thread, which handles Client-Data.
      */
      if(iDebug)
        log_mesg( WARN, "%s: Debug: Create Thread for ProcQEntry %d", cProgname, iCnt);

      if( (iCntPtr = (int *) calloc(1, sizeof(int))) == NULL)
        log_mesg(WARN_SYS, "%s: Error while allocating Memory for iCntPtr | Syserror", cProgname);
      else
      {
        *iCntPtr = iCnt;
        if( pthread_create(&ProcQ[iCnt].Decoding.TID, NULL, voidHandleClientRequest, (void *) iCntPtr) )
          log_mesg( WARN_SYS, "%s: Error: Unable creat HandleClientRequest Thread | Syserror", cProgname);
      }
    }
  } // while(TRUE)

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
  char          *cProgname,
                *cEncodedMsg,
                *cDecodedMsg,
                *cHostPtr;

  int           iSockErrno,
                iSockErrnoSize = sizeof(iSockErrno);

  const int     iOn;

  int           ProcQEnt;

  size_t        ElemRead;

  FILE          *Sock;


  cProgname = "BufferDaemon/HandleClientRequest - Thread";

  // Get and check Argument
  ProcQEnt = *((int *) vArg);
  free(vArg);

  if(ProcQEnt > ProcQEntries)
  {
    log_mesg( WARN, "%s: Error: ProcQEnt bigger then ProcQEntries ( %d > %d)! Maybe due to attached Debugger", cProgname, ProcQEnt, ProcQEntries);
    close(ProcQ[ProcQEnt].Decoding.iCliSock);
    pthread_exit(NULL);
  }
  if(ProcQEnt < 0)
  {
    log_mesg( WARN, "%s: Error: ProcQEnt (%d) lower then 0!", cProgname, ProcQEnt);
    close(ProcQ[ProcQEnt].Decoding.iCliSock);
    pthread_exit(NULL);
  }

  if(ProcQ[ProcQEnt].Decoding.SockType == IP)
  {
    cHostPtr = host_lookup(ProcQ[ProcQEnt].Decoding.CliAddrIn.sin_addr.s_addr);
    log_mesg( WARN, "%s: Accept Connection from [%s:%d]", cProgname
                                                        , cHostPtr
                                                        , ntohs(ProcQ[ProcQEnt].Decoding.CliAddrIn.sin_port));
    free(cHostPtr);
  }
  else if(ProcQ[ProcQEnt].Decoding.SockType == UnixDomain)
  {
    log_mesg( WARN, "%s: Accept Connection via Unix Domain Socket [%s]", cProgname, ProcQ[ProcQEnt].Decoding.CliAddrUn.sun_path);
  }
  else
  {
    log_mesg( WARN, "%s: Error: ProcQEnt (%d) contains a unknown Socket-Type!", cProgname, ProcQEnt);
    close(ProcQ[ProcQEnt].Decoding.iCliSock);
    pthread_exit(NULL);
  }


  // Detach
  if(pthread_detach(pthread_self()))
  {
    log_mesg( WARN_SYS, "%s: Error: pthread_detach(pthread_self()) | Syserror", cProgname);
    close(ProcQ[ProcQEnt].Decoding.iCliSock);
    pthread_exit(NULL);
  }


  /*
  ** Check Access with libwrap!!!
  ** XXX: Added later
  */


  /*
  ** Set Socket Options
  */
  if( setsockopt(ProcQ[ProcQEnt].Decoding.iCliSock, SOL_SOCKET, SO_KEEPALIVE, &iOn, sizeof(iOn)) < 0 )
  {
    close(ProcQ[ProcQEnt].Decoding.iCliSock);
    log_mesg( WARN_SYS, "%s: Error: Setting Keepalive Option for Socket | Syserror", cProgname);
    pthread_exit(NULL);
  }


  /*
  ** Alloc Stream Handle
  */
  if( (Sock = fdopen(ProcQ[ProcQEnt].Decoding.iCliSock, "r")) == NULL)
  {
    close(ProcQ[ProcQEnt].Decoding.iCliSock);
    log_mesg( WARN_SYS, "%s: Error: open Stream Handle | Syserror", cProgname);
    pthread_exit(NULL);
  }


  /*
  ** Alloc memory for encoded data
  */
  if( (cEncodedMsg = (char *) calloc(ProcQ[ProcQEnt].Decoding.MsgSize, 1)) == NULL)
  {
    log_mesg( WARN_SYS, "%s: Error: calloc() memory for encoded Data | Syserror", cProgname);
    close(ProcQ[ProcQEnt].Decoding.iCliSock);
    pthread_exit(NULL);
  }


  /************************************************************************************
  **
  ** Reading Client Data
  **
  ************************************************************************************/
  while( (ElemRead = fread(cEncodedMsg, ProcQ[ProcQEnt].Decoding.MsgSize, 1, Sock)) == 1 )
  {
    if(iDebug)
      log_mesg( WARN, "%s: Debug: Read Data from Client...\n", cProgname);


    /*
    ** Call Decode-Modules Decode-Function to get Plaintext Message
    */
    if( (cDecodedMsg = (*ProcQ[ProcQEnt].Decoding.FuncPtr)(cEncodedMsg, ProcQ[ProcQEnt].Decoding.MsgSize)) == NULL)
    {
      log_mesg( WARN, "%s: Error while decoding received Data!\n", cProgname);
      continue;
    }


    /*
    ** Now write the P(l)aintext Message to the Ringbuffer
    */
    if(iDebug)
      log_mesg( WARN, "%s: Debug: Write Log Data to Ringbuffer\n", cProgname);

    if(iDebug)
      log_mesg( WARN, "%s: Debug: MUTEX lock", cProgname);
    pthread_mutex_lock(&ProcQ[ProcQEnt].Ringbuffer.rb_mutex);

    if(iDebug)
      log_mesg( WARN, "%s: Debug: write (%s)", cProgname, cDecodedMsg);
    if(intRBWrite(&ProcQ[ProcQEnt].Ringbuffer, cDecodedMsg, ProcQ[ProcQEnt].Pop.MsgSize, TRUE) < 0)
      log_mesg( WARN, "%s: Error: intRBWrite(cDecodedMsg, ProcQ[ProcQEnt].Pop.MsgSize, TRUE)!\n", cProgname);

    if(iDebug)
      log_mesg( WARN, "%s: Debug: MUTEX unlock", cProgname);
    pthread_mutex_unlock(&ProcQ[ProcQEnt].Ringbuffer.rb_mutex);
  }  // while(fread())


  /*
  ** Client Connection Error Handling
  */
  if(getsockopt(ProcQ[ProcQEnt].Decoding.iCliSock, SOL_SOCKET, SO_ERROR, &iSockErrno, &iSockErrnoSize) < 0)
  {
    log_mesg( WARN_SYS, "%s: Error: getsockopt(SO_ERROR) | Syserror\n", cProgname);
    goto THREAD_EXIT;
  }

  cHostPtr = host_lookup(ProcQ[ProcQEnt].Decoding.CliAddrIn.sin_addr.s_addr);
  switch(iSockErrno)
  {
    case ECONNRESET:
      log_mesg( WARN, "%s: Client [%s:%d] resets the Connection!\n", cProgname, cHostPtr, ntohs(ProcQ[ProcQEnt].Decoding.CliAddrIn.sin_port));
      break;
    case ETIMEDOUT:
      log_mesg( WARN, "%s: Client [%s:%d] Connection timed out!\n", cProgname, cHostPtr, ntohs(ProcQ[ProcQEnt].Decoding.CliAddrIn.sin_port));
      break;
    case EHOSTUNREACH:
      log_mesg( WARN, "%s: Client [%s:%d] Host is unreachable\n", cProgname, cHostPtr, ntohs(ProcQ[ProcQEnt].Decoding.CliAddrIn.sin_port));
      break;
    default:
      if(feof(Sock))
        log_mesg( WARN, "%s: Client [%s:%d] disconnected!\n", cProgname, cHostPtr, ntohs(ProcQ[ProcQEnt].Decoding.CliAddrIn.sin_port));
      else
        log_mesg( WARN, "%s: Read invalid Message from Client!\n", cProgname);
  }
  free(cHostPtr);

THREAD_EXIT:
  fclose(Sock);
  free(cEncodedMsg);
  pthread_exit(NULL);
}


/*
** Timer - Thread
*/
void *voidTimer(void *vArg)
{
  char              *cProgname,
                    *cMsg = NULL;

  int               ProcQEntry;


  cProgname = "BufferDaemon/Timer - Thread";

  ProcQEntry = *((int *) vArg);
  free(vArg);

  if(ProcQEntry > ProcQEntries)
  {
    log_mesg( WARN, "%s: Error: ProcQEntry bigger then ProcQEntries ( %d > %d)! Maybe due to attached Debugger", cProgname, ProcQEntry, ProcQEntries);
    pthread_exit(NULL);
  }
  if(ProcQEntry < 0)
  {
    log_mesg( WARN, "%s: Error: ProcQEntry (%d) lower then 0!", cProgname, ProcQEntry);
    pthread_exit(NULL);
  }


  if(pthread_detach(pthread_self()))
  {
    log_mesg( WARN_SYS, "%s: Error: pthread_detach(pthread_self()) | Syserror", cProgname);
    pthread_exit(NULL);
  }

  if( (cMsg = calloc(ProcQ[ProcQEntry].Pop.MsgSize+1, sizeof(char))) == NULL )
  {
    log_mesg( WARN_SYS, "%s: Error: calloc(%d, sizeof(char)) memory for Message in Ringbuffer | Syserror", cProgname, ProcQ[ProcQEntry].Pop.MsgSize);
    goto TIMER_EXIT;
  }


  /*
  ** 'N go...
  */
  while(TRUE)
  {
    /*
    ** Sleep for Time Interval Seconds
    */
    if(iDebug)
      log_mesg( WARN, "%s: Debug: Sleeping...\n", cProgname);

    sleep(ProcQ[ProcQEntry].Pop.TimeInv);


    /*
    ** Read Data from Ringbuffer
    */
    if(iDebug)
      log_mesg( WARN, "%s: Debug: Start reading Data from Ringbuffer\n", cProgname);

    if(iDebug)
      log_mesg( WARN, "%s: Debug: MUTEX lock", cProgname);
    pthread_mutex_lock(&ProcQ[ProcQEntry].Ringbuffer.rb_mutex);
    while(intRBRead(&ProcQ[ProcQEntry].Ringbuffer, cMsg, ProcQ[ProcQEntry].Pop.MsgSize, TRUE) != -1)
    {
      if(iDebug)
        log_mesg( WARN, "%s: Debug: Read Data (%s) from  Ringbuffer", cProgname, cMsg);
      /*
      ** Call Module Function
      */
      if(iDebug)
        log_mesg( WARN, "%s: Debug: Call Modules FUNC Function\n", cProgname);

      if( (*ProcQ[ProcQEntry].Pop.FuncPtr)(cMsg, ProcQ[ProcQEntry].Pop.MsgSize) < 0 )
        log_mesg( WARN, "%s: Debug: Error while calling Modules FUNC Function\n", cProgname);

      if(iDebug)
        log_mesg( WARN, "%s: Debug: Zeroing cMsg", cProgname);
      memset(cMsg, 0, ProcQ[ProcQEntry].Pop.MsgSize);
    }
    if(iDebug)
      log_mesg( WARN, "%s: Debug: MUTEX unlock", cProgname);
    pthread_mutex_unlock(&ProcQ[ProcQEntry].Ringbuffer.rb_mutex);
  }


TIMER_EXIT:
  /*
  ** Close Module (just opened once)
  */
  if(iDebug)
    log_mesg( WARN, "%s: Debug: Close Module\n", cProgname);

  if( (*ProcQ[ProcQEntry].Pop.ClosePtr)() < 0 )
    log_mesg( WARN, "%s: Debug: Error while calling Modules CLOSE Function\n", cProgname);

  if(lt_dlclose(ProcQ[ProcQEntry].Pop.dlHandle))
    log_mesg( WARN, "%s: Error while closing Module | DlError: %s\n", cProgname, lt_dlerror());

  if(cMsg != NULL)
    free(cMsg);

  pthread_exit(NULL);
}


/*
** Ringbuffer Routines
*/
int intRBWrite(struct rb_info *rbi, char *data, size_t datalen, int overwrite)
{

  if(iDebug > 2)
    log_mesg( WARN, "%s: Debug: rbi->rb_write: rp_pos_w/r = %d/%d, rbi->rb_records = %d\n", cProgname, rbi->rb_pos_w, rbi->rb_pos_r, rbi->rb_records);

  if(rbi->rb_pos_w == rbi->rb_maxring) // swapping
  {
    if(iDebug > 2)
      log_mesg( WARN, "%s: Debug: Overflow detected: rbi->rb_pos_w (%d) == rbi->rb_pos_w (%d)", cProgname, rbi->rb_pos_w, rbi->rb_pos_w);

    if(overwrite == FALSE)
      return(-1);

    if(iDebug > 2)
      log_mesg( WARN, "%s: Debug: Overflow detected: Overwrite", cProgname);

    rbi->rb_pos_w     = 0;
    rbi->rb_overflow  = TRUE;
  }

  if(iDebug > 2)
    log_mesg( WARN, "%s: Debug: rbi->rb_write: copy data to ringbuffer\n", cProgname);

  memset(&rbi->RB[rbi->rb_pos_w*datalen], 0, datalen);
  memcpy(&rbi->RB[rbi->rb_pos_w*datalen], data, datalen);

  if(iDebug > 2)
    log_mesg( WARN, "%s: Debug: Copied Data to Ringbuffer[%d*%d] from User Buffer\n", cProgname, rbi->rb_pos_w, datalen);


  // claculate number of entries in ringbuffer
  if(rbi->rb_overflow == FALSE)
    rbi->rb_records = rbi->rb_pos_w - rbi->rb_pos_r;
  else
    rbi->rb_records = rbi->rb_maxring - (rbi->rb_pos_r - rbi->rb_pos_w);

  if(iDebug > 2)
    log_mesg( WARN, "%s: Debug: Set rbi->rb_records to %d\n", cProgname, rbi->rb_records);


  // set read ptr in the front of write ptr when we swapped -> read ptr to oldest entry
  if(rbi->rb_pos_w == rbi->rb_pos_r && rbi->rb_overflow == TRUE)
    rbi->rb_pos_r = rbi->rb_pos_w + 1;

  return((rbi->rb_pos_w)++);
}

int intRBRead(struct rb_info *rbi, char *data, size_t datalen, int release)
{
  if(iDebug > 2)
    log_mesg( WARN, "%s: Debug: rbi->rb_read: rp_pos_r = %d, rbi->rb_records = %d\n", cProgname, rbi->rb_pos_r, rbi->rb_records);

  if(rbi->rb_pos_r == rbi->rb_pos_w)
  {
    if(iDebug > 2)
      log_mesg( WARN, "%s: Debug: rbi->rb_read: no data to read from ringbuffer, setting rbi->rb_overflow = FALSE\n", cProgname);
    rbi->rb_overflow = FALSE;
    return(-1);
  }

  if(rbi->rb_pos_r == rbi->rb_maxring)
    rbi->rb_pos_r = 0;

  if(iDebug > 2)
    log_mesg( WARN, "%s: Debug: Copy Data form Ringbuffer[%d*%d] to User Buffer\n", cProgname, rbi->rb_pos_r, datalen);
  memcpy(data, &rbi->RB[rbi->rb_pos_r*datalen], datalen);

  if(release == TRUE)
  {
    memset(&rbi->RB[rbi->rb_pos_r*datalen], 0, datalen);

    // claculate number of entries in ringbuffer
    if(rbi->rb_overflow == FALSE)
      rbi->rb_records = rbi->rb_pos_w - rbi->rb_pos_r;
    else
      rbi->rb_records = rbi->rb_maxring - (rbi->rb_pos_r - rbi->rb_pos_w);
  }

  return((rbi->rb_pos_r)++);
}


/*
** log conf parse error
*/
void  voidCfgFatalFunc(cfgErrorCode ErrCode, const char *Str1 , int iDummy, const char *Str2)
{
  log_mesg( WARN, "%s: Error while Parsing Config File\n", cProgname);
}

void voidSigChild(int id)
{
  pid_t PID;
  int iStatus;

  PID = wait(&iStatus);

  log_mesg( WARN, "%s: Process died! (PID = %d)", cProgname, PID);
}

void voidSigHup(int id)
{
  log_mesg( WARN, "%s: SigHup() received -> re-reading '%s' (not supported, sorry :-\\)", cProgname, cConfFile);

  //intHandleConfFile(TRUE);
}


void voidSigUsr1_2(int id)
{
  if(id == SIGUSR1 && iDebug < INT_MAX)
  {
    iDebug++;
    log_mesg( WARN, "%s: SIGUSR1 received - Debug = %i\n", cProgname, iDebug);
  }
  if(id == SIGUSR2 && iDebug > 0)
  {
    iDebug--;
    log_mesg( WARN, "%s: SIGUSR2 received - Debug = %i\n", cProgname, iDebug);
  }
}

void voidSigTermination(int id)
{

  log_mesg( WARN, "%s: SigTermination() triggered (PID = %d)\n", cProgname, getpid());

  exit(0);
}

void voidSigRealTime(int id)
{
  log_mesg( WARN, "%s: Received real-time signal", cProgname);
  // IGNORE
}


/*
** Clean Up Routine
*/
void voidCleanUp(void)
{
  register int iCnt;

  pid_t MyPID = getpid();


  /*
  ** Send SIGTERM to other Processes
  */
  if(MyPID != MainPID)
  {
    // XXX: HandleCLientRequest SHOULD NEVER EVER send Signals !!!
    // XXX: Whats about Timer Processes??!!
    if(iDebug)
      log_mesg( WARN, "%s: CleanUp: Debug: Sending SIGTERM to Main Process (PID = %d)", cProgname, MainPID);

    if(kill(MainPID, SIGTERM) < 0) // XXX do we really need error handling here?
      log_mesg( WARN_SYS, "%s: CleanUp: failed kill(MainPID = %d, SIGTERM) | Syserror", cProgname, MainPID);
  }


  /*
  ** Free Process Queue Structure
  */
  for(iCnt = ProcQEntries; iCnt >= 0; iCnt--)
  {
    if(ProcQ[iCnt].Ringbuffer.RB != NULL)
      free(ProcQ[iCnt].Ringbuffer.RB);

    if(ProcQ[iCnt].MMap.MMAddr != NULL)
      munmap(ProcQ[iCnt].MMap.MMAddr, CfgMMSize[iSectCache]-1);

    // XXX Killing threads, how?

    if( (*ProcQ[iCnt].Decoding.ClosePtr)() < 0 )
      log_mesg( WARN, "%s: Debug: Error while calling Modules CLOSE Function\n", cProgname);

    lt_dlclose(ProcQ[iCnt].Decoding.dlHandle);

    free(&ProcQ[iCnt]);
  }


  /*
  ** Close Crypto Module
  */
  //mcrypt_generic_end(CryptModule);


  /*
  ** Stop using linltdl
  */
  if(lt_dlexit())
    log_mesg( FATAL_SYS, "%s: Error while trying to stop using libltdl | Syserror", cProgname);


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

/* we don't need that old BSD code anymore
  if( (fd = open("/dev/tty", O_RDWR) ) >= 0)
  {
    ioctl(fd, TIOCNOTTY, (char *) 0);       // lose controlling terminal
    close(fd);
  }
*/

  // child process

  //sleep(20); /// XXX just for GDB!!!

  // get a new session ID
  if(setsid() < 0)
    return(-1);

  chdir("/");     /* change working direc. */
  umask(0);       /* delete filecreatingmask */

  return(0);
}


/*
** Initialize Process Queue
*/
int intInitProcQueue(void)
{
  register int      iCnt;

  int               iOn = 1,
                    iInitDecModule,
                    iInitPopModule;

  char              *cModPath,
                    cModPathName[PATH_MAX+NAME_MAX+1],
                    *cHostPtr;

  cfgList           *LstTInv,
                    *LstOMod,
                    *LstOConf,
                    *LstIP,
                    *LstPort,
                    *LstEMod,
                    *LstEConf;


  if(iDebug)
    log_mesg( WARN, "%s: Debug: Start init ProcQ\n", cProgname);

  cModPath = CfgModPath[iSectModPath];

  for(LstIP     = CfgIPAddrList       [iSectIP],
      LstPort   = CfgPortNumList      [iSectPort],
      LstEMod   = CfgDecModulesList   [iSectDecModules],
      LstEConf  = CfgDecConfFileList  [iSectDecConfFile],
      LstTInv   = CfgTimeInvList      [iSectTimInv],
      LstOMod   = CfgPopModulesList   [iSectPopModules],
      LstOConf  = CfgPopConfFileList  [iSectPopConfFile],
      ProcQEntries = 0;
        LstIP     != NULL &&
        LstPort   != NULL &&
        LstEMod   != NULL &&
        LstEConf  != NULL &&
        LstTInv   != NULL &&
        LstOMod   != NULL &&
        LstOConf  != NULL;
      LstIP     = LstIP->next,
      LstPort   = LstPort->next,
      LstEMod   = LstEMod->next,
      LstEConf  = LstEConf->next,
      LstTInv   = LstTInv->next,
      LstOMod   = LstOMod->next,
      LstOConf  = LstOConf->next,
      ProcQEntries++
     )
  {
    iInitDecModule = TRUE;
    iInitPopModule = TRUE;

    // Make some Space.
    if( (ProcQ = (struct ProcessQueue *) realloc(ProcQ, (ProcQEntries+1) * sizeof(struct ProcessQueue))) == NULL)
    {
      log_mesg( WARN_SYS, "%s: Error while allocating new Memory for Process Queue for Element %d | Syserror", cProgname, ProcQEntries+1);
      return(-1);
    }


    /*************************************************
    * Let's open and initialize our Decoding Modules *
    *************************************************/
    if(iDebug)
      log_mesg( WARN, "%s: Debug: Init. Enc Module\n", cProgname);

    // Check for duplicate Modules
    asprintf(&ProcQ[ProcQEntries].Decoding.cModName, "%s", LstEMod->str);

    for(iCnt = 0; iCnt < ProcQEntries; iCnt++)
    {
      if(!strcmp(ProcQ[ProcQEntries].Decoding.cModName, ProcQ[iCnt].Decoding.cModName))
      {
        // copy handles and pointers
        if(iDebug)
          log_mesg( WARN, "%s: Debug: Detected duplicate Enc Module '%s'\n", cProgname, ProcQ[iCnt].Decoding.cModName);

        ProcQ[ProcQEntries].Decoding.dlHandle = ProcQ[iCnt].Decoding.dlHandle;
        ProcQ[ProcQEntries].Decoding.dlInfo   = ProcQ[iCnt].Decoding.dlInfo;
        ProcQ[ProcQEntries].Decoding.InitPtr  = ProcQ[iCnt].Decoding.InitPtr;
        ProcQ[ProcQEntries].Decoding.FuncPtr  = ProcQ[iCnt].Decoding.FuncPtr;
        ProcQ[ProcQEntries].Decoding.ClosePtr = ProcQ[iCnt].Decoding.ClosePtr;
        ProcQ[ProcQEntries].Decoding.MsgSize  = ProcQ[iCnt].Decoding.MsgSize;

        iInitDecModule = FALSE;
      }
    }


    if(iInitDecModule == TRUE)
    {
      snprintf(cModPathName, sizeof(cModPathName), "%s/%s", cModPath, LstEMod->str);
      if((ProcQ[ProcQEntries].Decoding.dlHandle = lt_dlopenext(cModPathName)) == NULL)
      {
        log_mesg( WARN, "%s: Error while opening Module '%s{.la,.so,.sl,...}' | DlError: %s\n", cProgname, cModPathName, lt_dlerror());
        return(-2);
      }

      log_mesg( WARN, "%s: Opened Module '%s'\n", cProgname, LstEMod->str);

      /* Get Module Info (just supported by libtool >= 1.4.0) */
      if((ProcQ[ProcQEntries].Decoding.dlInfo = lt_dlgetinfo(ProcQ[ProcQEntries].Decoding.dlHandle)) == NULL)
      {
        log_mesg( WARN, "%s: Can not get Module Info | DlError: %s\n", cProgname, lt_dlerror());
        return(-3);
      }

      if(iDebug)
      {
        if(ProcQ[ProcQEntries].Decoding.dlInfo->name)
          log_mesg( WARN, "%s: Module Name: %s\n", cProgname, ProcQ[ProcQEntries].Decoding.dlInfo->name);
        else
          log_mesg( WARN, "%s: Module is not a libtool module\n", cProgname);

        log_mesg( WARN, "%s: Module Filename: %s\n", cProgname, ProcQ[ProcQEntries].Decoding.dlInfo->filename);
        log_mesg( WARN, "%s: Module Reference Count: %i\n", cProgname, ProcQ[ProcQEntries].Decoding.dlInfo->ref_count);
      }


      /* Lookup Symbol Names in Module */
      if(iDebug)
        log_mesg( WARN, "%s: Debug: Lookup Symbols\n", cProgname);

      if((ProcQ[ProcQEntries].Decoding.InitPtr = (size_t(*)(char *))lt_dlsym(ProcQ[ProcQEntries].Decoding.dlHandle, SYMNAME_INIT)) == NULL)
      {
        log_mesg( WARN, "%s: Can not get Symbol Name | DlError: %s", cProgname, lt_dlerror());
        return(-4);
      }

      if((ProcQ[ProcQEntries].Decoding.FuncPtr = (char *(*)(char *, size_t))lt_dlsym(ProcQ[ProcQEntries].Decoding.dlHandle, SYMNAME_FUNC)) == NULL)
      {
        log_mesg( WARN, "%s: Can not get Symbol Name | DlError: %s", cProgname, lt_dlerror());
        return(-5);
      }

      if((ProcQ[ProcQEntries].Decoding.ClosePtr = (int(*)(void))lt_dlsym(ProcQ[ProcQEntries].Decoding.dlHandle, SYMNAME_FUNC)) == NULL)
      {
        log_mesg( WARN, "%s: Can not get Symbol Name | DlError: %s", cProgname, lt_dlerror());
        return(-6);
      }


      /* Call Module's Init Function */
      if(iDebug)
        log_mesg( WARN, "%s: Debug: Call Encoding Modules INIT Function\n", cProgname);

      if( (ProcQ[ProcQEntries].Decoding.MsgSize = (*ProcQ[ProcQEntries].Decoding.InitPtr)(LstEConf->str)) < 0 )
      {
        log_mesg( WARN, "%s: Error while calling Init Function '%s_LTX_%s' of Module '%s'\n", cProgname, ProcQ[ProcQEntries].Decoding.dlInfo->filename, SYMNAME_INIT, ProcQ[ProcQEntries].Decoding.dlInfo->filename);
        return(-7);
      }
    } // if(iInitDecModule == TRUE)


    /*
    ** Do the Socket stuff
    */
    if(LstIP->str[0] == '/') // Unix Domain Socket
    {
      ProcQ[ProcQEntries].Decoding.SockType = UnixDomain;
      memset(&ProcQ[ProcQEntries].Decoding.SAddrUn, 0, sizeof(saddr));
      ProcQ[ProcQEntries].Decoding.SAddrUn.sun_family      = AF_LOCAL;
      strncpy(ProcQ[ProcQEntries].Decoding.SAddrUn.sun_path, LstIP->str, sizeof(ProcQ[ProcQEntries].Decoding.SAddrUn.sun_path)-1);

      if(iDebug)
        log_mesg( WARN, "%s: Setting up Unix Domain Socket: %s", cProgname, ProcQ[ProcQEntries].Decoding.SAddrUn.sun_path);

      if( (ProcQ[ProcQEntries].Decoding.iSock = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1)
      {
        log_mesg( WARN_SYS, "%s: Error while creating Unix Domain Socket for Entry %d | Syserror", cProgname, ProcQEntries+1);
        return(-8);
      }

      if(bind(ProcQ[ProcQEntries].Decoding.iSock, (saddr *) &ProcQ[ProcQEntries].Decoding.SAddrUn, SUN_LEN(&ProcQ[ProcQEntries].Decoding.SAddrUn)) != 0)
      {
        log_mesg( WARN_SYS, "%s: Error while binding Unix Domain Socket to '%s' | Syserror", cProgname, LstIP->str);
        return(-10);
      }
    }
    else    // TCP Socket
    {
      ProcQ[ProcQEntries].Decoding.SockType = IP;
      memset(&ProcQ[ProcQEntries].Decoding.SAddrIn, 0, sizeof(saddr));
      ProcQ[ProcQEntries].Decoding.SAddrIn.sin_family      = AF_INET;
      ProcQ[ProcQEntries].Decoding.SAddrIn.sin_addr.s_addr = htonl(name_resolve(LstIP->str));
      ProcQ[ProcQEntries].Decoding.SAddrIn.sin_port        = htons(atoi(LstPort->str));

      if(iDebug)
      {
        log_mesg( WARN, "%s: Setting up Network: %s:%d", cProgname, (cHostPtr = host_lookup(ntohl(ProcQ[ProcQEntries].Decoding.SAddrIn.sin_addr.s_addr))), ntohs(ProcQ[ProcQEntries].Decoding.SAddrIn.sin_port));
        free(cHostPtr);
      }

      if( (ProcQ[ProcQEntries].Decoding.iSock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
      {
        log_mesg( WARN_SYS, "%s: Error while creating Socket for Entry %d | Syserror", cProgname, ProcQEntries+1);
        return(-8);
      }

      if( setsockopt(ProcQ[ProcQEntries].Decoding.iSock, SOL_SOCKET, SO_REUSEADDR, &iOn, sizeof(iOn)) < 0 )
      {
        log_mesg( WARN_SYS, "%s: Error while setting Option SO_REUSEADDR for Server Socket!\n", cProgname);
        return(-9);
      }

      if(bind(ProcQ[ProcQEntries].Decoding.iSock, (saddr *) &ProcQ[ProcQEntries].Decoding.SAddrIn, sizeof(ProcQ[ProcQEntries].Decoding.SAddrIn)) != 0)
      {
        log_mesg( WARN_SYS, "%s: Error while binding Socket to %s:%s | Syserror", cProgname, LstIP->str, LstPort->str);
        return(-10);
      }
    }

    if(listen(ProcQ[ProcQEntries].Decoding.iSock, (int) CfgBacklog[iSectMisc]) != 0)
    {
      log_mesg( WARN_SYS, "%s: Error while start listening on Socket %s:%s | Syserror", cProgname, LstIP->str, LstPort->str ? LstPort->str : "NONE");
      return(-11);
    }



    /***********************************************
    * Let's open and initialize our Output Modules *
    ************************************************/
    if(iDebug)
      log_mesg( WARN, "%s: Debug: Init. Out Module\n", cProgname);


    // Check for duplicate Modules
    asprintf(&ProcQ[ProcQEntries].Pop.cModName, "%s", LstOMod->str);

    for(iCnt = 0; iCnt < ProcQEntries; iCnt++)
    {
      if(!strcmp(ProcQ[ProcQEntries].Pop.cModName, ProcQ[iCnt].Pop.cModName))
      {
        // copy handles and pointers
        if(iDebug)
          log_mesg( WARN, "%s: Debug: Detected duplicate Out Module '%s'\n", cProgname, ProcQ[iCnt].Decoding.cModName);

        ProcQ[ProcQEntries].Pop.dlHandle = ProcQ[iCnt].Pop.dlHandle;
        ProcQ[ProcQEntries].Pop.dlInfo   = ProcQ[iCnt].Pop.dlInfo;
        ProcQ[ProcQEntries].Pop.InitPtr  = ProcQ[iCnt].Pop.InitPtr;
        ProcQ[ProcQEntries].Pop.FuncPtr  = ProcQ[iCnt].Pop.FuncPtr;
        ProcQ[ProcQEntries].Pop.ClosePtr = ProcQ[iCnt].Pop.ClosePtr;
        ProcQ[ProcQEntries].Pop.MsgSize  = ProcQ[iCnt].Pop.MsgSize;

        iInitPopModule = FALSE;
      }
    }


    if(iInitPopModule == TRUE)
    {
      snprintf(cModPathName, sizeof(cModPathName), "%s/%s", cModPath, LstOMod->str);
      if((ProcQ[ProcQEntries].Pop.dlHandle = lt_dlopenext(cModPathName)) == NULL)
      {
        log_mesg( WARN, "%s: Error while opening Module '%s{.la,.so,.sl,...}' | DlError: %s\n", cProgname, cModPathName, lt_dlerror());
        return(-12);
      }

      log_mesg( WARN, "%s: Opened Module '%s'\n", cProgname, LstOMod->str);

      /* Get Module Info (just supported by libtool >= 1.4.0) */
      if((ProcQ[ProcQEntries].Pop.dlInfo = lt_dlgetinfo(ProcQ[ProcQEntries].Pop.dlHandle)) == NULL)
      {
        log_mesg( WARN, "%s: Can not get Module Info | DlError: %s\n", cProgname, lt_dlerror());
        return(-13);
      }

      if(iDebug)
      {
        if(ProcQ[ProcQEntries].Pop.dlInfo->name)
          log_mesg( WARN, "%s: Module Name: %s\n", cProgname, ProcQ[ProcQEntries].Pop.dlInfo->name);
        else
          log_mesg( WARN, "%s: Module is not a libtool module\n", cProgname);

        log_mesg( WARN, "%s: Module Filename: %s\n", cProgname, ProcQ[ProcQEntries].Pop.dlInfo->filename);
        log_mesg( WARN, "%s: Module Reference Count: %i\n", cProgname, ProcQ[ProcQEntries].Pop.dlInfo->ref_count);
      }


      /* Lookup Symbol Names in Module */
      if(iDebug)
        log_mesg( WARN, "%s: Debug: Lookup Symbols\n", cProgname);

      if((ProcQ[ProcQEntries].Pop.InitPtr = (size_t(*)(char *))lt_dlsym(ProcQ[ProcQEntries].Pop.dlHandle, SYMNAME_INIT)) == NULL)
      {
        log_mesg( WARN, "%s: Can not get Symbol Name | DlError: %s", cProgname, lt_dlerror());
        return(-14);
      }

      if((ProcQ[ProcQEntries].Pop.FuncPtr = (char *(*)(char *, size_t))lt_dlsym(ProcQ[ProcQEntries].Pop.dlHandle, SYMNAME_FUNC)) == NULL)
      {
        log_mesg( WARN, "%s: Can not get Symbol Name | DlError: %s", cProgname, lt_dlerror());
        return(-15);
      }

      if((ProcQ[ProcQEntries].Pop.ClosePtr = (int(*)(void))lt_dlsym(ProcQ[ProcQEntries].Pop.dlHandle, SYMNAME_FUNC)) == NULL)
      {
        log_mesg( WARN, "%s: Can not get Symbol Name | DlError: %s", cProgname, lt_dlerror());
        return(-16);
      }


      /* Call Module's Init Function */
      if(iDebug)
        log_mesg( WARN, "%s: Debug: Call Output Modules INIT Function\n", cProgname);

      if( (ProcQ[ProcQEntries].Pop.MsgSize = (*ProcQ[ProcQEntries].Pop.InitPtr)(LstOConf->str)) < 0 )
      {
        log_mesg( WARN, "%s: Error while calling Init Function '%s_LTX_%s' of Module '%s'\n", cProgname, LstOMod->str, SYMNAME_INIT, LstOMod->str);
        return(-17);
      }
    } // if(iInitPopModule == TRUE)

    ProcQ[ProcQEntries].Pop.TimeInv = (time_t) atoi(LstTInv->str);


    /***************************************************
    * Creat Ringbuffer or mmaped Cache for each Module *
    ***************************************************/

    /*
    ** Use the ringbuffer vor small timeinv.s (10 sec) and the cache
    ** for bigger timeinv.s
    ** XXX: now we just use Ringbuffers to avoid complextity!!!
    */
    if(iDebug)
      log_mesg( WARN, "%s: Debug: Setting up Cache/Ringbuffer\n", cProgname);


    if(CfgRBSize[iSectCache] <= 0 && CfgMMSize[iSectCache] <= 0)
    {
      log_mesg( WARN, "%s: RBSIZE and MMSIZE could not both be 0!\n", cProgname);
      return(-20);
    }

    if(CfgRBSize[iSectCache] <= 0)
    {
      if(iDebug)
        log_mesg( WARN, "%s: Debug: RBSIZE is lower then 0! Rinbuffer will NOT be used\n", cProgname);
    }
    else
    {
      ProcQ[ProcQEntries].Ringbuffer.rb_maxring  = CfgRBSize[iSectCache];
      ProcQ[ProcQEntries].Ringbuffer.RBSize      = CfgRBSize[iSectCache];
      ProcQ[ProcQEntries].CMethod                = Ringbuffered;

      if(iDebug)
        log_mesg( WARN, "%s: Debug: Init PThread MUTEX", cProgname);
      pthread_mutex_init(&ProcQ[ProcQEntries].Ringbuffer.rb_mutex, NULL);


      if(iDebug)
        log_mesg( WARN, "%s: Debug: RBSIZE: %d * %d = %d\n", cProgname, ProcQ[ProcQEntries].Ringbuffer.RBSize, ProcQ[ProcQEntries].Pop.MsgSize, ProcQ[ProcQEntries].Ringbuffer.RBSize * ProcQ[ProcQEntries].Pop.MsgSize);

      if((ProcQ[ProcQEntries].Ringbuffer.RB = (char *) calloc(ProcQ[ProcQEntries].Ringbuffer.RBSize, ProcQ[ProcQEntries].Pop.MsgSize)) == NULL)
      {
        log_mesg( WARN_SYS, "%s: Error: Ringbuffer = calloc(Elements = %d, Size = %d) | Syserror", cProgname, ProcQ[ProcQEntries].Ringbuffer.RBSize, ProcQ[ProcQEntries].Pop.MsgSize);
        return(-21);
      }
    }

    if(CfgMMSize[iSectCache] <= 0)
    {
      if(iDebug)
        log_mesg( WARN, "%s: Error: MMSIZE is lower then 0! Memory Mapped I/O will NOT be used\n", cProgname);
    }
    else
    {
      ProcQ[ProcQEntries].MMap.MMSize = CfgMMSize[iSectCache];
      ProcQ[ProcQEntries].CMethod     = MemMapped;

      if(CfgMMPath[iSectCache] == NULL || CfgMMPath[iSectCache] == "")
      {
        log_mesg( WARN, "%s: Error: Cache- / Memory Mapped I/O - Filename not specified\n", cProgname);
        return(-22);
      }

      if((ProcQ[ProcQEntries].MMap.MMFd = open(CfgMMPath[iSectCache], O_RDWR | O_CREAT | O_TRUNC, 0600)) < 0)
      {
        log_mesg( WARN_SYS, "%s: Error: Cache- / Memory Mapped I/O - File (%s) could not be opened/created | Syserror", cProgname, CfgMMPath[iSectCache]);
        return(-23);
      }

      /* Set Size of File */
      if(lseek(ProcQ[ProcQEntries].MMap.MMFd, (off_t) CfgMMSize[iSectCache]-1, SEEK_SET) == (off_t) -1)
      {
        log_mesg( WARN_SYS, "%s: Error: lseek(MMFd, (off_t) %d-1, SEEK_SET) | Syserror", cProgname, CfgMMSize[iSectCache]);
        return(-24);
      }

      if(write(ProcQ[ProcQEntries].MMap.MMFd, "", 1) != 1)
      {
        log_mesg( WARN_SYS, "%s: Error: Could not write to Memory Mapped I/O - Space | Syserror", cProgname);
        return(-25);
      }

      // XXX: maybe MAP_PRIVATE is not the right choice, but it seems to be faster ;-)
      if( (ProcQ[ProcQEntries].MMap.MMAddr = mmap(0, (size_t) CfgMMSize[iSectCache]-1, PROT_READ | PROT_WRITE, MAP_FILE | MAP_PRIVATE, ProcQ[ProcQEntries].MMap.MMFd, 0)) == (void *) -1)
      {
        log_mesg( WARN, "%s: Error: mmap(0, (size_t) CfgMMSize[iSectCache]-1, PROT_READ | PROT_WRITE, MAP_FILE | MAP_PRIVATE, MMFd, 0) | Syserror", cProgname);
        return(-26);
      }
    }
  } // for()


  if(ProcQEntries == 0)
  {
    log_mesg( WARN, "%s: No Entries for Encoding or Output Modules found! Please, check Config File.\n", cProgname);
    return(-30);
  }
  ProcQEntries--;

  if(LstIP != NULL)
  {
    log_mesg( WARN, "%s: Too much IP Entries! Please, check Config File.\n", cProgname);
    return(-31);
  }
  if(LstPort != NULL)
  {
    log_mesg( WARN, "%s: Too much Port Entries! Please, check Config File.\n", cProgname);
    return(-32);
  }
  if(LstEMod != NULL)
  {
    log_mesg( WARN, "%s: Too much Encoding Module Entries! Please, check Config File.\n", cProgname);
    return(-33);
  }
  if(LstEConf != NULL)
  {
    log_mesg( WARN, "%s: Too much Encoding Config Entries! Please, check Config File.\n", cProgname);
    return(-34);
  }
  if(LstTInv != NULL)
  {
    log_mesg( WARN, "%s: Too much Time Interval Entries! Please, check Config File.\n", cProgname);
    return(-35);
  }
  if(LstOMod != NULL)
  {
    log_mesg( WARN, "%s: Too much Timer Module Entries! Please, check Config File.\n", cProgname);
    return(-36);
  }
  if(LstOConf != NULL)
  {
    log_mesg( WARN, "%s: Too much Timer Config Entries! Please, check Config File.\n", cProgname);
    return(-37);
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

  void (*log_func)(int iID, const char *ccFmt, ...);



  iSectIP           = -1;
  iSectPort         = -1;
  iSectModPath      = -1;
  iSectDecModules   = -1;
  iSectDecConfFile  = -1;
  iSectPopModules   = -1;
  iSectPopConfFile  = -1;
  iSectTimInv       = -1;
  iSectCache        = -1;
  iSectSec          = -1;
  iSectMisc         = -1;

  if(Syslog == TRUE)
    log_func = log_mesg;
  else
    log_func = err_mesg;

  if(lstat(cConfFile, &StatBuf) < 0)
    log_func(FATAL_SYS, "%s: Error while trying lstat(%s) | Syserror", cProgname, cConfFile);

  if((iCfgCount = cfgParse(cConfFile, CfgIni, CFG_INI)) < 0)
    log_func(FATAL, "%s: Error while parsing Config File %s\n", cProgname, cConfFile);

  if(iCfgCount != MAXSECT)
    log_func(FATAL, "%s: Error while parsing Config File %s | Sections Read: %d | Sections Expect: %d", cProgname, cConfFile, iCfgCount, MAXSECT);

  if(iDebug)
    log_func(WARN, "%s: iCfgCount = %d\n", cProgname, iCfgCount);

  for(iCnt = 0; iCnt < iCfgCount; iCnt++)
  {
    if(iDebug)
      log_func(WARN, "%s: [%s]", cProgname, cfgSectionNumberToName(iCnt));

    if(!strcasecmp(cfgSectionNumberToName(iCnt), IPADDR))
      iSectIP = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), PORTNUM))
      iSectPort = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), MODPATH))
      iSectModPath = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), DECMODS))
      iSectDecModules = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), DECCONFFILE))
      iSectDecConfFile = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), POPMODS))
      iSectPopModules = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), POPCONFFILE))
      iSectPopConfFile = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), TIMINV))
      iSectTimInv = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), CACHE))
      iSectCache = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECNPRV))
      iSectSec = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), MISC))
      iSectMisc = iCnt;
    else
      log_func(FATAL, "%s: Error in Config File %s | Unknown Section: %s", cProgname, cConfFile, cfgSectionNumberToName(iCnt));
  }

  if(iSectIP == -1 || iSectPort == -1 || iSectModPath == -1 ||
     iSectDecModules == -1 ||  iSectDecConfFile == -1 ||
     iSectPopModules == -1 ||  iSectPopConfFile == -1 ||
     iSectTimInv == -1 || iSectCache == -1 ||
     iSectSec == -1 || iSectMisc == -1)
    log_func(FATAL, "%s: Error in Config File %s | A Section is missing!\n", cProgname, cConfFile);

  return(0);
}
