/***************************************************************************
                          main.c  -  description
                             -------------------
    begin                : Don Dez 21 18:52:52 CET 2000
    copyright            : (C) 2000 by Thomas Biege
    email                : thetom@uin4d.de
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

#define _HAVE_CAPABILITIES    // XXX


#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <setjmp.h>
#include <limits.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/uio.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
extern int errno;

//#ifdef _HAVE_CAPABILITIES
//  #include <linux/capability.h>
 // #include <linux/prctl.h>
//#endif

/*
** get libltdl/libtool from http://www.gnu.org/software/libtool
** Note from the Doc.:
** Note that libltdl is not threadsafe, i.e. a multithreaded application has to
** use a mutex for libltdl. It was reported that GNU/Linux's glibc 2.0's
** dlopen with RTLD_LAZY (which libltdl uses by default) is not thread-safe,
** but this problem is supposed to be fixed in glibc 2.1. On the other hand,
** RTLD_NOW was reported to introduce problems in multi-threaded applications
** on FreeBSD. Working around these problems is left as an exercise for the
** reader; contributions are certainly welcome.
**
** XXX: What's about using thread_safe_flag_spec in libtool script???
*/
#include <ltdl.h>

/*
** Libmcrypt has to be installed
** Get it from: http://mcrypt.hellug.gr
*/
#include <mcrypt.h>

/* LAuS */
#if defined(HAVE_LIBLAUSSRV)
  #include <linux/audit.h>
  #include <laus.h>
  #include <laussrv.h>
#endif


#include <mice.h>
#include <logformat.h>

#include "pv.h"
#include "exchangefd.h"
#include "parsecfg.h"
#include "unixdomainsocket.h"
#include "dataforwarder.h"



/*
** Defines
*/
#define USAGE(id)   err_mesg(id, "usage: %s [-d <level>] [-f <config file>] \
                                  [-u <user>] [-g <group>]\n\n", cProgname);



/*
** Typedefs
*/
typedef struct
{
  size_t  DataLen;
  char    cData[MAX_DATA];
  u_int   uiFileType;
} ShmEntry;


typedef struct
{
  char    *cName;
  int     Fd;
  FILE    *FdBuff;
  dev_t   Device;
  ino_t   Inode;
  off_t   Size;
  time_t  Atime;
  time_t  Mtime;
  time_t  Ctime;
  int     iCharDevice;
  u_int   uiType;
  int     iErrors;
} FileSpec;



/*
** Global Variables
*/
extern char      *cProgname;

// path to PID files
char            cPathMain[PATH_MAX+NAME_MAX+1];
char            cPathFdesc[PATH_MAX+NAME_MAX+1];
char            cPathLog[PATH_MAX+NAME_MAX+1];

// needed for privilege handling
struct passwd  *PwdEnt;
struct group   *GrpEnt;

// debug variable
static volatile sig_atomic_t  iDebug;


// socket for connection to SQL- and Analysis-Agent
int       SqlSock;
int       AnaSock;

pid_t     ParentPID;
pid_t     FdescServerPID;
pid_t     LogWatchPID;

int       ShmID;
int       SemID;
ShmEntry  *ShmAddr;

int       StreamPipe[2];

MCRYPT    CryptModule;


/*
** SigJmp Stuff for reconfiguring with SIGHUP
*/
static sigjmp_buf             ProcStat;
static volatile sig_atomic_t  Sig_DataReady;


/*
** Configure Stuff
*/
char      *cConfFile;

char      **CfgSyslogFac;
char      **CfgSQLIP;
char      **CfgSQLProto;
char      **CfgASIP;
char      **CfgASProto;
char      **CfgUser;
char      **CfgGroup;
char      **CfgEncKey;
char      **CfgDevRandom;
char      **CfgCryptMod;
char      **CfgPidPath;
char      **CfgChrootPath;
char      **CfgModPath;
char      **CfgModConfFilter;
char      **CfgModConfFormat;
char      **CfgModConfPseudo;
char      **CfgModFilter;
char      **CfgModFormat;
char      **CfgModPseudo;
int       *CfgEncrypt;
int       *CfgPseudo;
int       *CfgFilter;
int       *CfgSQLPort;
int       *CfgASPort;
int       *CfgShmSize;
int       *CfgReconnect;
long      *CfgSleepInv;
cfgList   **CfgFileList;

int       iSectSQL;
int       iSectAna;
int       iSectSec;
int       iSectLog;
int       iSectModPath;
int       iSectModules;
int       iSectModConf;
int       iSectMisc;

cfgStruct CfgIni[] =
{
  // Sql Section
  {"SQLPORT"        ,CFG_INT          ,&CfgSQLPort        },
  {"SQLIP"          ,CFG_STRING       ,&CfgSQLIP          },
  {"SQLPROTO"       ,CFG_STRING       ,&CfgSQLProto       },

  // Analysis Unit Section
  {"ASPORT"         ,CFG_INT          ,&CfgASPort         },
  {"ASIP"           ,CFG_STRING       ,&CfgASIP           },
  {"ASPROTO"        ,CFG_STRING       ,&CfgASProto        },

  // Security and Privacy Section
  {"ENCRYPT"        ,CFG_BOOL         ,&CfgEncrypt        },
  {"PSEUDO"         ,CFG_BOOL         ,&CfgPseudo         },
  {"FILTER"         ,CFG_BOOL         ,&CfgFilter         },
  {"USER"           ,CFG_STRING       ,&CfgUser           },
  {"GROUP"          ,CFG_STRING       ,&CfgGroup          },
  {"CHROOT"         ,CFG_STRING       ,&CfgChrootPath     },
  {"ENCKEY"         ,CFG_STRING       ,&CfgEncKey         },
  {"DEVRANDOM"      ,CFG_STRING       ,&CfgDevRandom      },
  {"CRYPTMOD"       ,CFG_STRING       ,&CfgCryptMod       },

  // Log Files Section
  {"FILE"           ,CFG_STRING_LIST  ,&CfgFileList       },

  // Modules Search Path Section
  {"MODPATH"        ,CFG_STRING       ,&CfgModPath        },

  // Modules Section
  {"MOD_FILTER"     ,CFG_STRING       ,&CfgModFilter      },
  {"MOD_LOGFORMAT"  ,CFG_STRING       ,&CfgModFormat      },
  {"MOD_PSEUDONYM"  ,CFG_STRING       ,&CfgModPseudo      },

  // Modules Conf Section
  {"FILTERCONF"     ,CFG_STRING       ,&CfgModConfFilter  },
  {"LOGFORMATCONF"  ,CFG_STRING       ,&CfgModConfFormat  },
  {"PSEUDONYMCONF"  ,CFG_STRING       ,&CfgModConfPseudo  },

  // Misc Section
  {"SHMSIZE"        ,CFG_INT          ,&CfgShmSize        },
  {"SLEEPINV"       ,CFG_LONG         ,&CfgSleepInv       },
  {"RECONNECT"      ,CFG_INT          ,&CfgReconnect      },
  {"PIDPATH"        ,CFG_STRING       ,&CfgPidPath        },
  //{"SYSLOGFAC"  ,CFG_INT          ,&CfgSyslogFac  },

  {NULL             ,CFG_END          ,NULL               }
};


/*
** Subroutine Definition
*/
void  voidLogWatch(void);    // own process
void  voidFdescServer(void); // own process
void  voidSigChild(int id);
void  voidSigHup(int id);
void  voidSigUsr1_2(int id);
void  voidSigUnused(int id);
void  voidSigTermination(int id);
void  voidSerialKiller_1(void);
void  voidCleanUp(void);
void  voidCfgFatalFunc(cfgErrorCode ErrCode, const char *Str1 , int iDummy, const char *Str2);
void  DBG(int threshold, const char *str, ...);

int   intAbrakadabra(void);
int   intHandleClientRequest(char *cRequest, int iByteCount, int Pipe);
int   intParseClientRequest(char *cRequest, int *Argc, char *Argv[]);
int   intHandleConfFile(int Syslog);
int   intReadFile(char *cData, size_t DataSize, FILE *DataStream, u_int uiType);


/*********************************************************************
*
* M A I N
*
*********************************************************************/
int main(int argc, char *argv[])
{
  char                        *cKey;
  char                        *cPassword;
  char                        cModPathName[PATH_MAX+NAME_MAX+1];

  int                         iOpt;
  int                         iSec;
  register int                iCnt;

  int                         (*modFormatInit)(char *)                              = 0;
  int                         (*modFormatFunc)(LogFormat *, char *, size_t, u_int)  = 0;
  int                         (*modFilterInit)(char *)                              = 0;
  int                         (*modFilterFunc)(LogFormat *, u_int)                  = 0;
  int                         (*modPseudoInit)(char *)                              = 0;
  int                         (*modPseudoFunc)(LogFormat *, u_int)                  = 0;

  uid_t                       eUID = geteuid();
  uid_t                       rUID = getuid();
  gid_t                       eGID = getegid();
  gid_t                       rGID = getgid();
  size_t                      KeySize = 16;  /* 128 Bit Key */

  struct sigaction            SigAction;

  ShmEntry                    ShmDataBuf;
  CipherMsg                   Message;
  LogFormat                   *LogEntry = (LogFormat *) &Message.cCipherText;
  lt_dlhandle                 dlHandleFilter;
  lt_dlhandle                 dlHandleFormat;
  lt_dlhandle                 dlHandlePseudo;



  cProgname = "DataForwarder/Main";  // argv[0];



  /*
  ** First let's check, that we didn't run
  ** set[gu]id, because this code was not designed to be set[gu]id
  ** and I don't like it! *eg*
  */
  if(rUID != eUID || rGID != eGID)
    err_mesg(FATAL, "%s: Do NOT run me as set[ug]id app, it's NOT neccessary and I do NOT like it! Run me as user root from the boot scripts. :-)\n", cProgname);


  /*
  ** Read Commanline Options.
  */
  cConfFile   = PATHCONFFILE;

  iDebug = 0;

  opterr = 0;
  while((iOpt = getopt(argc, argv, "f:d:")) != EOF)
  {
    switch(iOpt)
    {
      case 'f':	if(optarg == NULL || optarg[0] == '-')
                  USAGE(FATAL)
                if((cConfFile = strdup(optarg)) == NULL)
                  err_mesg(FATAL_SYS, "%s: strdup(CONFILE)\nSyserror", cProgname);
                break;
      case 'd': if(optarg == NULL || optarg[0] == '-' || !isdigit(optarg[0]))
                  USAGE(FATAL)
                iDebug = atoi(optarg);
                break;
      default:  USAGE(FATAL)
    }
  }


  /*
  ** Open Syslog
  */
  log_open(cProgname, LOG_PID, LOG_DAEMON); // XXX: CfgSyslogFac[iSectMisc]);
  _err_pname = cProgname;


  log_mesg(WARN, "%s: Starting...", cProgname);


  /*
  ** Parse Conf File
  ** Redo this when receiving SIGHUP
  ** Security: The Config File has to be in a secure Directory. The Directory and File have to be just
  **           writeable by root.
  **           I really love parsecfg.c but don't trust parsecfg.c to be bugfree, so this Code avoids
  **           to run set[ug]id.
  */
  intHandleConfFile(0);


  /*
  ** Daemon Spell
  */
  if(intAbrakadabra() < 0)
    err_mesg(FATAL_SYS, "%s: Abrakadabra: Something is wrong with my Magic Formula *+~#'%**\n", cProgname);

  ParentPID = getpid();


  /*
  ** Get Passwd and Group Entry
  */
  if(!(PwdEnt = getpwnam(CfgUser[iSectSec])) || !(GrpEnt = getgrnam(CfgGroup[iSectSec])))
    err_mesg(FATAL_SYS, "%s: Can not get passwd/user (%s) or group (%s) entry!\nSyserror", cProgname, CfgUser[iSectSec], CfgGroup[iSectSec]);


  /*
  ** Drop root Privileges and change to another User and Group.
  ** Keep EUID 0 for FdescServer!
  ** We do this to reduce the Risk by exploiting some unknown Bugs
  ** via Log Entries.
  ** Chroot'ing!? XXX
  */
  DBG(2, "Set new Privileges");
  if(setgroups(0, NULL) < 0)
    log_mesg(FATAL_SYS, "%s: setgroups(0, NULL)\n", cProgname);
  if(setgid(GrpEnt->gr_gid) < 0 || setreuid(0, PwdEnt->pw_uid) < 0)
    log_mesg(FATAL_SYS, "%s: Can not set GID/[E]UID\n", cProgname);


  /*
  ** Creat PID File
  */
  DBG(2, "Create PID File");
  if(CfgPidPath[iSectMisc] == NULL)
    log_mesg(FATAL, "%s: main: Fatal: You did not set the PIDPATH!", cProgname);

  snprintf(cPathMain, sizeof(cPathMain), "%s/%s", CfgPidPath[iSectMisc], PIDMAIN);
  switch(make_pidfile(cPathMain, 1))
  {
    case -100:
      log_mesg(FATAL, "%s: main: PID file: resulting string too long\n", cProgname);
    case -101:
      log_mesg(FATAL, "%s: main: PID file: cannot create temp. file\n", cProgname);
    case -1:
      log_mesg(FATAL, "%s: main: PID file: cannot rename/link temp. file\n", cProgname);
  }


  /*
  ** Let's Open the Sockets, before we start the Monitor Processes
  */
  DBG(1, "Open Connection to SQL Server and Analysis Server");

  iSec = 0;
  SqlSock = AnaSock = -666;
  do
  {
    sleep(iSec);

    if(CfgSQLIP[iSectSQL] != NULL && CfgSQLPort[iSectSQL] != 0 && SqlSock < 0)
    {
      if((SqlSock = tcp_open(CfgSQLIP[iSectSQL], NULL, CfgSQLPort[iSectSQL])) == -1)
        log_mesg(WARN, "%s: Error while opening Socket to SQL Server [%s:%d]. (%d)", cProgname, CfgSQLIP[iSectSQL], CfgSQLPort[iSectSQL], SqlSock);
    }

    if(CfgASIP[iSectAna] != NULL && CfgASPort[iSectAna] != 0 && AnaSock < 0)
    {
      if((AnaSock = tcp_open(CfgASIP[iSectAna], NULL, CfgASPort[iSectAna])) == -1)
        log_mesg(WARN, "%s: Error while opening Socket to Analysis Server [%s:%d]. (%d)", cProgname, CfgASIP[iSectAna], CfgASPort[iSectAna], AnaSock);
    }

    if(SqlSock == -666 && AnaSock == -666)
      log_mesg(FATAL, "%s: Error: Neither SQL nor Analysis Server specified in Config File!\n", cProgname);

    if( ++iSec >= CfgReconnect[iSectMisc])
      log_mesg(WARN, "%s: main: Fatal: Give up connecting to SQL- and/or Analysis-Agent! We try it again later.", cProgname);

  } while(SqlSock == -1 || AnaSock == -1);


  /*
  ** Setting Parse Error Function.
  ** This will print an Error Message to Syslog not Stderr
  ** We need this for Runtime Reconfiguration via SIGHUP.
  */
  cfgSetFatalFunc(voidCfgFatalFunc);


  /*
  ** Install new Signal Handler
  */
  DBG(1, "Install Signal Handlers");

  if(set_signal(SIGCHLD, voidSigChild) != 0)
    log_mesg(FATAL_SYS, "%s: set_signal(SIGCHLD) | Syserror", cProgname);

  if(set_signal(SIGHUP, voidSigHup) != 0)
    log_mesg(FATAL_SYS, "%s: set_signal(SIGHUP) | Syserror", cProgname);

  if(set_signal(SIGUSR1, voidSigUsr1_2) != 0)
    log_mesg(FATAL_SYS, "%s: set_signal(SIGUSR1) | Syserror", cProgname);
  if(set_signal(SIGUSR2, voidSigUsr1_2) != 0)
    log_mesg(FATAL_SYS, "%s: set_signal(SIGUSR2) | Syserror", cProgname);

  if(set_signal(SIGINT, voidSigTermination) != 0)
    log_mesg(FATAL_SYS, "%s: set_signal(SIGINT) | Syserror", cProgname);
  if(set_signal(SIGQUIT, voidSigTermination) != 0)
    log_mesg(FATAL_SYS, "%s: set_signal(SIGQUIT) | Syserror", cProgname);
  if(set_signal(SIGTERM, voidSigTermination) != 0)
    log_mesg(FATAL_SYS, "%s: set_signal(SIGTERM) | Syserror", cProgname);


  /*
  ** Install Clean Up Routine
  */
  if(atexit(voidCleanUp) != 0)
    log_mesg(FATAL_SYS, "%s: atexit(voidCleanUp) | Syserror", cProgname);


  /*
  ** Establish Unix Domain Socket
  ** - StreamPipe[0] will be used by LogWatch
  ** - StreamPipe[1] will be used by FdescServer
  */
  if(intUDSockPair(StreamPipe) < 0)
    log_mesg(FATAL_SYS, "%s: intUDSockPair()\n", cProgname);


  /*
  ** Fork FdescServer
  ** The FdescServer will drop it's root Privileges
  ** and just keeps CAP_DAC_OVERWRITE to be able to
  ** open Files.
  */
  DBG(1, "Start FdesServer Process");
  if((FdescServerPID = fork()) < 0)
    log_mesg(FATAL_SYS, "%s: #1 fork() failed\n", cProgname);
  else if(FdescServerPID == 0)
    voidFdescServer();



  /************************************************************
  **                      Parent Process                     **
  ************************************************************/

  /*
  ** Close one End of the Unix Domain Socket
  */
  close(StreamPipe[1]);


  /*
  ** Now we also drop EUID, we dont need it
  */
  DBG(2, "Drop root Privilege entirely");
  if(seteuid(0) < 0 ||  setuid(PwdEnt->pw_uid) < 0)
    log_mesg(FATAL_SYS, "%s: Can not drop root Privilege entirely\n", cProgname);

  //log_mesg(WARN, "UID = %d, EUID = %d, GID = %d, EGID = %d", getuid(), geteuid(), getgid(), getegid());


  /*
  ** Set up Shared Memory and Semaphore
  ** We (main) communicate with LogWatch via the Shared Memory
  ** do i need another shm segment, which should be used if the first on is blocked? XXX :-\
  */
  DBG(1, "Set Up Shared Memory");

  if((ShmID = shmget(IPC_PRIVATE, CfgShmSize[iSectMisc], S_IRUSR | S_IWUSR | IPC_CREAT | IPC_EXCL)) == -1)
    log_mesg(FATAL_SYS, "%s: shmget()\n", cProgname);
  if((ShmAddr = (ShmEntry *) shmat(ShmID, NULL, 0)) == (void *) -1)
    log_mesg(FATAL_SYS, "%s: shmat()\n", cProgname);

  DBG(1, "Set Up Semaphore");

  if((SemID = semget(IPC_PRIVATE, 1, S_IRUSR | S_IWUSR | IPC_CREAT | IPC_EXCL)) == -1)
    log_mesg(FATAL_SYS, "%s: semget()\n", cProgname);
  if(semctl(SemID, 0, SETVAL, (int) 1) == -1)
    log_mesg(FATAL_SYS, "%s: semctl(SETVAL, 1)\n", cProgname);


  /*
  ** Fork Log Watcher
  */
  DBG(1, "Start LogWatch Process");
  if((LogWatchPID = fork()) < 0)
    log_mesg(FATAL_SYS, "%s: #2 fork()\n", cProgname);
  else if(LogWatchPID == 0)
    voidLogWatch();


  /*
  ** Init. libltdl
  */
  if(lt_dlinit())
    log_mesg(FATAL_SYS, "%s: Error while trying to initialize libltdl | Syserror", cProgname);


  /*
  ** Init. RegEx-, LogFormat- and Pseudonymizer-Module
  */
  DBG(1, "Init. Modules and Lookup Symbols");


  if(CfgModFormat[iSectModules])
  {
    snprintf(cModPathName, sizeof(cModPathName), "%s/%s", CfgModPath[iSectModPath], CfgModFormat[iSectModules]);

    if((dlHandleFormat = lt_dlopenext(cModPathName)) == NULL)
      log_mesg(FATAL, "%s: Error while opening Module '%s{.la,.so,.sl,...}' | DlError: %s\n", cProgname, cModPathName, lt_dlerror());

    if((modFormatInit = (int(*)(char *))lt_dlsym(dlHandleFormat, SYMNAME_INIT)) == NULL)
      log_mesg(FATAL, "%s: Can not get Symbol Name | DlError: %s", cProgname, lt_dlerror());
    if((modFormatFunc = (int(*)(LogFormat *, char *, size_t, u_int))lt_dlsym(dlHandleFormat, SYMNAME_FUNC)) == NULL)
      log_mesg(FATAL, "%s: Can not get Symbol Name | DlError: %s", cProgname, lt_dlerror());

    DBG(1, "Call Logformat-Module's INIT Function");
    if( (*modFormatInit)(CfgModConfFormat[iSectModConf]) < 0 )
      log_mesg(FATAL, "%s: Error while calling Init Function '%s_LTX_%s' of Module '%s'\n", cProgname, CfgModFormat[iSectModules], SYMNAME_INIT, CfgModFormat[iSectModules]);
  }

  if(CfgModFilter[iSectModules] && CfgFilter[iSectSec])
  {
    snprintf(cModPathName, sizeof(cModPathName), "%s/%s", CfgModPath[iSectModPath], CfgModFilter[iSectModules]);

    if((dlHandleFilter = lt_dlopenext(cModPathName)) == NULL)
      log_mesg(FATAL, "%s: Error while opening Module '%s{.la,.so,.sl,...}' | DlError: %s\n", cProgname, cModPathName, lt_dlerror());

    if((modFilterInit = (int(*)(char *))lt_dlsym(dlHandleFilter, SYMNAME_INIT)) == NULL)
      log_mesg(FATAL, "%s: Can not get Symbol Name | DlError: %s", cProgname, lt_dlerror());

    if((modFilterFunc = (int(*)(LogFormat *, u_int))lt_dlsym(dlHandleFilter, SYMNAME_FUNC)) == NULL)
      log_mesg(FATAL, "%s: Can not get Symbol Name | DlError: %s", cProgname, lt_dlerror());

    DBG(1, "Call Filter-Module's INIT Function");
    if( (*modFilterInit)(CfgModConfFilter[iSectModConf]) < 0 )
      log_mesg(FATAL, "%s: Error while calling Init Function '%s_LTX_%s' of Module '%s'\n", cProgname, CfgModFilter[iSectModules], SYMNAME_INIT, CfgModFilter[iSectModules]);
  }

  if(CfgModPseudo[iSectModules] && CfgPseudo[iSectSec])
  {
    snprintf(cModPathName, sizeof(cModPathName), "%s/%s", CfgModPath[iSectModPath], CfgModPseudo[iSectModules]);
    if((dlHandlePseudo = lt_dlopenext(cModPathName)) == NULL)
      log_mesg(FATAL, "%s: Error while opening Module '%s{.la,.so,.sl,...}' | DlError: %s\n", cProgname, cModPathName, lt_dlerror());

    if((modPseudoInit = (int(*)(char *))lt_dlsym(dlHandlePseudo, SYMNAME_INIT)) == NULL)
      log_mesg(FATAL, "%s: Can not get Symbol Name | DlError: %s", cProgname, lt_dlerror());
    if((modPseudoFunc = (int(*)(LogFormat *, u_int))lt_dlsym(dlHandlePseudo, SYMNAME_FUNC)) == NULL)
      log_mesg(FATAL, "%s: Can not get Symbol Name | DlError: %s", cProgname, lt_dlerror());

    DBG(1, "Call Pseudo-Module's INIT Function");
    if( (*modPseudoInit)(CfgModConfPseudo[iSectModConf]) < 0 )
      log_mesg(FATAL, "%s: Error while calling Init Function '%s_LTX_%s' of Module '%s'\n", cProgname, CfgModPseudo[iSectModules], SYMNAME_INIT, CfgModPseudo[iSectModules]);
  }


  /*
  ** Init the Crypto Stuff
  */
  if(CfgEncrypt[iSectSec])
  {
    DBG(1, "Init. Cryptographie Module");

    if((cKey = calloc(1, KeySize)) == NULL)
      log_mesg(FATAL, "%s: Error while allocating Memory for Twofish Key\n", cProgname);

    if((cPassword = calloc(1, strlen(CfgEncKey[iSectSec])+1)) == NULL)
      log_mesg(FATAL, "%s: Error while allocating Memory for Encryption Key\n", cProgname);

    strcpy(cPassword, CfgEncKey[iSectSec]);

    /*
    ** Generate the Key using the Password
    ** Why do we not need this? XXX
    ** mhash_keygen(KEYGEN_MCRYPT, MHASH_MD5, cKey, cKeySize, NULL, 0, cPassword, strlen(cPassword));
    */

    memmove(cKey, cPassword, KeySize);

    if((CryptModule = mcrypt_module_open(CfgCryptMod[iSectSec], NULL, "cfb", NULL)) == MCRYPT_FAILED)
      log_mesg(FATAL, "%s: Error while trying to load Crypto Module '%s'\n", cProgname, CfgCryptMod[iSectSec]);

    Message.IVLen = mcrypt_enc_get_iv_size(CryptModule);
    if(Message.IVLen != 16)
      log_mesg(FATAL, "%s: IV Length is not equal to 16! Please check if 'Twofish' Crypto Algo. is enabled.", cProgname);

    //if((IV = (char *) malloc(Message.IVLen))) == NULL)
      //log_mesg(FATAL, "%s: Error while allocating Memory for IV ('Initialisierungsvektor')\n", cProgname);

    /*
    ** Test Module
    *
    if(mcrypt_enc_self_test(CryptModule))
      log_mesg(FATAL, "%s: Error occured while doing Selftest on Crypto Module\n", cProgname);
    */
  }
  else
    Message.IVLen = 0;  // plaintext mode


  /*
  ** Set SIGUNUSED for synchronisation with LogWatch Process
  */
  DBG(1, "Set SIGUNUSED Handler");

  SigAction.sa_handler = voidSigUnused;
  sigemptyset(&SigAction.sa_mask);
  if(sigaction(SIGUNUSED, &SigAction, NULL) < 0)
    log_mesg(FATAL_SYS, "%s: Error: sigaction(SIGUNUSED) | Syserror", cProgname);

  Sig_DataReady = FALSE;



  /*************************************************************************************
  **
  **                        Read Data and Process it. Main Loop!
  **
  *************************************************************************************/

  DBG(1, "Start reading Data from Shared Memory");

  while(TRUE)
  {
    memset(&ShmDataBuf        , 0, sizeof(ShmEntry));
    memset(Message.cCipherText, 0, sizeof(Message.cCipherText));  /* LogEntry points to Message.cCipherText */


    /*
    ** The LogWatch Process will send us a SIGUSR1 if there
    ** is something to read.
    */
    DBG(1, "Waiting on SIGUNUSED...");

    sigsuspend(&SigAction.sa_mask);
    if(Sig_DataReady != TRUE)
      continue;

    DBG(1, "Cought SIGUNUSED... let's go!");


    /*
    ** 1. Decrement Semaphore
    ** 2. Read the Data
    ** 3. Increment Semaphore to indicate, that we are done
    */
    DBG(3, "Semaphore: P()");

    P(SemID);

    memcpy(&ShmDataBuf, ShmAddr, sizeof(ShmEntry));

    Sig_DataReady = FALSE;

    V(SemID);

    DBG(3, "Semaphore: V()");

    //log_mesg(WARN, "Read Shared Memory Data: %s\n", ShmDataBuf.cData);


    /*
    ** Standard Log Format-Module
    */
    if(CfgModFormat[iSectModules])
    {
      DBG(1, "Standard Log Format-Module");
      if(modFormatFunc((LogFormat *) &Message.cCipherText, ShmDataBuf.cData, ShmDataBuf.DataLen, ShmDataBuf.uiFileType) != 0)
        continue; // error occured, ignore line :-(
    }

    
    /*
    ** Filter-Module
    */
    if(CfgFilter[iSectSec] && CfgModFilter[iSectModules])
    {
      DBG(1, "Filter-Module");
      if(modFilterFunc((LogFormat *) &Message.cCipherText, ShmDataBuf.uiFileType) == 1)
        continue;   // user wants to ignore this line
    }
    // even on error we proceed here


    /*
    ** Pseudonymizer-Module
    */
    if(CfgPseudo[iSectSec] && CfgModPseudo[iSectModules])
    {
      DBG(1, "Pseudonymizer-Module");
      modPseudoFunc((LogFormat *) &Message.cCipherText, ShmDataBuf.uiFileType);
    }

    /* XXX: should it be done here or in the format-module? */
    LogEntry->uiFileType = ShmDataBuf.uiFileType;
    

    /*
    ** Encrypt Data
    ** We don't need a 100% unbreakable Ciphertext, because the Information we try to
    ** protect isn't very valueable. Encryption is just used to hide Data from the
    ** Eyes of the Attacker, so s/he doesn't know what's been logged in Realtime.
    */
    if(CfgEncrypt[iSectSec])
    {
      DBG(1, "Encrypt Data");

      /*
      ** Put "random" Data in IV.
      */
      memset(Message.IV, 0, Message.IVLen);
      srand(time(0));
      for(iCnt = 0; iCnt < Message.IVLen; iCnt++)
        Message.IV[iCnt] = rand();

      if(mcrypt_generic_init(CryptModule, cKey, KeySize, Message.IV) < 0)
        log_mesg(FATAL, "%s: Error while initializing Crypto Module\n", cProgname);

      /*
      ** We just are able to use Byte-by-Byte Encryption.
      ** This sux because it's very slow. XXX
      */
      for(iCnt = 0; iCnt < sizeof(LogFormat); iCnt++)
        mcrypt_generic(CryptModule, &Message.cCipherText[iCnt], 1);

      if(mcrypt_generic_deinit(CryptModule) < 0)
        log_mesg(WARN, "%s: Error while clearing Crypto Module!\n", cProgname);
    }

    Message.CipherTextLen = sizeof(LogFormat);
    

    DBG(5, "Send Data [%s] to SQL Server and Analysis Server", LogEntry->cLogdata);

    /*
    ** Send Data to MySQL Server.
    ** We have a Daemon running there, which decrypts our Data
    ** and stores it in the SQL Database.
    */
    if(SqlSock != -666)
    {
      if(writen(SqlSock, (char *) &Message, sizeof(Message)) < 0)
      {
        log_mesg(WARN, "%s: Error while sending Data to SQL Server. Try to reopen Connection...\n", cProgname);

        close(SqlSock);

        if((SqlSock = tcp_open(CfgSQLIP[iSectSQL], NULL, CfgSQLPort[iSectSQL])) < 0)
          log_mesg(WARN, "%s: Error while opening Socket to SQL Server.\n", cProgname);

        if(writen(SqlSock, (char *) &Message, sizeof(Message)) < 0)
        {
          log_mesg(WARN, "%s: Error while sending Data to SQL Server. Skipping Log Entry!", cProgname);
          //close(SqlSock);
          //exit(-1); // XXX exit or do it again.. dunno
        }
      }
    }


    /*
    ** Send Data to Analysis Unit
    */
    if(AnaSock != -666)
    {
      if(writen(AnaSock, (char *) &Message, sizeof(Message)) < 0)
      {
        log_mesg(WARN, "%s: Error while sending Data to Analysis Server. Try to reopen Connection...\n", cProgname);

        close(AnaSock);

        if((AnaSock = tcp_open(CfgASIP[iSectAna], NULL, CfgASPort[iSectAna])) < 0)
          log_mesg(WARN, "%s: Error while opening Socket to Analysis Server.\n", cProgname);

        if(writen(AnaSock, (char *) &Message, sizeof(Message)) < 0)
        {
          log_mesg(WARN, "%s: Error while sending Data to Analysis Server. Skipping Log Entry!", cProgname);
          //close(AnaSock);
          //exit(-1); // XXX exit or do it again.. dunno
        }
      }
    }

  }

  // Neverever reached
  return EXIT_SUCCESS;
}


/********************************************************
*
* S U B R O U T I N E S
*
********************************************************/


/*
** voidLogWatch (LW)
** The LW Process asks the FdescServer Process via a Stream Pipe/
** Unix Domain Socket to open Files to monitor.
** New Entries in the Files will be passed to the Parent Process
** via the Shared Memory Segment.
**
*/
void voidLogWatch(void) // own process
{
  char            cMode[10];
  char            cCmd[10];
  //char            cBuf[100];

  int             iFdIdx;
  int             iBytesRead, iTotalBytesRead;
  int             iDelayOrig, iDelay, iDelayLeft;
  register int    iCnt;

  struct iovec    IOV[3];
  struct stat     StatBuf;
  //struct timeval  TimeInv;

  size_t          AmountToRead;
  size_t          DiffSize;
  //sigset_t        SigSet;

  FileSpec        *FileInfo = NULL;
  ShmEntry        ShmData;
  cfgList         *FileList;



  _err_pname = cProgname = "DataForwarder/LogWatch";


  /*
  ** Create PID File
  *
  DBG(2, "Create PID File");
  snprintf(cPathLog, sizeof(cPathLog), "%s/%s", CfgPidPath[iSectMisc], PIDLOGWA);
  if(make_pidfile(cPathLog, 0) < 0)
    log_mesg(FATAL, "%s: voidLogWatch(): Fatal: Error while creating pid file!\n", cProgname);
  */

  snprintf(cMode, sizeof(cMode), " %o", S_IRUSR);


  /*
  ** If (the User had changed the Conf File and) we received a SIGHUP
  ** we have to re-read the File List an reopen the Files
  */
  DBG(1, "Set Jump Point");

  if(sigsetjmp(ProcStat, TRUE))
  {
    // WHY DOES IT NOT WORK?!?!? XXX
    DBG(1, "Clean File List");

    for(iCnt = 0; iCnt <= iFdIdx; iCnt++)
    {
      free(FileInfo[iCnt].cName);
      free(&FileInfo[iCnt]);
    }
    FileInfo = NULL;
  }


  /*
  ** Send open Requests to FdescServer Process via Stream Pipe
  */
  strncpy(cCmd, FS_CMD_OPEN, sizeof(cCmd)-1);


  DBG(2, "Open File List, Cmd: '%s'", cCmd);

  for(FileList = CfgFileList[iSectLog], iFdIdx = 0; FileList != NULL; FileList = FileList->next, iFdIdx++)
  {
    char *FileName = NULL;

    if( (FileName = strstr(FileList->str, "/")) == NULL )
      continue;

    memset(&IOV, 0, sizeof(IOV));

    IOV[0].iov_base = cCmd;
    IOV[0].iov_len  = strlen(cCmd);
    IOV[1].iov_base = FileName;
    IOV[1].iov_len  = strlen(FileName);
    IOV[2].iov_base = cMode;
    IOV[2].iov_len  = strlen(cMode)+1;  /* +1, because of terminating \0 */

    DBG(1, "Send Request to FdescServer");

    if( writev(StreamPipe[0], IOV, 3) != (IOV[0].iov_len + IOV[1].iov_len + IOV[2].iov_len) )
      log_mesg(WARN_SYS, "%s: Error while sending Request '%s%s%s' via to FdescServer | Syserror", cProgname, cCmd, CfgFileList[iSectLog]->str, cMode);

    DBG(2, "Realloc Memory for FileInfo Array");

    if((FileInfo = (FileSpec *) realloc(FileInfo, (iFdIdx+1) * sizeof(FileSpec))) == NULL)
      log_mesg(FATAL_SYS, "%s: Error while trying to reserve Memory for File Info. Array (Idx = %d) | Syserror", cProgname, iFdIdx);

    FileInfo[iFdIdx].Fd = intRecvFd(StreamPipe[0]);

    DBG(2, "Received File Descriptor '%ld' from FdescServer for '%s'", FileInfo[iFdIdx].Fd, FileName);

    if(FileInfo[iFdIdx].Fd < 0)
    {
      switch(FileInfo[iFdIdx].Fd)
      {
        case XFD_ERR_OPEN:
          log_mesg(WARN_SYS, "%s: Error: XFD_ERR_OPEN | Syserror", cProgname);
          break;
        case XFD_ERR_MISSINGNULL:
          log_mesg(FATAL, "%s: Error: XFD_ERR_MISSINGNULL", cProgname);
          break;
        case XFD_ERR_PARSE:
          log_mesg(FATAL, "%s: Error: XFD_ERR_PARSE", cProgname);
          break;
        case XFD_ERR_TERM:
          log_mesg(FATAL, "%s: Error: XFD_ERR_TERM", cProgname);
          break;
        case XFD_ERR_STAT:
          log_mesg(WARN, "%s: Error: XFD_ERR_STAT", cProgname);
          FileInfo[iFdIdx].Fd = -1;
          break;
        case XFD_ERR_FILETYPE:
          log_mesg(FATAL, "%s: Error: XFD_ERR_FILETYPE", cProgname);
          break;
        default:
          log_mesg(WARN, "%s: Error: XFD_ERR_UNKNOWN!!!", cProgname);
          FileInfo[iFdIdx].Fd = -1;
      }
    }

    DBG(3, "FileInfo[%d].cName <- '%s'", iFdIdx, FileName);


    if((FileInfo[iFdIdx].cName = strdup(FileName)) == NULL)
      log_mesg(FATAL_SYS, "%s: Error while trying strdup(%s) | Syserror", cProgname, FileName);


    /*
    ** Just request Stat Information for __existing__ Files
    */
    if(FileInfo[iFdIdx].Fd >= 0)
    {

      DBG(1, "Updating FileInfo");

      if(fstat(FileInfo[iFdIdx].Fd, &StatBuf) < 0) // XXX: try again later or abort?
      {
        log_mesg(WARN_SYS, "%s: Error while trying fstat(%s) | Syserror", cProgname, FileName);
        FileInfo[iFdIdx].Fd = -1;
        continue;
      }

      FileInfo[iFdIdx].FdBuff      = fdopen(FileInfo[iFdIdx].Fd, "r");
      FileInfo[iFdIdx].Device      = StatBuf.st_dev;
      FileInfo[iFdIdx].Inode       = StatBuf.st_ino;
      FileInfo[iFdIdx].Size        = StatBuf.st_size;
      FileInfo[iFdIdx].Atime       = StatBuf.st_atime;
      FileInfo[iFdIdx].Mtime       = StatBuf.st_mtime;
      FileInfo[iFdIdx].Ctime       = StatBuf.st_ctime;
      FileInfo[iFdIdx].iErrors     = 0;

      DBG(3, "Set Filetype = FTF_UNKNOWN (%s)", FileList->str);
      FileInfo[iFdIdx].uiType = FTF_UNKNOWN;
      if(strstr(FileList->str, FTT_FILE) != NULL)
      {
        DBG(3, "Set Filetype = FTF_FILE");
        FileInfo[iFdIdx].uiType = FTF_FILE;
      }
      else if(strstr(FileList->str, FTT_LAUS) != NULL)
      {
        DBG(3, "Set Filetype = FTF_LAUS");
        FileInfo[iFdIdx].uiType = FTF_LAUS;
      }
      else if(strstr(FileList->str, FTT_SCSLOG) != NULL)
      {
        DBG(3, "Set Filetype = FTF_SCSLOG");
        FileInfo[iFdIdx].uiType = FTF_SCSLOG;
      }

      if(S_ISREG(StatBuf.st_mode))
      {
        FileInfo[iFdIdx].iCharDevice = FALSE;
        /* XXX this is not useful for LAuS bin files */
        DBG(2, "lseek(%s ,(off_t) 0, SEEK_END)", FileInfo[iFdIdx].cName);
        if(lseek(FileInfo[iFdIdx].Fd, (off_t) 0, SEEK_END) == (off_t) -1)
          log_mesg(FATAL_SYS, "%s: Error: lseek(FileInfo[iFdIdx].Fd ,(off_t) 0, SEEK_END) | Syserror:", cProgname);
        if(fseek(FileInfo[iFdIdx].FdBuff, (off_t) 0, SEEK_END) == -1)
          log_mesg(FATAL_SYS, "%s: Error: fseek(FileInfo[iFdIdx].FdBuff ,(off_t) 0, SEEK_END) | Syserror:", cProgname);
      }
      else
        FileInfo[iFdIdx].iCharDevice = TRUE;
    }
  }
  iFdIdx--;

  DBG(1, "File list complete!");


  if( (iDelayOrig = (int) CfgSleepInv[iSectMisc]) <= 0)
  {
    log_mesg(WARN, "%s: Error SLEEPINV invalid. Using default Value of 5 s", cProgname);
    iDelayOrig = 5;
  }
  iDelay = iDelayOrig;

  DBG(1, "Debug: Start monitoring Log Files");


  while(TRUE)
  {
NEXT_SLEEP:
    if( (iDelayLeft = sleep(iDelay)) != 0)
    {
      iDelay = iDelayLeft;
      continue;
    }
    else
      iDelay = iDelayOrig;
    

    //sigprotection(SP_ON, &SigSet);
NEXT:
    for(iCnt = 0; iCnt <= iFdIdx; iCnt++)
    {
      /*
      ** Stat the File (-name) to get the Information we need
      ** to make our Decissions
      */
      DBG(3, "Monitoring Log Files: stat(%s)", FileInfo[iCnt].cName);

      if(stat(FileInfo[iCnt].cName, &StatBuf) < 0)
      {
        /*
        ** File doesn't exist anymore.
        ** I will close the Fd and mark it with -1 but don't clean the Information about that
        ** File. If it's recreated, then I will open it again and update all Informations.
        */
        fclose(FileInfo[iCnt].FdBuff);
        FileInfo[iCnt].Fd = -1;

        DBG(2, "Error: File '%s' doesn't exist anymore. I'll ignore it and reopen it, if it was recreated!", FileInfo[iCnt].cName);
        continue;
      }

      /*
      ** Check if we can open the File now.
      */
      if(FileInfo[iCnt].Fd == -1)
      {
        DBG(2, "Monitoring Log Files: New File '%s'", FileInfo[iCnt].cName);

        /*
        ** Open File.
        */
        memset(&IOV, 0, sizeof(IOV));

        IOV[0].iov_base = cCmd;
        IOV[0].iov_len  = strlen(cCmd);
        IOV[1].iov_base = FileInfo[iCnt].cName;
        IOV[1].iov_len  = strlen(FileInfo[iCnt].cName);
        IOV[2].iov_base = cMode;
        IOV[2].iov_len  = strlen(cMode)+1;  /* +1, because of terminating \0 */

        if( writev(StreamPipe[0], IOV, 3) != (IOV[0].iov_len + IOV[1].iov_len + IOV[2].iov_len) )
          log_mesg(WARN_SYS, "%s: Error while sending Request '%s%s%s' via to FdescServer | Syserror", cProgname, cCmd, FileInfo[iCnt].cName, cMode);

        FileInfo[iCnt].Fd = intRecvFd(StreamPipe[0]);
        switch(FileInfo[iCnt].Fd)
        {
          case XFD_ERR_OPEN:
            log_mesg(WARN_SYS, "%s: Error: XFD_ERR_OPEN | Syserror", cProgname);
            goto NEXT; //continue;
          case XFD_ERR_MISSINGNULL:
            log_mesg(FATAL, "%s: Error: XFD_ERR_MISSINGNULL", cProgname);
            break;
          case XFD_ERR_PARSE:
            log_mesg(FATAL, "%s: Error: XFD_ERR_PARSE", cProgname);
            break;
          case XFD_ERR_TERM:
            log_mesg(FATAL, "%s: Error: XFD_ERR_TERM", cProgname);
            break;
          case XFD_ERR_STAT:
            log_mesg(WARN, "%s: Error: XFD_ERR_STAT", cProgname);
            FileInfo[iFdIdx].Fd = -1;
            goto NEXT; //continue;
          case XFD_ERR_FILETYPE:
            log_mesg(FATAL, "%s: Error: XFD_ERR_FILETYPE", cProgname);
            break;
          default:
            log_mesg(WARN, "%s: Error: XFD_ERR_UNKNOWN", cProgname);
            FileInfo[iFdIdx].Fd = -1;
            goto NEXT; //continue;
        }

        if(fstat(FileInfo[iCnt].Fd, &StatBuf) < 0)
          log_mesg(FATAL_SYS, "%s: Error while trying fstat(%s) | Syserror", cProgname, FileInfo[iCnt].cName);

        FileInfo[iCnt].FdBuff   = fdopen(FileInfo[iCnt].Fd, "r");
        FileInfo[iCnt].Device   = StatBuf.st_dev;
        FileInfo[iCnt].Inode    = StatBuf.st_ino;
        FileInfo[iCnt].Size     = (off_t) 0;      /* set Size to 0 to read all the data the next time! XXX should we read it now? */
        FileInfo[iCnt].Atime    = StatBuf.st_atime;
        FileInfo[iCnt].Mtime    = StatBuf.st_mtime;
        FileInfo[iCnt].Ctime    = StatBuf.st_ctime;
        FileInfo[iCnt].iErrors  = 0;

        if(S_ISREG(StatBuf.st_mode))
        {
          FileInfo[iFdIdx].iCharDevice = FALSE;
          DBG(2, "lseek(%s ,(off_t) 0, SEEK_END)", FileInfo[iFdIdx].cName);
          if(lseek(FileInfo[iFdIdx].Fd, (off_t) 0, SEEK_END) == (off_t) -1)
            log_mesg(FATAL_SYS, "%s: Error: lseek(FileInfo[iFdIdx].Fd ,(off_t) 0, SEEK_END) | Syserror:", cProgname);
          if(fseek(FileInfo[iFdIdx].FdBuff, (off_t) 0, SEEK_END) == -1)
            log_mesg(FATAL_SYS, "%s: Error: fseek(FileInfo[iFdIdx].FdBuff ,(off_t) 0, SEEK_END) | Syserror:", cProgname);
        }
        else
          FileInfo[iFdIdx].iCharDevice = TRUE;
      }
      /*
      ** Check if the File was re-created.
      */
      else if(FileInfo[iCnt].Device != StatBuf.st_dev || FileInfo[iCnt].Inode != StatBuf.st_ino)
      {
        fclose(FileInfo[iCnt].FdBuff);

        DBG(1, "Monitoring Log Files: Inode Changed, Reopen File '%s'", FileInfo[iCnt].cName);

        /*
        ** Reopen File.
        */
        memset(&IOV, 0, sizeof(IOV));

        IOV[0].iov_base = cCmd;
        IOV[0].iov_len  = strlen(cCmd);
        IOV[1].iov_base = FileInfo[iCnt].cName;
        IOV[1].iov_len  = strlen(FileInfo[iCnt].cName);
        IOV[2].iov_base = cMode;
        IOV[2].iov_len  = strlen(cMode)+1;  /* +1, because of terminating \0 */

        if( writev(StreamPipe[0], IOV, 3) != (IOV[0].iov_len + IOV[1].iov_len + IOV[2].iov_len) )
          log_mesg(WARN_SYS, "%s: Error while sending Request '%s%s%s' via to FdescServer | Syserror", cProgname, cCmd, FileInfo[iCnt].cName, cMode);

        FileInfo[iCnt].Fd = intRecvFd(StreamPipe[0]);
        switch(FileInfo[iCnt].Fd)
        {
          case XFD_ERR_OPEN:
            log_mesg(WARN_SYS, "%s: Error: XFD_ERR_OPEN | Syserror", cProgname);
            goto NEXT_SLEEP; //continue;
          case XFD_ERR_MISSINGNULL:
            log_mesg(FATAL, "%s: Error: XFD_ERR_MISSINGNULL", cProgname);
            break;
          case XFD_ERR_PARSE:
            log_mesg(FATAL, "%s: Error: XFD_ERR_PARSE", cProgname);
            break;
          case XFD_ERR_TERM:
            log_mesg(FATAL, "%s: Error: XFD_ERR_TERM", cProgname);
            break;
          case XFD_ERR_STAT:
            log_mesg(WARN, "%s: Error: XFD_ERR_STAT", cProgname);
            FileInfo[iFdIdx].Fd = -1;
            goto NEXT_SLEEP; //continue;
          case XFD_ERR_FILETYPE:
            log_mesg(FATAL, "%s: Error: XFD_ERR_FILETYPE", cProgname);
            break;
          default:
            log_mesg(WARN, "%s: Error: XFD_ERR_UNKNOWN", cProgname);
            FileInfo[iFdIdx].Fd = -1;
            goto NEXT_SLEEP; //continue;
        }

        if(FileInfo[iCnt].Fd == XFD_ERR_OPEN)
          continue;

        if(fstat(FileInfo[iCnt].Fd, &StatBuf) < 0)
          log_mesg(FATAL_SYS, "%s: Error while trying fstat(%s) | Syserror", cProgname, FileInfo[iCnt].cName);


        FileInfo[iCnt].FdBuff   = fdopen(FileInfo[iCnt].Fd, "r");
        FileInfo[iCnt].Device   = StatBuf.st_dev;
        FileInfo[iCnt].Inode    = StatBuf.st_ino;
        FileInfo[iCnt].Size     = (off_t) 0;      /* set Size to 0 to read all the data the next time! XXX should we read it now? */
        FileInfo[iCnt].Atime    = StatBuf.st_atime;
        FileInfo[iCnt].Mtime    = StatBuf.st_mtime;
        FileInfo[iCnt].Ctime    = StatBuf.st_ctime;
        FileInfo[iCnt].iErrors  = 0;

        if(S_ISREG(StatBuf.st_mode))
        {
          FileInfo[iFdIdx].iCharDevice = FALSE;
          DBG(2, "lseek(%s ,(off_t) 0, SEEK_END)", FileInfo[iFdIdx].cName);
          if(lseek(FileInfo[iFdIdx].Fd, (off_t) 0, SEEK_END) == (off_t) -1)
            log_mesg(FATAL_SYS, "%s: Error: lseek(FileInfo[iFdIdx].Fd ,(off_t) 0, SEEK_END) | Syserror:", cProgname);
          if(fseek(FileInfo[iFdIdx].FdBuff, (off_t) 0, SEEK_END) == -1)
            log_mesg(FATAL_SYS, "%s: Error: fseek(FileInfo[iFdIdx].FdBuff ,(off_t) 0, SEEK_END) | Syserror:", cProgname);
        }
        else
          FileInfo[iFdIdx].iCharDevice = TRUE;
      }
      /*
      ** Process non-reg. File
      */
      else if(FileInfo[iCnt].iCharDevice == TRUE)
      {
        DBG(1, "Monitoring Log Files: Process non-reg. File '%s'", FileInfo[iCnt].cName);

        /*
        ** Should I Use Threads (Detached)?
        ** pro: we don't block other files
        ** con: the same data may be read and logged twice or more times XXX
        */
        //while( (iBytesRead = readn(FileInfo[iCnt].Fd, ShmData.cData, sizeof(ShmData.cData)-1)) > 0)
        while( (iBytesRead = intReadFile(ShmData.cData, sizeof(ShmData.cData), FileInfo[iCnt].FdBuff, FileInfo[iCnt].uiType)) > 0)
        {
          //ShmData.cData[iBytesRead-1] = '\0'; // remove \n
          ShmData.DataLen = iBytesRead;
          ShmData.uiFileType = FileInfo[iCnt].uiType;
          // not neccessary for fgets(): ShmData.cData[iBytesRead-1] = 0;

          DBG(3, "Semaphore: P()\n");

          P(SemID);

          //log_mesg(WARN, "SHM: nonreg: write [%s]", ShmData.cData);

          memcpy(ShmAddr, &ShmData, sizeof(ShmEntry));

          V(SemID);

          if(kill(ParentPID, SIGUNUSED) < 0)
            log_mesg(FATAL_SYS, "%s: Error: kill(%d, SIGUNUSED) | Syserror", cProgname, ParentPID);

          DBG(3, "Semaphore: V()");

          memset(&ShmData, 0, sizeof(ShmData));
        }
      }
      /*
      ** Check if the File was the same as before but has been truncated.
      */
      else if(FileInfo[iCnt].iCharDevice != TRUE && FileInfo[iCnt].Size > StatBuf.st_size)
      {
        DBG(1, "Monitoring Log Files: File '%s' had been truncated", FileInfo[iCnt].cName);

        if(lseek(FileInfo[iCnt].Fd, 0, SEEK_SET) == (off_t) -1)
          log_mesg(FATAL_SYS, "%s: Error while rewinding File Descriptor for '%s' | Syserror", cProgname, FileInfo[iCnt].cName);
        if(fseek(FileInfo[iCnt].FdBuff, 0, SEEK_SET) == (off_t) -1)
          log_mesg(FATAL_SYS, "%s: Error while rewinding File Stream for '%s' | Syserror", cProgname, FileInfo[iCnt].cName);

        FileInfo[iCnt].Device   = StatBuf.st_dev;
        FileInfo[iCnt].Inode    = StatBuf.st_ino;
        FileInfo[iCnt].Size     = (off_t) 0;
        FileInfo[iCnt].Atime    = StatBuf.st_atime;
        FileInfo[iCnt].Mtime    = StatBuf.st_mtime;
        FileInfo[iCnt].Ctime    = StatBuf.st_ctime;
        FileInfo[iCnt].iErrors  = 0;
      }
      /*
      ** Check m- and atime and read Data.
      */
      else if(FileInfo[iCnt].Mtime != StatBuf.st_mtime) // || FileInfo[iCnt].Atime != StatBuf.st_atime)
      {
        DBG(1, "Monitoring Log Files: A- or Mtime of File '%s' changed", FileInfo[iCnt].cName);

        memset(ShmData.cData, 0, sizeof(ShmData.cData));


        /*
        ** We handle reg. Files and Char Devices/FIFOs differently.
        ** We just read the size difference for reg. Files but
        ** read till EOF for Char Devices and FIFOs.
        */
        DiffSize = StatBuf.st_size - FileInfo[iCnt].Size;
        iTotalBytesRead = 0;
        DBG(2, "DiffSize (%d) = StatBuf.st_size (%d) - FileInfo[iCnt].Size (%d)\n", DiffSize, StatBuf.st_size, FileInfo[iCnt].Size);
        if( DiffSize >= sizeof(ShmData.cData) )
          AmountToRead = sizeof(ShmData.cData) - 1;
        else
          AmountToRead = DiffSize;

        if(AmountToRead <= 0)
        {
          DBG(2, "AmountToRead = %d ---> REDO\n", AmountToRead);
          goto NEXT_SLEEP;
        }

        do
        {
          memset(&ShmData, 0, sizeof(ShmEntry));

          errno = 0;
          if( (iBytesRead = intReadFile(ShmData.cData, AmountToRead, FileInfo[iCnt].FdBuff, FileInfo[iCnt].uiType)) < 0 )
          {
            if(++FileInfo[iCnt].iErrors > MAX_ERRORS)
            {
              log_mesg(WARN, "%s: Error (Nr. %d) while reading from File '%s'. Skipping to next File.", cProgname, FileInfo[iCnt].iErrors, FileInfo[iCnt].cName);
              FileInfo[iCnt].iErrors--; // give him a new chance next time
              break; // leave diffsize calculus
            }
            else
            {
              DBG(1, "%s: Error (Nr. %d) while reading from File '%s'. Retrying...", cProgname, FileInfo[iCnt].iErrors, FileInfo[iCnt].cName);
              continue;
            }
          }

          FileInfo[iCnt].iErrors = 0;

          if(iBytesRead < 1)
          {
            DBG(2, "iBytesRead < 1!!!");
            break; // leave diffsize calculus
          }

          DBG(2, "iBytesRead = %d, iTotalBytesRead = %d\n", iBytesRead, iTotalBytesRead);

          iTotalBytesRead += iBytesRead;
          
          ShmData.DataLen = iBytesRead;
          ShmData.uiFileType = FileInfo[iCnt].uiType;

          DBG(3, "Semaphore: P()\n");

          P(SemID);
          memcpy(ShmAddr, &ShmData, sizeof(ShmEntry));
          V(SemID);

          if(kill(ParentPID, SIGUNUSED) < 0)
            log_mesg(FATAL_SYS, "%s: Error: kill(%d, SIGUNUSED) | Syserror", cProgname, ParentPID);

          DBG(3, "Semaphore: V()");

          DiffSize -= iBytesRead;
          if(DiffSize <= 0)
            AmountToRead = 0;
          else
          {
            if( DiffSize >= sizeof(ShmData.cData) )
              AmountToRead = sizeof(ShmData.cData) - 1;
            else
              AmountToRead = DiffSize;
          }

        } while(DiffSize > 0);

        /* update file information structure */
        FileInfo[iCnt].Device   = StatBuf.st_dev;
        FileInfo[iCnt].Inode    = StatBuf.st_ino;
        FileInfo[iCnt].Atime    = StatBuf.st_atime;
        FileInfo[iCnt].Mtime    = StatBuf.st_mtime;
        FileInfo[iCnt].Ctime    = StatBuf.st_ctime;
        FileInfo[iCnt].iErrors  = 0;

        if(iBytesRead > 1 && DiffSize <= 0) /* we read everything */
        {
          FileInfo[iCnt].Size = StatBuf.st_size;
        }
        else /* last loop: we read nothing and get no error OR an error occured. */
        {
          if(iTotalBytesRead > 0)  /* ...but we already read someting. */
            FileInfo[iCnt].Size += iTotalBytesRead;
          /* ... we read nothing so keep size unchanged */
          
          if(iCnt < iFdIdx)
            goto NEXT; // check next file
          else
            goto NEXT_SLEEP; // we are the last one in the list, sleep again
        }
      }
    } /* for(...) */

    // XXX sigprotection(SP_OFF, &SigSet);
  } /* while(TRUE) */


  exit(0);
}

void debug_message(char *data, size_t size)
{
  int i;

  for(i = 0; i < size; i++)
    log_mesg(WARN, "DEBUG_MESSAGE: %d [%d | 0x%02x | %c]\n", i, data[i],
             data[i], isascii(data[i]) ? data[i] : '?');
}

#include "readfile.c"


/*
** voidFdescServer (FS) and Helper Functions
** The FS acts as a Open Server. It has the Capabilities to
** open a File and passes the File Descriptor to LogWatch.
** LogWatch and FdescServer communicate via a Unix Domain Socket
** (aka Stream Pipe)
*/
void voidFdescServer(void)  // own process
{
  int                 iByteCount;
  char                cBuf[MAX_DATA];
//  pid_t               MyPID = getpid();
//  cap_user_header_t   CapHdr;
//  cap_user_data_t     CapData;


  _err_pname = cProgname = "DataForwarder/FdescServer";


  /*
  ** Create PID File
  *
  DBG(2, "Create PID File");
  snprintf(cPathFdesc, sizeof(cPathFdesc), "%s/%s", CfgPidPath[iSectMisc], PIDFDSRV);
  if(make_pidfile(cPathFdesc, 0) < 0)
    log_mesg(FATAL, "%s: voidFdescServer(): Fatal: Error while creating pid file!\n", cProgname);
  */

  DBG(1, "Init. Capabilities");


  /*
  if((CapHdr = (cap_user_header_t) calloc(1, sizeof(cap_user_header_t))) == NULL)
    log_mesg(FATAL_SYS, "%s: Error: calloc(1, sizeof(cap_user_header_t)) | Syserror", cProgname);

  if((CapData = (cap_user_data_t) calloc(1, sizeof(cap_user_data_t))) == NULL)
    log_mesg(FATAL_SYS, "%s: Error: calloc(1, sizeof(cap_user_header_t)) | Syserror", cProgname);

  CapHdr->version = _LINUX_CAPABILITY_VERSION;

  if(capget(CapHdr, CapData) < 0)
    log_mesg(FATAL_SYS, "%s: Error: capget() | Syserror", cProgname);

  // is this correct? XXX

  CapData->effective   |=  (1<<((CAP_DAC_OVERRIDE)&31));
  CapData->permitted   |=  (1<<((CAP_DAC_OVERRIDE)&31));
  CapData->inheritable  =  0;

  if(capset(CapHdr, CapData) != 0)
    log_mesg(FATAL_SYS, "%s: capset() | Syserror", cProgname);

  free(CapHdr);
  free(CapData);
  */


  /*
  ** Set EUID to 0 to open files and to create PID file.
  ** setuid() for CAPS! XXX
  */
  DBG(2, "Restore Privileges");
  if(setreuid(PwdEnt->pw_uid, 0) < 0)
    log_mesg(FATAL_SYS, "%s: Can not set UID | Syserror", cProgname);
  if(setregid(GrpEnt->gr_gid, 0) < 0)
    log_mesg(FATAL_SYS, "%s: Can not set GID | Syserror", cProgname);
  




  /***************************************************************************************
  **
  **                          Start reading Client Requests
  **
  ***************************************************************************************/
  DBG(1, "Ready for reading Client Requests");

  while((iByteCount = read(StreamPipe[1], cBuf, sizeof(cBuf))) != 0)
  {
    if(iByteCount < 0)
    {
      log_mesg(WARN_SYS, "%s: Error while reading from Stream Pipe | Syserror", cProgname);
      errno = 0;
      continue;
    }

    DBG(1, "Request received");

    if(intHandleClientRequest(cBuf, iByteCount, StreamPipe[1]) == XFD_ERR_TERM)
    {
      DBG(1, "Term Command received");

      exit(0);    /* LogWatch terminates and tells us to do the same */
    }
  }

  exit(0);
}


int intHandleClientRequest(char *cRequest, int iByteCount, int Pipe)
{
  char          *Argv[MAX_ARGC];
  int           Argc, NewFd;
  int           iRetVal;
  struct stat   StatBuf;


  if(cRequest[iByteCount-1] != '\0')
  {
    DBG(1, "Error: XFD_ERR_MISSINGNULL");
    intSendFd(Pipe, XFD_ERR_MISSINGNULL);
    return(XFD_ERR_MISSINGNULL);
  }

  if((iRetVal = intParseClientRequest(cRequest, &Argc, Argv)) < 0)
  {
    DBG(1, "XFD_ERR_PARSE (%d)", iRetVal);
    intSendFd(Pipe, XFD_ERR_PARSE);
    return(XFD_ERR_PARSE);
  }

  if(!strcmp(Argv[0], FS_CMD_TERM))
  {
    DBG(1, "Error: XFD_ERR_TERM");
    return(XFD_ERR_TERM);
  }

  if(stat(Argv[1], &StatBuf) < 0)
  {
    DBG(1, "Error: XFD_ERR_STAT");
    intSendFd(Pipe, XFD_ERR_STAT);
    return(XFD_ERR_STAT);
  }

  if(!S_ISREG(StatBuf.st_mode) && !S_ISCHR(StatBuf.st_mode) && !S_ISFIFO(StatBuf.st_mode))
  {
    DBG(1, "Error: XFD_ERR_FILETYPE");
    intSendFd(Pipe, XFD_ERR_FILETYPE);
    return(XFD_ERR_FILETYPE);
  }

  if((NewFd = open(Argv[1], atoi(Argv[2]))) < 0)
  {
    DBG(1, "Error: open(%s, %o) | Syserror", Argv[1], atoi(Argv[2]));

    intSendFd(Pipe, XFD_ERR_OPEN);
    return(XFD_ERR_OPEN);
  }

  DBG(1, "Open File '%s' (%d)", Argv[1], NewFd);

  if(intSendFd(Pipe, NewFd) < 0)
    log_mesg(FATAL_SYS, "%s: Error while Sending  Filedescriptor for '%s' | Syserror", cProgname, Argv[1]);

  close(NewFd);

  return(0);
}

int intParseClientRequest(char *cRequest, int *Argc, char *Argv[])
{
  char  *cPtr;
  int   argc = *Argc;


  if(strtok(cRequest, " \t\n") == NULL)
    return(-1);

  Argv[argc = 0] = cRequest;
  while( (cPtr = strtok(NULL, " \t\n")) != NULL)
  {
    if(++argc >= MAX_ARGC-1)
      return(PCR_INVALIDARGC);

    Argv[argc] = cPtr;
  }

  Argv[++argc] = NULL;

  if(argc != 3)
    return(PCR_INVALIDARGC);
  if( strncmp(Argv[0], FS_CMD_OPEN, strlen(FS_CMD_OPEN)-1) &&
      strncmp(Argv[0], FS_CMD_TERM, strlen(FS_CMD_TERM)-1) &&
      strncmp(Argv[0], FS_CMD_PID , strlen(FS_CMD_PID )-1)    )
  {
    DBG(1, "Error: Invalid Command '%s'", Argv[0]);
    return(PCR_INVALIDCMD);
  }

  return(0);
}


/*
** Signal Handlers
*/
void voidSigUnused(int id)
{
  Sig_DataReady = TRUE;
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

void voidSigChild(int id)
{
  pid_t PID;
  int iStatus;

  PID = wait(&iStatus);

  // XXX die verschiedenen PIDs sind nur dem Parent und dem jeweiligen Child bekannt!!!

  if(PID == FdescServerPID)
    log_mesg(FATAL, "%s: FdescServer dies! (PID = %d)", cProgname, PID);
  else if(PID == LogWatchPID)
    log_mesg(FATAL, "%s: LogWatch dies! (PID = %d)", cProgname, PID);
  else
    log_mesg(WARN, "%s: Unknown Child dies! (PID = %d)", cProgname, PID);
}

void voidSigHup(int id)
{
  pid_t   MyPID = getpid();

  DBG(1, "SigHup() triggered re-reading '%s'", cConfFile);

  // XXX BAD THING!

  intHandleConfFile(TRUE);

  /*
  ** Also send SIGHUP to the LogWatch Process
  ** Every Process has it's own Memory Segment, so every Process
  ** has to re-read the Config File for setting up their global
  ** Variables. (FdescServer doesn't need to)
  */
  if(LogWatchPID != MyPID)
    kill(LogWatchPID, SIGHUP);
  if(LogWatchPID == MyPID)
    siglongjmp(ProcStat, TRUE); /* re-read file list */
}

void voidSigTermination(int id)
{

  DBG(1, "SigTermination() triggered...");

  exit(0);
}


/*
** Clean Up Routine
*/
void voidCleanUp(void)
{
  pid_t MyPID = getpid();


  /*
  ** Remove PID File
  */
  if(MyPID == ParentPID)
  {
    if(remove(cPathMain) < 0)
      log_mesg(WARN_SYS, "%s: CleanUp: Error: remove(%s) | Syserror", cProgname, cPathMain);
  }
  else if(MyPID == FdescServerPID)
  {
    if(remove(cPathFdesc) < 0)
      log_mesg(WARN_SYS, "%s: CleanUp: Error: remove(%s) | Syserror", cProgname, cPathFdesc);
  }
  else if(MyPID == LogWatchPID)
  {
    if(remove(cPathLog) < 0)
      log_mesg(WARN_SYS, "%s: CleanUp: Error: remove(%s) | Syserror", cProgname, cPathLog);
  }
  else
    log_mesg(WARN, "%s: CleanUp: Unknown PID %u at Clean Up", cProgname, MyPID);


  /*
  ** Send SIGTERM to the LogWatch or Parent Process
  ** All the Processes share the same Session ID, so it will work (at least on BSDish Systems)
  ** ... I hope. :-\
  ** APUE from W.R. Stevens says, that just SIGCONT could be send to Processes of the same Session ID
  ** Maybe we could solve all the Problems for Systems w/o Capabilities by just setting the eUID of
  ** the Fdesc Server Process to root and setting the rUID to the UID of the other Processes. On Linux
  ** even seteuid(2) would suffice!
  ** XXX
  */
  if(ParentPID == MyPID)
  {
    DBG(1, "CleanUp: Sending SIGTERM to LogWatch and FdescServer");

    if(kill(LogWatchPID, SIGTERM) < 0)
      log_mesg(WARN_SYS, "%s: CleanUp: kill(LogWatchPID, SIGTERM) | Syserror", cProgname);
    if(kill(FdescServerPID, SIGTERM) < 0)
      log_mesg(WARN_SYS, "%s: CleanUp: kill(FdescServerPID, SIGTERM) | Syserror", cProgname);
  }
  if(LogWatchPID == MyPID)
  {
    DBG(1, "CleanUp: Sending SIGTERM to Parent and FdescServer");

    if(kill(ParentPID, SIGTERM) < 0)
      log_mesg(WARN_SYS, "%s: CleanUp: kill(ParentPID, SIGTERM) | Syserror", cProgname);
    if(kill(FdescServerPID, SIGTERM) < 0)
      log_mesg(WARN_SYS, "%s: CleanUp: kill(FdescServerPID, SIGTERM) | Syserror", cProgname);

    close(StreamPipe[0]);
  }
  if(FdescServerPID == MyPID)
  {
    DBG(1, "CleanUp: Sending SIGTERM to Parent and LogWatch");

    if(kill(ParentPID, SIGTERM) < 0)
      log_mesg(WARN_SYS, "%s: CleanUp: kill(ParentPID, SIGTERM) | Syserror", cProgname);
    if(kill(LogWatchPID, SIGTERM) < 0)
      log_mesg(WARN_SYS, "%s: CleanUp: kill(LogWatchPID, SIGTERM) | Syserror", cProgname);

    close(StreamPipe[1]);
  }


  /*
  ** Remove Semapore and Shared Memory
  ** to aviod Resource Starvation
  ** How does the LogWatch Process knows about this? XXX Who cares if it's killed anyway. ;-)
  */
  if(MyPID == ParentPID || MyPID == LogWatchPID)
  {
    if((shmctl(ShmID, IPC_RMID, NULL)) < 0)
      log_mesg(WARN_SYS, "%s: CleanUp: Couldn't release Shared Memory | Syserror", cProgname);
    if((semctl(SemID, 0, IPC_RMID, (int) 0)) < 0)
      log_mesg(WARN_SYS, "%s: CleanUp: Couldn't release Semaphore | Syserror", cProgname);
  }

  // where to free the Fd array? XXX

  /*
  ** Close Crypto Module
  */
  mcrypt_generic_end(CryptModule);

  /*
  ** Close Sockets
  */
  close(SqlSock);
  close(AnaSock);


  /*
  ** Close Syslog Sesion
  */
  closelog();

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

  // child process

  // get a new session ID
  if(setsid() < 0)
    return(-1);

  chdir("/");     /* change working direc. */
  umask(0);       /* delete filecreatingmask */

  return(0);
}


/*
** log conf parse error
*/
void  voidCfgFatalFunc(cfgErrorCode ErrCode, const char *Str1 , int iDummy, const char *Str2)
{
  log_mesg(WARN, "%s: Error while Parsing Config File\n", cProgname);
}


/*
** Handle Config File
*/
int intHandleConfFile(int Syslog)
{
  int             iCfgCount;
  int             iCnt;
  struct stat     StatBuf;


  iSectSQL      = -1;
  iSectAna      = -1;
  iSectSec      = -1;
  iSectLog      = -1;
  iSectModPath  = -1;
  iSectModules  = -1;
  iSectModConf  = -1;
  iSectMisc     = -1;

  if(lstat(cConfFile, &StatBuf) < 0)
    LOG(Syslog, FATAL_SYS, "%s: Error while trying lstat(%s) | Syserror", cProgname, cConfFile);

/* XXX
  if( !S_ISREG(StatBuf.st_mode) || StatBuf.st_uid != getuid() || StatBuf.st_gid != getgid() || !(StatBuf.st_mode & (S_IWUSR | S_IRUSR)) )
    LOG(Syslog, FATAL_SYS, "%s: Security Warning: %s must be a regular File and owned by User %d and Group %d\n"
                           "and just read-/write-able by the User and noone else. Exit.\n", cProgname, cConfFile, rUID, rGID);
*/

  if((iCfgCount = cfgParse(cConfFile, CfgIni, CFG_INI)) < 0)
    LOG(Syslog, FATAL, "%s: Error while parsing Config File %s\n", cProgname, cConfFile);

  if(iCfgCount != SECT_MAXSECT)
    LOG(Syslog, FATAL, "%s: Error while parsing Config File %s | Sections Read: %d | Sections Expect: %d", cProgname, cConfFile, iCfgCount, SECT_MAXSECT);

  //if(iDebug)
    //LOG(Syslog, WARN, "%s: Debug: iCfgCount = %d\n", cProgname, iCfgCount);

  for(iCnt = 0; iCnt < iCfgCount; iCnt++)
  {
    //if(iDebug)
      //LOG(Syslog, WARN, "%s: Debug: [%s]", cProgname, cfgSectionNumberToName(iCnt), NULL, NULL);

    if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_SQLSRV))
      iSectSQL = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_ANASRV))
      iSectAna = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_SECNPRV))
      iSectSec = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_LOGFLST))
      iSectLog = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_MODPATH))
      iSectModPath = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_MODULES))
      iSectModules = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_MODCONF))
      iSectModConf = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_MISC))
      iSectMisc = iCnt;
    else
      LOG(Syslog, FATAL, "%s: Error in Config File %s | Unknown Section: %s", cProgname, cConfFile, cfgSectionNumberToName(iCnt));
  }

  // needed? XXX
  if(iSectSQL == -1 || iSectAna == -1 || iSectSec == -1 || iSectLog == -1 || iSectModPath == -1 || iSectModules == -1 || iSectModConf == -1 || iSectMisc == -1)
    LOG(Syslog, FATAL, "%s: Error in Config File %s | A Section is missing!\n", cProgname, cConfFile);

  if(CfgEncrypt[iSectSec] && CfgEncKey[iSectSec] == NULL)
  {
    LOG(Syslog, WARN, "%s: ENCRYPT is set but there is no Key specified. ENCRYPTION DISABLED!!!\n", cProgname);
    CfgEncrypt[iSectSec] = 0;
  }

  if(CfgReconnect[iSectMisc] < 0)
  {
    LOG(Syslog, WARN, "%s: RECONNECT is negativ. We will make it positiv!!!\n", cProgname);
    CfgReconnect[iSectMisc] = -1 * CfgReconnect[iSectMisc];
  }


  return(0);
}

void DBG(int threshold, const char *str, ...)
{
  char maxstr[4*1024];
  va_list az;

  va_start(az, str);
  vsnprintf(maxstr, sizeof(maxstr), str, az);

  debug(TRUE, iDebug, threshold, "%s: Debug(%d): %s", _err_pname, threshold, maxstr);

  va_end(az);
}
