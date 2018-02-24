#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <mcrypt.h>

#include <libidmef/idmefxml.h>
#include <libidmef/idmefxml_parse.h>

#include <libxml/xmlversion.h>

#include <mice.h>
#include "reaction-mesg-format.h"
#include "checksum.h"
#include "parsecfg.h"


#define TRUE              1
#define FALSE             0

#define CONFFILE          "/etc/M-ICE/rid_4_countermeasure.conf"
#define SAVEFILE          "/var/log/M-ICE/rid_4_countermeasure.log"

// Config Stuff
#define SECT_PIPE         "PIPE_NAME"
#define SECT_SEC          "SECURITY"
#define SECT_NET          "NETWORK"
#define SECT_MAXSECT      3

#define FID_SHELL         0x000001



int iDebug = 0;

struct
{
  int     iSectionNr;
  char    **cPipe;
} CfgPipe;

struct
{
  int     iSectionNr;
  char    **cPwd;
} CfgSec;

struct
{
  int     iSectionNr;
  char    **cPort;
} CfgNet;


cfgStruct CfgIni[] =
{
  // Pipe Name
  {"PIPE"         ,CFG_STRING       ,&CfgPipe.cPipe },

  // Security
  {"PASSWORD"     ,CFG_STRING       ,&CfgSec.cPwd   },

  // Network Section
  {"PORT"         ,CFG_STRING       ,&CfgNet.cPort  },


  // The End
  {NULL           ,CFG_END          ,NULL           }
};



void  voidSendReactionMsg(RIDMsgFormat RIDmsg);
char  *charGetAddress(RIDMsgFormat RIDmsg);
int   intHandleConfFile(char *cConfFile);




/*************************************************************************
*
*         M A I N
*
*************************************************************************/

int main(void)
{
  FILE          *streamFifo;
  RIDMsgFormat  RIDmsg;



  if(intHandleConfFile(CONFFILE) < 0)
    log_mesg(FATAL, "M-ICE Countermeasure: Error while parsing Config File");

  if( (streamFifo = fopen(CfgPipe.cPipe[CfgPipe.iSectionNr], "r")) == NULL)
    log_mesg(FATAL, "M-ICE Countermeasure: Error while opening FIFO '%s'", CfgPipe.cPipe[CfgPipe.iSectionNr]);

  while(TRUE)
  {
    clearerr(streamFifo);
    if(fread((char *) &RIDmsg, sizeof(RIDMsgFormat), 1, streamFifo) != 1)
    {
      if(ferror(streamFifo))
      {
        log_mesg(WARN_SYS, "M-ICE Countermeasure: Error while reading from FIFO | Syserror");
        continue;
      }

      sleep(2);
      continue;
    }

    voidSendReactionMsg(RIDmsg);
  }

  exit(0);
}


/************************************************************************
*
* SUBROUTINES
*
************************************************************************/

/*
** Look up Source Address in IDMEF Message
*/
char *charGetAddress(RIDMsgFormat RIDmsg)
{
  char          *cAddress;
  IDMEFmessage  *IDMEFmsg;


  // Parse IDMEF Message
  IDMEFmsg = 0;
  if( (IDMEFmsg = get_idmef_message(RIDmsg.cIdmefMsg, strlen(RIDmsg.cIdmefMsg))) == 0)
  {
    log_mesg(WARN, "M-ICE Countermeasure Error while parsing IDMEF Message! Skipping Reaction Message!!!\n");
    return(NULL);
  }

  cAddress = strdup(IDMEFmsg->alerts[0]->sources[0]->node->addresses[0]->address);

  free_message(IDMEFmsg);

  return(cAddress);
}



/*
** Send encrypted Reaction Message
*/
void voidSendReactionMsg(RIDMsgFormat RIDmsg)
{
  char            CliMsg[sizeof(stCipherRctMsg)],
                  SrvMsg[sizeof(stCipherRctMsg)],
                  *cRawKey = CfgSec.cPwd[CfgSec.iSectionNr],
                  *cKey,
                  *cAddress,
                  *cPort;

  short           sChkSum_New,
                  sChkSum_Orig;

  int             iSock,
                  iCnt;

  const int       iKeySize = 16;

  MCRYPT          CryptoModule;

  stCipherRctMsg  *CipMsgPtr;
  stReactionMsg   *RctMsgPtr;
  // Client Messages
  stExecMsg       *ExcMsgPtr;
  // Server Messages
  stRetvalMsg     *RetMsgPtr;




  // Setup Message for Server
  memset(CliMsg, 0, sizeof(CliMsg));

  CipMsgPtr = (stCipherRctMsg *)  CliMsg;
  RctMsgPtr = (stReactionMsg *)   CipMsgPtr->cCipherText;
  ExcMsgPtr = (stExecMsg *)       &RctMsgPtr->ModeData.Exec;

  RctMsgPtr->Timestamp      = (time_t) htonl(time(NULL));
  RctMsgPtr->Mode           = (u_int)  htonl(MID_EXEC);


  memcpy(ExcMsgPtr->alert_id, RIDmsg.cAlertID, sizeof(ExcMsgPtr->alert_id)-1);
  ExcMsgPtr->reaction_id    = (int) htonl(RIDmsg.iRID);
  ExcMsgPtr->uid_for_exec   = 0;
  ExcMsgPtr->gid_for_exec   = 0;
  ExcMsgPtr->function_id    = (int) htonl(FID_SHELL);
  ExcMsgPtr->num_of_args    = (int) htonl(1);
  memcpy(ExcMsgPtr->arg_fmt_string, "echo TEST > /tmp/rd.txt", sizeof(ExcMsgPtr->arg_fmt_string)-1);


  // Checksum
  CipMsgPtr->CipherTextLen = sizeof(stReactionMsg);
  RctMsgPtr->sChkSum = in_chksum((u_short *) CipMsgPtr->cCipherText, CipMsgPtr->CipherTextLen);

  if(iDebug)
    log_mesg(WARN, "M-ICE Countermeasure Checksum of Plaintext (%u) = %hu", CipMsgPtr->CipherTextLen, RctMsgPtr->sChkSum);


  // Start encrypting the Message
  if(cRawKey != NULL && cRawKey[0] != '\0')
  {
    if(iDebug)
      log_mesg(WARN, "M-ICE Countermeasure start encrypting our message");

    if(iDebug > 1)
      log_mesg(WARN, "M-ICE Countermeasure alloc memory for key");

    if((cKey = calloc(1, iKeySize)) == NULL)
    {
      log_mesg(WARN, "M-ICE Countermeasure Error while allocating Memory for Twofish Key\n");
      return;
    }

    memmove(cKey, cRawKey, iKeySize);

    if(iDebug)
      log_mesg(WARN, "M-ICE Countermeasure Using Key: '%s'", cKey);

    if(iDebug > 1)
      log_mesg(WARN, "M-ICE Countermeasure open crypt module");

    if((CryptoModule = mcrypt_module_open("twofish", NULL, "cfb", NULL)) == MCRYPT_FAILED)
    {
      log_mesg(WARN, "M-ICE Countermeasure Error while trying to load Crypto Module '%s'\n", "twofish");
      return;
    }

    if(iDebug > 1)
      log_mesg(WARN, "M-ICE Countermeasure alloc memory for IV");

    CipMsgPtr->IVLen = mcrypt_enc_get_iv_size(CryptoModule);

    if(CipMsgPtr->IVLen != sizeof(CipMsgPtr->IV))
    {
      log_mesg(FATAL, "M-ICE Countermeasure IV Length is not equal to 16! Please check if 'Twofish' Crypto Algo. is enabled.");
      return;
    }

    if(iDebug > 1)
      log_mesg(WARN, "M-ICE Countermeasure fill IV with random data");

    srand(time(0));
    for(iCnt = 0; iCnt < CipMsgPtr->IVLen; iCnt++)
    {
      if(iDebug > 1)
        log_mesg(WARN, "M-ICE Countermeasure rand...");

      CipMsgPtr->IV[iCnt] = rand();
    }


    if(iDebug)
      log_mesg(WARN, "M-ICE Countermeasure init crypt module");

    if(mcrypt_generic_init(CryptoModule, cKey, iKeySize, CipMsgPtr->IV) < 0)
    {
      log_mesg(FATAL, "M-ICE Countermeasure Error while initializing Crypto Module\n");
      return;
    }


    /*
    ** Encrypt Data
    */
    for(iCnt = 0; iCnt < CipMsgPtr->CipherTextLen; iCnt++)
      mcrypt_generic(CryptoModule, &CipMsgPtr->cCipherText[iCnt], 1);

    if(iDebug)
      log_mesg(WARN, "M-ICE Countermeasure Checksum of Ciphertext = %hu", in_chksum((u_short *) CipMsgPtr->cCipherText, CipMsgPtr->CipherTextLen));

  }
  else  // NO encryption
  {
    if(iDebug)
      log_mesg(WARN, "M-ICE Countermeasure DONT encrypt our message");

    CipMsgPtr->IVLen = 0;
  }



  // Send away
  if( (cAddress = charGetAddress(RIDmsg)) == NULL)
  {
    log_mesg(WARN, "M-ICE Countermeasure Error while looking up IP Address");
    return;
  }
  if((cPort = CfgNet.cPort[CfgNet.iSectionNr]) == NULL)
  {
    log_mesg(WARN, "M-ICE Countermeasure Error while looking up TCP Port");
    return;
  }

  if(iDebug)
    log_mesg(WARN, "M-ICE Countermeasure open TCP connection to %s:%s", cAddress, cPort);

  if( (iSock = tcp_open(cAddress, NULL, atoi(cPort))) < 0 )
  {
    log_mesg(WARN, "M-ICE Countermeasure Error while opening Socket to Remote Host.\n");
    return;
  }


  if(iDebug)
    log_mesg(WARN, "M-ICE Countermeasure send data over TCP connection");

  if(writen(iSock, (char *) &CliMsg, sizeof(CliMsg)) < 0)
  {
    log_mesg(WARN, "M-ICE Countermeasure Error while sending Data to Remote Host. Try to reopen Connection...\n");
    close(iSock);
    if((iSock = tcp_open(cAddress, NULL, atoi(cPort))) < 0)
    {
      log_mesg(WARN, "M-ICE Countermeasure Error while opening Socket to Remote Host.\n");
      return;
    }
    if(writen(iSock, (char *) &CliMsg, sizeof(CliMsg)) < 0)
    {
      log_mesg(WARN, "M-ICE Countermeasure Error while sending Reaction Message to Remote Host. Abort!\n");
      close(iSock);
      return;
    }
  }


  /*
  ** Wait for Answer
  */
  memset(SrvMsg, 0, sizeof(SrvMsg));
  if(readn(iSock, SrvMsg, sizeof(SrvMsg)) != sizeof(SrvMsg))
  {
    log_mesg(WARN, "M-ICE Countermeasure Error while receiving Answer from Remote Host. Abort!\n");
    close(iSock);
    return;
  }


  // Setup Pointers
  CipMsgPtr = (stCipherRctMsg *)  SrvMsg;
  RctMsgPtr = (stReactionMsg *)   CipMsgPtr->cCipherText;
  RetMsgPtr = (stRetvalMsg *)     &RctMsgPtr->ModeData.Retval;


  // Verify Checksum (CRC)
  if(iDebug)
    log_mesg(WARN, "M-ICE Countermeasure Debug: Verify Checksum\n");

  sChkSum_Orig        = RctMsgPtr->sChkSum;
  RctMsgPtr->sChkSum  = 0;
  sChkSum_New         = in_chksum((u_short *) CipMsgPtr->cCipherText, CipMsgPtr->CipherTextLen);

  if(iDebug)
    log_mesg(WARN, "M-ICE Countermeasure Debug: Checksum (Orig [%hu], New [%hu])\n", sChkSum_Orig, sChkSum_New);

  if(sChkSum_Orig != sChkSum_New)
  {
    log_mesg(WARN, "M-ICE Countermeasure Checksum does not match. Close Connection to Client!\n");
    return;
  }

  RctMsgPtr->sChkSum = sChkSum_Orig;

  switch((int) ntohl(RetMsgPtr->ret_val))
  {
    case RID_SUCCESS:
      log_mesg(WARN, "M-ICE Countermeasure Return Code: RID_SUCCESS");
    break;

    case RID_UNKNOWNMODE:
      log_mesg(WARN, "M-ICE Countermeasure Return Code: RID_UNKNOWNMODE");
    break;

    case RID_NARGS:
      log_mesg(WARN, "M-ICE Countermeasure Return Code: RID_NARGS");
    break;

    case RID_UNKNOWNFUNC:
      log_mesg(WARN, "M-ICE Countermeasure Return Code: RID_UNKNOWNFUNC");
    break;

    case RID_ERROR:
      log_mesg(WARN, "M-ICE Countermeasure Return Code: RID_ERROR");
    break;

    default:
      log_mesg(WARN, "M-ICE Countermeasure Return Code is unknown! Maybe Error while decoding Message!");
  }


  // The End...
  close(iSock);

  if(cRawKey != NULL && cRawKey[0] != '\0')
  {
    free(cKey);
    mcrypt_module_close(CryptoModule);
  }

  free(cAddress);

  return;
}



/*
** Read Config File and set global Var.s
*/
int intHandleConfFile(char *cConfFile)
{
  int               iCfgCount;
  int               iCnt;
  struct stat       StatBuf;


  CfgPipe.iSectionNr  = -1;
  CfgSec.iSectionNr   = -1;
  CfgNet.iSectionNr   = -1;


  if(lstat(cConfFile, &StatBuf) < 0)
  {
    log_mesg(WARN_SYS, "M-ICE Countermeasure: Error while trying lstat(%s) | Syserror", cConfFile);
    return(-1);
  }

  if((iCfgCount = cfgParse(cConfFile, CfgIni, CFG_INI)) < 0)
  {
    log_mesg(WARN, "M-ICE Countermeasure: Error while parsing Config File %s\n", cConfFile);
    return(-2);
  }

  if(iCfgCount != SECT_MAXSECT)
  {
    log_mesg(WARN, "M-ICE Countermeasure: Error while parsing Config File %s | Sections Read: %d | Sections Expect: %d", cConfFile, iCfgCount, SECT_MAXSECT);
    return(-3);
  }

  for(iCnt = 0; iCnt < iCfgCount; iCnt++)
  {
    if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_PIPE))
      CfgPipe.iSectionNr = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_SEC))
      CfgSec.iSectionNr = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_NET))
      CfgNet.iSectionNr = iCnt;
    else
    {
      log_mesg(WARN, "M-ICE Countermeasure: Error in Config File %s | Unknown Section: %s", cConfFile, cfgSectionNumberToName(iCnt));
      return(-4);
    }
  }

  if(CfgPipe.iSectionNr == -1 || CfgSec.iSectionNr == -1 || CfgNet.iSectionNr == -1)
  {
    log_mesg(WARN, "M-ICE Countermeasure: Error in Config File %s, Section is missing!\n", cConfFile);
    return(-5);
  }

  return(0);
}
