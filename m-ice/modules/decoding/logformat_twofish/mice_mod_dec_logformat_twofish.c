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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <mcrypt.h>

#include <mice.h>
#include "mice_mod_dec_logformat_twofish.h"
#include "logformat.h"
#include "checksum.h"
#include "parsecfg.h"


#define TRUE              1
#define FALSE             0



int   _mice_mod_dec_logformat_twofish_iDebug = FALSE;

char  *_mice_mod_dec_logformat_twofish_cProgname;


/*
** Crypto
*/
struct
{
  MCRYPT    CryptModule;
  char      *cCryptModName;
  char      *cKey;
  size_t    KeySize;  /* 128 Bit Key */
  char      *cRawKey;
  char      *cPassword;
  char      *cDevRand;
} _mice_mod_dec_logformat_twofish_CryptoInfo;


/*
** Configure Stuff
*/
int _mice_mod_dec_logformat_twofish_CfgDone = FALSE;

struct
{
  int     iSectionNr;
  char    **cCfgKey;  // XXX: what's about protected pages for our Keys so they can not be swapped? ppl who can read the swap can also read the conf file ;)
  char    **cCfgCryptoMod;
  char    **cCfgDevRand;
} _mice_mod_dec_logformat_twofish_CfgCryptoInfo;



cfgStruct    _mice_mod_dec_logformat_twofish_CfgIni[] =
{
  // Crypto Info
  {"ENCKEY"     ,CFG_STRING       ,&_mice_mod_dec_logformat_twofish_CfgCryptoInfo.cCfgKey       },
  {"CRYPTMOD"   ,CFG_STRING       ,&_mice_mod_dec_logformat_twofish_CfgCryptoInfo.cCfgCryptoMod },
  {"DEVRANDOM"  ,CFG_STRING       ,&_mice_mod_dec_logformat_twofish_CfgCryptoInfo.cCfgDevRand   },

  // The End
  {NULL         ,CFG_END          ,NULL                                                         }
};



/*
** Function Declaration
*/
int _mice_mod_dec_logformat_twofish_HandleConfFile(char *cConfFile);



/***************************************************************************************
**
** p u b l i c   M o d u l e   F u n c t i o n s
**
***************************************************************************************/


/*
** Init
*/
size_t mice_mod_dec_logformat_twofish_LTX_init(char *ConfFile)
{

  _mice_mod_dec_logformat_twofish_cProgname = "BufferDaemon/mice_mod_dec_logformat_towfish";

  if(_mice_mod_dec_logformat_twofish_CfgDone != FALSE)
  {
    log_mesg(WARN, "mice_mod_dec_logformat_twofish: Do NOT call init function twice, call close function inbetween");
    return(-1);
  }

  if(_mice_mod_dec_logformat_twofish_HandleConfFile(ConfFile) < 0)
    return(-1);


  _mice_mod_dec_logformat_twofish_CryptoInfo.cRawKey        = _mice_mod_dec_logformat_twofish_CfgCryptoInfo.cCfgKey[_mice_mod_dec_logformat_twofish_CfgCryptoInfo.iSectionNr];
  _mice_mod_dec_logformat_twofish_CryptoInfo.cCryptModName  = _mice_mod_dec_logformat_twofish_CfgCryptoInfo.cCfgCryptoMod[_mice_mod_dec_logformat_twofish_CfgCryptoInfo.iSectionNr];
  _mice_mod_dec_logformat_twofish_CryptoInfo.cDevRand       = _mice_mod_dec_logformat_twofish_CfgCryptoInfo.cCfgDevRand[_mice_mod_dec_logformat_twofish_CfgCryptoInfo.iSectionNr];
  _mice_mod_dec_logformat_twofish_CryptoInfo.KeySize        = 16;


  /*
  ** Init. Crypto Module
  */
  if(strlen(_mice_mod_dec_logformat_twofish_CryptoInfo.cRawKey) >= MIN_KEYLEN)
  {
    if(_mice_mod_dec_logformat_twofish_iDebug)
      log_mesg(WARN, "%s: Debug: Init. Crypto Module\n", _mice_mod_dec_logformat_twofish_cProgname);

    if((_mice_mod_dec_logformat_twofish_CryptoInfo.cKey = calloc(1, _mice_mod_dec_logformat_twofish_CryptoInfo.KeySize)) == NULL)
    {
      log_mesg(WARN_SYS, "%s: Error while allocating Memory for Twofish Key\n", _mice_mod_dec_logformat_twofish_cProgname);
      return(-2);
    }

    if((_mice_mod_dec_logformat_twofish_CryptoInfo.cPassword = calloc(1, strlen(_mice_mod_dec_logformat_twofish_CryptoInfo.cRawKey)+1)) == NULL)
    {
      log_mesg(WARN_SYS, "%s: Error while allocating Memory for decryption Key\n", _mice_mod_dec_logformat_twofish_cProgname);
      return(-3);
    }

    strcpy(_mice_mod_dec_logformat_twofish_CryptoInfo.cPassword, _mice_mod_dec_logformat_twofish_CryptoInfo.cRawKey);
    memmove(_mice_mod_dec_logformat_twofish_CryptoInfo.cKey, _mice_mod_dec_logformat_twofish_CryptoInfo.cPassword, _mice_mod_dec_logformat_twofish_CryptoInfo.KeySize);

    if(_mice_mod_dec_logformat_twofish_iDebug)
      log_mesg(WARN, "%s: Debug: init: mcrypt_open()\n", _mice_mod_dec_logformat_twofish_cProgname);

    if((_mice_mod_dec_logformat_twofish_CryptoInfo.CryptModule = mcrypt_module_open(_mice_mod_dec_logformat_twofish_CryptoInfo.cCryptModName, NULL, "cfb", NULL)) == MCRYPT_FAILED)
    {
      log_mesg(WARN, "%s: Error while trying to load Crypto Module '%s'\n", _mice_mod_dec_logformat_twofish_cProgname, _mice_mod_dec_logformat_twofish_CryptoInfo.cCryptModName);
      return(-4);
    }
  }
  else
  {
    log_mesg(WARN, "%s: Key is shorter then the minimum length of %d characters\n", _mice_mod_dec_logformat_twofish_cProgname, MIN_KEYLEN);
    return(-5);
  }

  _mice_mod_dec_logformat_twofish_CfgDone = TRUE;

  if(_mice_mod_dec_logformat_twofish_iDebug)
    log_mesg(WARN, "%s: Debug: init: return\n", _mice_mod_dec_logformat_twofish_cProgname);

  return(sizeof(CipherMsg)); // return the max. size of bytes the caller must accept for a message

  // XXX oder doch ne struct{ sizeof decoedmsg, sizeof decodedmsg }

}



/*
** Main Function
*/
char *mice_mod_dec_logformat_twofish_LTX_func(char *cData, size_t DataSize)
{
  static char   cDecodedMsg[sizeof(CipherMsg)]; // TAKE CARE: this gets overwritten at next call

  u_short       sChkSum_Orig;
  u_short       sChkSum_New;

  register int  iCnt;

  CipherMsg     *CMsg;
  LogFormat     *LFmt;


  if(_mice_mod_dec_logformat_twofish_CfgDone != TRUE)
  {
    log_mesg(WARN, "mice_mod_dec_logformat_twofish: Error! You have to call mice_mod_dec_logformat_twofish_LTX_init() first!\n");
    return(NULL);
  }

  if(DataSize < sizeof(LogFormat))
  {
    log_mesg(WARN, "mice_mod_dec_logformat_twofish: Data to process is too small (%d < %d)\n", DataSize, sizeof(LogFormat));
    return(NULL);
  }
  
  CMsg = (CipherMsg *) cData;

  if(_mice_mod_dec_logformat_twofish_iDebug)
    log_mesg(WARN, "%s: Debug: IVLen = %d, IV[0] = 0x%0.2x, CipherTextLen = %d, expected Length = %d\n", _mice_mod_dec_logformat_twofish_cProgname, CMsg->IVLen, CMsg->IV[0], CMsg->CipherTextLen, sizeof(LogFormat));

  if( CMsg->CipherTextLen != sizeof(LogFormat) )
  {
    log_mesg(WARN, "%s: Error: Length of received Messages does not match the expected Length!!!\n", _mice_mod_dec_logformat_twofish_cProgname);
    return(NULL);
  }


  /*
  ** Check Timestamp to avoid replay and cut-n-paste attacks
  ** XXX: Added later
  */


  /*
  ** Message is NOT decryted.
  */
  if(CMsg->IVLen == 0)
  {
    if(_mice_mod_dec_logformat_twofish_iDebug)
      log_mesg(WARN, "%s: Debug: Message is NOT decrypted!\n", _mice_mod_dec_logformat_twofish_cProgname);

    return( CMsg->cCipherText );
  }


  /*
  ** Message is decryted. Let's decrypt it!
  */
  if(_mice_mod_dec_logformat_twofish_iDebug)
    log_mesg(WARN, "%s: Debug: Decrypt Data", _mice_mod_dec_logformat_twofish_cProgname);

  if(mcrypt_generic_init(_mice_mod_dec_logformat_twofish_CryptoInfo.CryptModule, _mice_mod_dec_logformat_twofish_CryptoInfo.cKey, _mice_mod_dec_logformat_twofish_CryptoInfo.KeySize, CMsg->IV) < 0)
  {
    log_mesg(WARN, "%s: Error while initializing Crypto Module\n", _mice_mod_dec_logformat_twofish_cProgname);
    return(NULL);
  }

  memset(cDecodedMsg, 0, sizeof(cDecodedMsg));
  memcpy(cDecodedMsg, CMsg->cCipherText, CMsg->CipherTextLen);

  for(iCnt = 0; iCnt < CMsg->CipherTextLen; iCnt++)
    mdecrypt_generic(_mice_mod_dec_logformat_twofish_CryptoInfo.CryptModule, &cDecodedMsg[iCnt], 1);

  LFmt = (LogFormat *) cDecodedMsg;

  if(_mice_mod_dec_logformat_twofish_iDebug > 1)
    log_mesg(WARN,  "%s: Decrypt-Test: "
                    "LFmt->cHost = %s | "
                    "LFmt->cDomain = %s | "
                    "LFmt->cIP = %s | "
                    "LFmt->cOSystem = %s | "
                    "LFmt->cRelease = %s | "
                    "LFmt->cVersion = %s | "
                    "LFmt->cDate = %s | "
                    "LFmt->cTime = %s | "
                    "LFmt->cLogdata = %s | "
                    "LFmt->sChkSum = %hu", _mice_mod_dec_logformat_twofish_cProgname, LFmt->cHost, LFmt->cDomain, LFmt->cIP, LFmt->cOSystem, LFmt->cRelease, LFmt->cVersion, LFmt->cDate, LFmt->cTime, LFmt->cLogdata, LFmt->sChkSum);


  /*
  ** Verify Checksum (CRC)
  */
  if(_mice_mod_dec_logformat_twofish_iDebug)
    log_mesg(WARN, "%s: Debug: Verify Checksum\n", _mice_mod_dec_logformat_twofish_cProgname);

  sChkSum_Orig    = LFmt->sChkSum;
  LFmt->sChkSum   = 0;
  sChkSum_New     = in_chksum((u_short *) LFmt, sizeof(LogFormat));

  if(_mice_mod_dec_logformat_twofish_iDebug)
    log_mesg(WARN, "%s: Debug: Checksum (Orig [%hu], New [%hu])\n", _mice_mod_dec_logformat_twofish_cProgname, sChkSum_Orig, sChkSum_New);

  if(sChkSum_Orig != sChkSum_New)
  {
    log_mesg(WARN, "%s: Debug: Checksum does not match... skipping Message\n", _mice_mod_dec_logformat_twofish_cProgname);
    //free(cDecodedMsg);
    return(NULL);
  }

  LFmt->sChkSum = sChkSum_Orig;

  if(mcrypt_generic_deinit(_mice_mod_dec_logformat_twofish_CryptoInfo.CryptModule) < 0)
    log_mesg(WARN, "%s: Error while clearing Crypto Module!\n", _mice_mod_dec_logformat_twofish_cProgname);

  return(cDecodedMsg);
}



/*
** Close
*/
int mice_mod_dec_logformat_twofish_LTX_close(void)
{
  if(_mice_mod_dec_logformat_twofish_CryptoInfo.CryptModule != NULL)
    if(mcrypt_module_close(_mice_mod_dec_logformat_twofish_CryptoInfo.CryptModule) < 0)
      log_mesg(WARN, "%s: Error while closing Crypto Module!\n", _mice_mod_dec_logformat_twofish_cProgname);

  if(_mice_mod_dec_logformat_twofish_CryptoInfo.cPassword != NULL)
    free(_mice_mod_dec_logformat_twofish_CryptoInfo.cPassword);
  if(_mice_mod_dec_logformat_twofish_CryptoInfo.cKey != NULL)
    free(_mice_mod_dec_logformat_twofish_CryptoInfo.cKey);

  _mice_mod_dec_logformat_twofish_CfgDone = FALSE;

  return(0);
}



/*
** Read Config File and set global Var.s
*/
int _mice_mod_dec_logformat_twofish_HandleConfFile(char *cConfFile)
{
  int              iCfgCount;
  int              iCnt;
  struct stat      StatBuf;


  _mice_mod_dec_logformat_twofish_CfgCryptoInfo.iSectionNr  = -1;

  if(lstat(cConfFile, &StatBuf) < 0)
  {
    log_mesg(WARN_SYS, "mice_mod_dec_logformat_twofish: Error while trying lstat(%s) | Syserror", cConfFile);
    return(-1);
  }

  if((iCfgCount = cfgParse(cConfFile, _mice_mod_dec_logformat_twofish_CfgIni, CFG_INI)) < 0)
  {
    log_mesg(WARN, "mice_mod_dec_logformat_twofish: Error while parsing Config File %s\n", cConfFile);
    return(-2);
  }

  if(iCfgCount != SECT_MAXSECT)
  {
    log_mesg(WARN, "mice_mod_dec_logformat_twofish: Error while parsing Config File %s | Sections Read: %d | Sections Expect: %d", cConfFile, iCfgCount, SECT_MAXSECT);
    return(-3);
  }

  for(iCnt = 0; iCnt < iCfgCount; iCnt++)
  {
    if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_CRYPTO))
      _mice_mod_dec_logformat_twofish_CfgCryptoInfo.iSectionNr  = iCnt;
    else
    {
      log_mesg(WARN, "mice_mod_dec_logformat_twofish: Error in Config File %s | Unknown Section: %s", cConfFile, cfgSectionNumberToName(iCnt));
      return(-4);
    }
  }

  if( _mice_mod_dec_logformat_twofish_CfgCryptoInfo.iSectionNr == -1 )
  {
    log_mesg(WARN, "mice_mod_dec_logformat_twofish: Error in Config File %s, Section is missing!\n", cConfFile);
    return(-5);
  }

  return(0);
}

