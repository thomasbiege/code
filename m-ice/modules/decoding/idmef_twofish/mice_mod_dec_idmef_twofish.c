/***************************************************************************
                          mice_mod_dec_idmef_twofish.h  -  description
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <mcrypt.h>

#include <mice.h>
#include "mice_mod_dec_idmef_twofish.h"
#include "idmef-mesg-format.h"
#include "parsecfg.h"


#define TRUE              1
#define FALSE             0



int    _mice_mod_dec_idmef_twofish_iDebug = FALSE;

char  *_mice_mod_dec_idmef_twofish_cProgname;


/*
** Crypto
*/
struct
{
  MCRYPT    CryptModule;
  char      *cCryptModName;
  size_t    KeySize;  /* 128 Bit Key */
  char      *cKey;
  char      *cRawKey;
  char      *cPassword;
  char      *cDevRand;
} _mice_mod_dec_idmef_twofish_CryptoInfo;


/*
** Configure Stuff
*/
int _mice_mod_dec_idmef_twofish_CfgDone = FALSE;

struct
{
  int     iSectionNr;
  char    **cCfgKey;  // XXX: what's about protected pages for our Keys so they can not be swapped?
  char    **cCfgCryptoMod;
  char    **cCfgDevRand;
} _mice_mod_dec_idmef_twofish_CfgCryptoInfo;

struct
{
  int     iSectionNr;
  char    **cCfgMaxMsgSize;
} _mice_mod_dec_idmef_twofish_CfgIdmefInfo;


cfgStruct    _mice_mod_dec_idmef_twofish_CfgIni[] =
{
  // Crypto Info
  {"ENCKEY"     ,CFG_STRING       ,&_mice_mod_dec_idmef_twofish_CfgCryptoInfo.cCfgKey       },
  {"CRYPTMOD"   ,CFG_STRING       ,&_mice_mod_dec_idmef_twofish_CfgCryptoInfo.cCfgCryptoMod },
  {"DEVRANDOM"  ,CFG_STRING       ,&_mice_mod_dec_idmef_twofish_CfgCryptoInfo.cCfgDevRand   },

  // IDMEF Info
  {"MAXMSGSIZE" ,CFG_STRING       ,&_mice_mod_dec_idmef_twofish_CfgIdmefInfo.cCfgMaxMsgSize },

  // The End
  {NULL         ,CFG_END          ,NULL                                             }
};



/*
** Function Declaration
*/
int _mice_mod_dec_idmef_twofish_HandleConfFile(char *cConfFile);



/***************************************************************************************
**
** p u b l i c   M o d u l e   F u n c t i o n s
**
***************************************************************************************/


/*
** Init
*/
size_t mice_mod_dec_idmef_twofish_LTX_init(char *ConfFile)
{

  _mice_mod_dec_idmef_twofish_cProgname = "BufferDaemon/mice_mod_dec_idmef_twofish";


  if(_mice_mod_dec_idmef_twofish_CfgDone != FALSE)
  {
    log_mesg(WARN, "mice_mod_dec_idmef_twofish: Do NOT call init function twice, call close function inbetween");
    return(-1);
  }

  if(_mice_mod_dec_idmef_twofish_HandleConfFile(ConfFile) < 0)
    return(-1);


  _mice_mod_dec_idmef_twofish_CryptoInfo.cRawKey        = _mice_mod_dec_idmef_twofish_CfgCryptoInfo.cCfgKey[_mice_mod_dec_idmef_twofish_CfgCryptoInfo.iSectionNr];
  _mice_mod_dec_idmef_twofish_CryptoInfo.cCryptModName  = _mice_mod_dec_idmef_twofish_CfgCryptoInfo.cCfgCryptoMod[_mice_mod_dec_idmef_twofish_CfgCryptoInfo.iSectionNr];
  _mice_mod_dec_idmef_twofish_CryptoInfo.cDevRand       = _mice_mod_dec_idmef_twofish_CfgCryptoInfo.cCfgDevRand[_mice_mod_dec_idmef_twofish_CfgCryptoInfo.iSectionNr];
  _mice_mod_dec_idmef_twofish_CryptoInfo.KeySize        = 16;


  /*
  ** Init. Crypto Module
  */
  if(strlen(_mice_mod_dec_idmef_twofish_CryptoInfo.cRawKey) >= MIN_KEYLEN)
  {
    if(_mice_mod_dec_idmef_twofish_iDebug)
      log_mesg(WARN, "%s: Debug: Init. Crypto Module\n", _mice_mod_dec_idmef_twofish_cProgname);

    if((_mice_mod_dec_idmef_twofish_CryptoInfo.cKey = calloc(_mice_mod_dec_idmef_twofish_CryptoInfo.KeySize, 1)) == NULL)
    {
      log_mesg(WARN_SYS, "%s: Error while allocating Memory for Twofish Key\n", _mice_mod_dec_idmef_twofish_cProgname);
      return(-2);
    }

    
    if((_mice_mod_dec_idmef_twofish_CryptoInfo.cPassword = calloc(strlen(_mice_mod_dec_idmef_twofish_CryptoInfo.cRawKey)+1, 1)) == NULL)
    {
      log_mesg(WARN_SYS, "%s: Error while allocating Memory for decryption Key\n", _mice_mod_dec_idmef_twofish_cProgname);
      return(-3);
    }

    strcpy(_mice_mod_dec_idmef_twofish_CryptoInfo.cPassword, _mice_mod_dec_idmef_twofish_CryptoInfo.cRawKey);
    memmove(_mice_mod_dec_idmef_twofish_CryptoInfo.cKey, _mice_mod_dec_idmef_twofish_CryptoInfo.cPassword, _mice_mod_dec_idmef_twofish_CryptoInfo.KeySize);
    

    //_mice_mod_dec_idmef_twofish_CryptoInfo.cPassword = NULL;
    //memmove(_mice_mod_dec_idmef_twofish_CryptoInfo.cKey, _mice_mod_dec_idmef_twofish_CryptoInfo.cRawKey, _mice_mod_dec_idmef_twofish_CryptoInfo.KeySize);

    if(_mice_mod_dec_idmef_twofish_iDebug)
      log_mesg(WARN, "%s: Debug: init: mcrypt_open()", _mice_mod_dec_idmef_twofish_cProgname);

    if((_mice_mod_dec_idmef_twofish_CryptoInfo.CryptModule = mcrypt_module_open(_mice_mod_dec_idmef_twofish_CryptoInfo.cCryptModName, NULL, "cfb", NULL)) == MCRYPT_FAILED)
    {
      log_mesg(WARN, "%s: Error while trying to load Crypto Module '%s'", _mice_mod_dec_idmef_twofish_cProgname, _mice_mod_dec_idmef_twofish_CryptoInfo.cCryptModName);
      return(-4);
    }
  }
  else
  {
    log_mesg(WARN, "%s: Key is shorter then the minimum length of %d characters\n", _mice_mod_dec_idmef_twofish_cProgname, MIN_KEYLEN);
    return(-5);
  }

  _mice_mod_dec_idmef_twofish_CfgDone = TRUE;


  if(_mice_mod_dec_idmef_twofish_iDebug)
    log_mesg(WARN, "%s: Debug: init: return\n", _mice_mod_dec_idmef_twofish_cProgname);

  return(sizeof(CipherIdmefMsg)); // return the max. size of bytes the caller must accept for a message

  // XXX oder doch ne struct{ sizeof decoedmsg, sizeof decodedmsg }

}



/*
** Main Function
*/
char *mice_mod_dec_idmef_twofish_LTX_func(char *cData, size_t DataSize)
{
  static char     cDecodedMsg[sizeof(CipherIdmefMsg)];  // TAKE CARE: this gets overwritten at next call

  u_short         sChkSum_Orig;
  u_short         sChkSum_New;

  register int    iCnt;

  CipherIdmefMsg  *CMsg;
  IdmefMsgFormat  *IdmefMsgPtr;




  if(_mice_mod_dec_idmef_twofish_CfgDone != TRUE)
  {
    log_mesg(WARN, "mice_mod_dec_idmef_twofish_twofish: Error! You have to call mice_mod_dec_idmef_twofish_LTX_init() first!");
    return(NULL);
  }


  CMsg = (CipherIdmefMsg *)  cData;
  

  if(_mice_mod_dec_idmef_twofish_iDebug)
    log_mesg(WARN, "%s: Debug: IVLen = %d, IV[0] = 0x%0.2x, CipherTextLen = %d, expected Length = %d\n", _mice_mod_dec_idmef_twofish_cProgname, CMsg->IVLen, CMsg->IV[0], CMsg->CipherTextLen, sizeof(IdmefMsgFormat));

  if( CMsg->CipherTextLen != sizeof(IdmefMsgFormat) )
  {
    log_mesg(WARN, "%s: Error: Length of received Messages does not match the expected Length!!!", _mice_mod_dec_idmef_twofish_cProgname);
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
    if(_mice_mod_dec_idmef_twofish_iDebug)
      log_mesg(WARN, "%s: Debug: Message is NOT decrypted!", _mice_mod_dec_idmef_twofish_cProgname);

    IdmefMsgPtr  = (IdmefMsgFormat *)  CMsg->cCipherText;

    return(IdmefMsgPtr->cIdmefMsg);
  }



  /*
  ** Message is decryted. Let's decrypt it!
  */
  if(_mice_mod_dec_idmef_twofish_iDebug)
    log_mesg(WARN, "%s: Debug: Decrypt Data", _mice_mod_dec_idmef_twofish_cProgname);

  if(mcrypt_generic_init(_mice_mod_dec_idmef_twofish_CryptoInfo.CryptModule, _mice_mod_dec_idmef_twofish_CryptoInfo.cKey, _mice_mod_dec_idmef_twofish_CryptoInfo.KeySize, CMsg->IV) < 0)
  {
    log_mesg(WARN, "%s: Error while initializing Crypto Module\n", _mice_mod_dec_idmef_twofish_cProgname);
    return(NULL);
  }

/*
  if(_mice_mod_dec_idmef_twofish_iDebug)
  {
    char  plain[1024],
          cipher[1024];

    memcpy(plain, "TEXTMSG", 7);
    memcpy(cipher, plain, strlen(plain));

    for(iCnt = 0; iCnt < strlen(cipher); iCnt++)
      mcrypt_generic(_mice_mod_dec_idmef_twofish_CryptoInfo.CryptModule, &cipher[iCnt], 1);
    for(iCnt = 0; iCnt < strlen(cipher); iCnt++)
      mdecrypt_generic(_mice_mod_dec_idmef_twofish_CryptoInfo.CryptModule, &cipher[iCnt], 1);

    if(strcmp(plain, cipher) != 0)
      log_mesg(WARN, "%s: Debug: CRYPT-TEST does not match: plain = '%s', cipher = '%s'", _mice_mod_dec_idmef_twofish_cProgname, plain, cipher);
    else
      log_mesg(WARN, "%s: Debug: CRYPT-TEST does match: plain = '%s', cipher = '%s'", _mice_mod_dec_idmef_twofish_cProgname, plain, cipher);
  }
*/

  memset(cDecodedMsg, 0, sizeof(cDecodedMsg));
  memcpy(cDecodedMsg, CMsg->cCipherText, CMsg->CipherTextLen);


  for(iCnt = 0; iCnt < CMsg->CipherTextLen; iCnt++)
    mdecrypt_generic(_mice_mod_dec_idmef_twofish_CryptoInfo.CryptModule, &cDecodedMsg[iCnt], 1);

  IdmefMsgPtr = (IdmefMsgFormat *) cDecodedMsg;

  if(_mice_mod_dec_idmef_twofish_iDebug)
    log_mesg(WARN, "%s: Debug: Decrypted Data: '%s'", _mice_mod_dec_idmef_twofish_cProgname, cDecodedMsg);



  /*
  ** Verify Checksum (CRC)
  */
  if(_mice_mod_dec_idmef_twofish_iDebug)
    log_mesg(WARN, "%s: Debug: Verify Checksum\n", _mice_mod_dec_idmef_twofish_cProgname);

  sChkSum_Orig          = IdmefMsgPtr->sChkSum;
  IdmefMsgPtr->sChkSum  = 0;
  sChkSum_New           = in_chksum((u_short *) cDecodedMsg, CMsg->CipherTextLen);

  if(_mice_mod_dec_idmef_twofish_iDebug)
    log_mesg(WARN, "%s: Debug: Checksum (Orig [%hu], New [%hu])", _mice_mod_dec_idmef_twofish_cProgname, sChkSum_Orig, sChkSum_New);

  if(sChkSum_Orig != sChkSum_New)
  {
    log_mesg(WARN, "%s: Debug: Checksum does not match... skipping Message\n", _mice_mod_dec_idmef_twofish_cProgname);
    return(NULL);
  }

  IdmefMsgPtr->sChkSum = sChkSum_Orig;

  if(mcrypt_generic_deinit(_mice_mod_dec_idmef_twofish_CryptoInfo.CryptModule) < 0)
    log_mesg(WARN, "%s: Error while clearing Crypto Module!", _mice_mod_dec_idmef_twofish_cProgname);

  return(IdmefMsgPtr->cIdmefMsg);    // XXX: return cDecodedMsg and handle it in the Output-Module to keep up consistdecy
}



/*
** Close
*/
int mice_mod_dec_idmef_twofish_LTX_close(void)
{
  if(_mice_mod_dec_idmef_twofish_CryptoInfo.CryptModule != NULL)
    if(mcrypt_module_close(_mice_mod_dec_idmef_twofish_CryptoInfo.CryptModule) < 0)
      log_mesg(WARN, "%s: Error while closing Crypto Module!", _mice_mod_dec_idmef_twofish_cProgname);

  if(_mice_mod_dec_idmef_twofish_CryptoInfo.cPassword != NULL)
    free(_mice_mod_dec_idmef_twofish_CryptoInfo.cPassword);
  if(_mice_mod_dec_idmef_twofish_CryptoInfo.cKey != NULL)
    free(_mice_mod_dec_idmef_twofish_CryptoInfo.cKey);

  _mice_mod_dec_idmef_twofish_CfgDone = FALSE;

  return(0);
}



/*
** Read Config File and set global Var.s
*/
int _mice_mod_dec_idmef_twofish_HandleConfFile(char *cConfFile)
{
  int              iCfgCount;
  int              iCnt;
  struct stat      StatBuf;


  _mice_mod_dec_idmef_twofish_CfgCryptoInfo.iSectionNr  = -1;
  _mice_mod_dec_idmef_twofish_CfgIdmefInfo.iSectionNr   = -1;

  if(lstat(cConfFile, &StatBuf) < 0)
  {
    log_mesg(WARN_SYS, "mice_mod_dec_idmef_twofish_twofish: Error while trying lstat(%s) | Syserror", cConfFile);
    return(-1);
  }

  if((iCfgCount = cfgParse(cConfFile, _mice_mod_dec_idmef_twofish_CfgIni, CFG_INI)) < 0)
  {
    log_mesg(WARN, "mice_mod_dec_idmef_twofish_twofish: Error while parsing Config File %s\n", cConfFile);
    return(-2);
  }

  if(iCfgCount != SECT_MAXSECT)
  {
    log_mesg(WARN, "mice_mod_dec_idmef_twofish_twofish: Error while parsing Config File %s | Sections Read: %d | Sections Expect: %d", cConfFile, iCfgCount, SECT_MAXSECT);
    return(-3);
  }

  for(iCnt = 0; iCnt < iCfgCount; iCnt++)
  {
    if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_CRYPTO))
      _mice_mod_dec_idmef_twofish_CfgCryptoInfo.iSectionNr  = iCnt;
    else if(!strcasecmp(cfgSectionNumberToName(iCnt), SECT_IDMEF))
      _mice_mod_dec_idmef_twofish_CfgIdmefInfo.iSectionNr   = iCnt;
    else
    {
      log_mesg(WARN, "mice_mod_dec_idmef_twofish_twofish: Error in Config File %s | Unknown Section: %s", cConfFile, cfgSectionNumberToName(iCnt));
      return(-4);
    }
  }

  if( _mice_mod_dec_idmef_twofish_CfgCryptoInfo.iSectionNr == -1 || _mice_mod_dec_idmef_twofish_CfgIdmefInfo.iSectionNr == -1)
  {
    log_mesg(WARN, "mice_mod_dec_idmef_twofish_twofish: Error in Config File %s, Section is missing!", cConfFile);
    return(-5);
  }

  return(0);
}

