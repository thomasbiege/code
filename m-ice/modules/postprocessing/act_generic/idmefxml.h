/************************************************************************
 * libidmef: A library to create IDMEF messages in XML format.
 * Author: Joe McAlerney, Silicon Defense, (joey@SiliconDefense.com)
 *
 * Copyright (c) 2000,2001 by Silicon Defense (http://www.silicondefense.com/)
 * 
 * This library is released under the GNU GPL and BSD software licenses.
 * You may choose to use one or the other, BUT NOT BOTH.  The GNU GPL
 * license is located in the file named COPYING.  The BSD license is located
 * in the file named COPYING.BSD.  Please contact us if there are any
 * questions.
 **************************************************************************/

/***************************************************************
* This is an implementation of the IDMEF XML DTD described in
* draft-ietf-idwg-idmef-xml-05.txt
****************************************************************/

#ifndef IDMEF_XML_H
#define IDMEF_XML_H

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/valid.h>
#include <libxml/entities.h>
#include <libxml/xmlmemory.h>
#include <libxml/debugXML.h>
#include <libxml/xmlIO.h>
#include <libxml/xmlerror.h>
#include <sys/time.h>

#ifdef WIN32
typedef unsigned long ulong; /* windows uses ULONG, but not ulong */
#endif

#ifdef FREEBSD 
typedef unsigned long ulong; /* windows uses ULONG, but not ulong */
#endif


#define IDMEF_MESSAGE_VERSION  "1.0"
#define MAX_ALERTID_BUFFER_SIZE 11   /* ulong (2^32 + 1) */
#define MAX_UTC_DATETIME_SIZE   23   /* YYYY-MM-DDThh:mm:ss.ssZ */
#define TZ_SIZE                 6    /* +hh:mm */
#define MAX_NTP_TIMESTAMP_SIZE  21   /* 0xNNNNNNNN.0xNNNNNNNN */

#define DTD_NAME        "IDMEF-Message"
#define DTD_EXTERNAL_ID "-//IETF//DTD RFC XXXX IDMEF v1.0//EN"

/*******************************************
 * Global variables
 *******************************************/

xmlDocPtr doc;
xmlDtdPtr dtd;
xmlValidCtxtPtr vctxt;
char *g_dtd_path;
xmlOutputBufferPtr g_output;

/*=================================================*
 *               Function Prototypes               *
 *=================================================*/


/*=============================================================================
   New Element functions  

   Sub-elements/attributes that are not required, or additonal instances
   of the required ones, will be appended at the end of the parameter string -
   denoted by "..."
 ============================================================================*/

xmlNodePtr newIDMEF_Message(xmlNodePtr, ...);
xmlNodePtr newAlert(xmlNodePtr, ...);
xmlNodePtr newToolAlert(xmlNodePtr, ...);
xmlNodePtr newCorrelationAlert(xmlNodePtr, ...);
xmlNodePtr newOverflowAlert(xmlNodePtr, ...);
xmlNodePtr newHeartbeat(xmlNodePtr, ...);

xmlNodePtr newAnalyzer(xmlNodePtr, ...);
xmlNodePtr newAssessment(xmlNodePtr, ...);
xmlNodePtr newClassification(xmlNodePtr, ...);
xmlNodePtr newSource(xmlNodePtr, ...);
xmlNodePtr newTarget(xmlNodePtr, ...);
xmlNodePtr newAdditionalData(xmlNodePtr, ...);

xmlNodePtr newCreateTime(struct timeval *);
xmlNodePtr newAnalyzerTime(struct timeval *);
xmlNodePtr newDetectTime(struct timeval *);

xmlNodePtr newImpact(xmlNodePtr, ...);
xmlNodePtr newAction(xmlNodePtr, ...);
xmlNodePtr newConfidence(xmlNodePtr, ...);

xmlNodePtr newNode(xmlNodePtr, ...);
xmlNodePtr newAddress(xmlNodePtr, ...);
xmlNodePtr newUser(xmlNodePtr, ...);
xmlNodePtr newUserId(xmlNodePtr, ...);
xmlNodePtr newProcess(xmlNodePtr, ...);
xmlNodePtr newService(xmlNodePtr, ...);
xmlNodePtr newWebService(xmlNodePtr, ...);
xmlNodePtr newFileList(xmlNodePtr, ...);
xmlNodePtr newFile(xmlNodePtr, ...);
xmlNodePtr newFileAccess(xmlNodePtr, ...);
xmlNodePtr newLinkage(xmlNodePtr, ...);
xmlNodePtr newInode(xmlNodePtr, ...);
xmlNodePtr newSNMPService(xmlNodePtr, ...);


xmlNodePtr newSimpleElement(char *, char *);
xmlNodePtr newAttribute(char *, char *);

/*-----------------------------------------------------------------------*
 * These are functions that perform different operations on XML elements
 * that have been created with the above "new" functions.
 *-----------------------------------------------------------------------*/

xmlNodePtr addElement(xmlNodePtr, xmlNodePtr);
int addElements(xmlNodePtr, xmlNodePtr, ...);
xmlNodePtr setAttribute(xmlNodePtr, xmlNodePtr);
int setAttributes(xmlNodePtr, xmlNodePtr, ...);
xmlNodePtr getElement(xmlNodePtr, char *);
int hasElement(xmlNodePtr, char *);

/*-------------------------------------------------------------------------*
 * These are functions that perform different operations on XML documents.
 *-------------------------------------------------------------------------*/

int globalsInit(char *);
void IDMEFglobalFileOutputBufferInit(FILE *);
int createCurrentDoc(const char *);
xmlDocPtr createDoc(const char *);
int setCurrentDoc(xmlDocPtr);
xmlDocPtr getCurrentDoc();
void clearCurrentDoc();
xmlDocPtr copyCurrentDoc();
int resetCurrentDoc();
int validateCurrentDoc();
void printCurrentMessage(FILE *);

/*---------------------------------------
 * Miscellaneous time format functions.
 *---------------------------------------*/

xmlChar *currentNtpTimestamp();
xmlChar *currentDatetime();
xmlChar *timevalToNtpTimestamp(struct timeval *);
xmlChar *timevalToDatetime(struct timeval *);
int testTime();


/*--------------------------------
 * Other utility functions
 *-------------------------------*/

unsigned long getStoredAlertID(char *);
int saveAlertID(unsigned long, char *);
void badNode(xmlNodePtr, char *);
char * intToString(int);
char * ulongToString(unsigned long);
xmlDocPtr xmlAddIntSubset(xmlDocPtr, xmlDtdPtr);
xmlDtdPtr xmlRemoveIntSubset(xmlDocPtr);
char * ntpstampToString(void *);
xmlOutputBufferPtr IDMEFxmlOutputBufferCreate(FILE *, xmlCharEncodingHandlerPtr);
void IDMEFxmlDocContentDumpOutput(xmlOutputBufferPtr, xmlDocPtr, 
                                  const char *, int);
int IDMEFxmlFileWrite (void *, const char *, int);


#endif /* IDMEF_XML_H */
