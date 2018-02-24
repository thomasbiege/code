/***************************************************************************
                          mice_mod_out_aa_regex.c  -  description
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

#ifndef __MICE_MOD_OUT_AA_REGEX_HDR__
#define __MICE_MOD_OUT_AA_REGEX_HDR__


#define XML_VERSION   "1.0"


// RegEx
#define FASTMAPSIZE   1024


// Host Info ID
#define HI_NONE       0x0001
#define HI_MNGMNT     0x0010
#define HI_AGENT      0x0100
#define HI_BOTH       0x0110


// Section ID
#define SECT_HOST     "HOST_INFO"
#define SECT_IDMEF    "IDMEF_INFO"
#define SECT_AUTH     "AUTH"
#define SECT_ROOT     "ROOT"
#define SECT_READ     "READ"
#define SECT_WRITE    "WRITE"
#define SECT_MONI     "MONITORING"
#define SECT_APPS     "APPS"
#define SECT_EXPL     "EXPLOIT"
#define SECT_FW       "FIREWALL"
#define SECT_DEF      "DEFAULT"
#define SECT_MAXSECT  11


// Section Type
#define ST_AUTH       0x1000
#define ST_ROOT       0x2000
#define ST_READ       0x3000
#define ST_WRITE      0x4000
#define ST_MONI       0x5000
#define ST_APPS       0x6000
#define ST_EXPL       0x7000
#define ST_FW         0x8000
#define ST_DEF        0x0000


// Rules Type
#define RT_AUTH_S     "0x1010"
#define RT_AUTH_F     "0x1020"
                                                 
#define RT_ROOT_W     "0x2010"
#define RT_ROOT_O     "0x2020"
#define RT_ROOT_R     "0x2030"
#define RT_ROOT_S     "0x2040"
#define RT_ROOT_E     "0x2050"

#define RT_READ_S     "0x3010"
#define RT_READ_F     "0x3020"

#define RT_WRITE_S    "0x4010"
#define RT_WRITE_F    "0x4020"

#define RT_MONI_U     "0x5010"
#define RT_MONI_G     "0x5020"

#define RT_APPS_N     "0x6010"

#define RT_EXPL_R     "0x7010"

#define RT_FW_D       "0x8010"
#define RT_FW_R       "0x8020"
#define RT_FW_A       "0x8030"
#define RT_FW_I       "0x8040"

                              
// Log Data Type
#define LT_RAW        0x01
#define LT_SCS        0x02


#endif

