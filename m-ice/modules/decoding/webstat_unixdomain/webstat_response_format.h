/***************************************************************************
                           webstat_response_format.h  -  description
                             -------------------
    copyright            : (C) 2003 by Thomas Biege
    email                : thomas@uin4d.de
 ***************************************************************************/
#ifndef __WEBSTATRESPFORMAT__
#define __WEBSTATRESPFORMAT__

#define WSP_MAX_MSG 8*1024

typedef struct
{
  size_t  size;
} WS_RespHeader;

typedef struct
{
  char    *scenario_name;
  u_long  scenario_id;
  u_long  instance_id;
  char    *from_state;
  char    *transition;
  char    *to_state;
  int     argc;
  char    **argv;
  void    *userdata;
} WS_RespPayload;


#endif


