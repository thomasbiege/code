#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>

#include <logformat.h>
#include <mice.h>
#include <mice_parse.h>

int  Debug = FALSE;

/*
** Subfunctions
*/
char *get_token_value(char *logline, char *token_id, size_t token_len, char *delim, size_t delim_len)
{
  char        *cPtr;
  static char cDummy[MAX_DATA];
  int         iCnt;


  if(Debug > 1)
    log_mesg(WARN, "libmice_parse: get_token_value: Looking for Value of Token '%s'[%d]", token_id, token_len);

  if( (cPtr = strstr(logline, token_id)) == NULL)
  {
    if(Debug > 1)
      log_mesg(WARN, "libmice_parse: get_token_value: %s with length %d not found", token_id, token_len);
    return(NULL);
  }

  memset(cDummy, 0, sizeof(cDummy));
  for(iCnt = 0, cPtr += token_len; iCnt < sizeof(cDummy) &&
                                   iCnt < strlen(logline) - (strlen(logline)-strlen(cPtr)) &&
                                   *cPtr != '\0';
      iCnt++, cPtr++)
  {
    //if( ((*cPtr) == ' ') && ((*(cPtr+1)) == '|') )
    if(Debug > 2)
      log_mesg(WARN, "libmice_parse: get_token_value: Checking for Delimiter '%s'[%d] in String '%s'",
               delim, delim_len, cPtr);
    if(strncmp(cPtr, delim, delim_len) == 0)
    {
      if(Debug > 1)
        log_mesg(WARN, "libmice_parse: get_token_value: End of Value found: '%s'[%d]", delim, delim_len);

      break;  // end of value
    }


    if(Debug > 2)
      log_mesg(WARN, "libmice_parse: get_token_value: Copy Value %c", *cPtr);
    cDummy[iCnt] = (*cPtr);
  }

  // Token with no value
  if(iCnt == 0)
  {
    if(Debug)
      log_mesg(WARN, "libmice_parse: get_token_value: NO VALUE");
    strcpy(cDummy, "NO VALUE");
  }

  return(cDummy);
}

int parse_scslog_entry(char *logline, SCSLogFormat *scslog_ptr)
{
  char *cValuePtr;


  if(!strstr(logline, SCSLOG_IDENTIFIER))
    return(-1);

  // Syscall
  if( (cValuePtr = get_token_value(logline, SCSLOG_SYSCALL, strlen(SCSLOG_SYSCALL), SCSLOG_DELIMITER,
                                   strlen(SCSLOG_DELIMITER))) == NULL)
    return(-2);
  snprintf(scslog_ptr->cSyscall, sizeof(scslog_ptr->cSyscall), "%s", cValuePtr);


  // Program
  if( (cValuePtr = get_token_value(logline, SCSLOG_PROGRAM, strlen(SCSLOG_PROGRAM), SCSLOG_DELIMITER,
                                   strlen(SCSLOG_DELIMITER))) == NULL)
    return(-3);
  snprintf(scslog_ptr->cProgram, sizeof(scslog_ptr->cProgram), "%s", cValuePtr);


  // PID
  if( (cValuePtr = get_token_value(logline, SCSLOG_PID, strlen(SCSLOG_PID), SCSLOG_DELIMITER,
                                   strlen(SCSLOG_DELIMITER))) == NULL)
    return(-4);
  scslog_ptr->PID =(pid_t) atoi(cValuePtr);


  // UID
  if( (cValuePtr = get_token_value(logline, SCSLOG_UID, strlen(SCSLOG_UID), SCSLOG_DELIMITER,
                                   strlen(SCSLOG_DELIMITER))) == NULL)
    return(-5);
  scslog_ptr->UID = (uid_t) atoi(cValuePtr);


  // EUID
  if( (cValuePtr = get_token_value(logline, SCSLOG_EUID, strlen(SCSLOG_EUID), SCSLOG_DELIMITER,
                                   strlen(SCSLOG_DELIMITER))) == NULL)
    return(-6);
  scslog_ptr->EUID = (uid_t) atoi(cValuePtr);


  // Call
  if( (cValuePtr = get_token_value(logline, SCSLOG_CALL, strlen(SCSLOG_CALL), SCSLOG_DELIMITER,
                                   strlen(SCSLOG_DELIMITER))) == NULL)
    return(-7);
  snprintf(scslog_ptr->cCall, sizeof(scslog_ptr->cCall), "%s", cValuePtr);


  // Comment
  if( (cValuePtr = get_token_value(logline, SCSLOG_COMMENT, strlen(SCSLOG_COMMENT), SCSLOG_DELIMITER,
                                   strlen(SCSLOG_DELIMITER))) == NULL)
    return(-8);
  snprintf(scslog_ptr->cComment, sizeof(scslog_ptr->cComment), "%s", cValuePtr);

  return(0);
}

int parse_firewall_entry(char *logline, FirewallLogFormat *fwlog_ptr)
{
  char *cValuePtr;


  if(!strstr(logline, FW_IDENTIFIER))
    return(-1);

  // Action
  if( (cValuePtr = get_token_value(logline, FW_ACTION, strlen(FW_ACTION), FW_DELIMITER, strlen(FW_DELIMITER))) == NULL)
    return(-2);
  snprintf(fwlog_ptr->cAction, sizeof(fwlog_ptr->cAction), "%s", cValuePtr);

  // In
  if( (cValuePtr = get_token_value(logline, FW_IN, strlen(FW_IN), FW_DELIMITER, strlen(FW_DELIMITER))) == NULL)
    return(-3);
  snprintf(fwlog_ptr->cIn, sizeof(fwlog_ptr->cIn), "%s", cValuePtr);

  // Out
  if( (cValuePtr = get_token_value(logline, FW_OUT, strlen(FW_OUT), FW_DELIMITER, strlen(FW_DELIMITER))) == NULL)
    return(-4);
  snprintf(fwlog_ptr->cOut, sizeof(fwlog_ptr->cOut), "%s", cValuePtr);

  // MAC
  if( (cValuePtr = get_token_value(logline, FW_MAC, strlen(FW_MAC), FW_DELIMITER, strlen(FW_DELIMITER))) == NULL)
    return(-5);
  snprintf(fwlog_ptr->cMAC, sizeof(fwlog_ptr->cMAC), "%s", cValuePtr);

  // Source
  if( (cValuePtr = get_token_value(logline, FW_SOURCE, strlen(FW_SOURCE), FW_DELIMITER, strlen(FW_DELIMITER))) == NULL)
    return(-6);
  snprintf(fwlog_ptr->cSource, sizeof(fwlog_ptr->cSource), "%s", cValuePtr);

  // Destination
  if( (cValuePtr = get_token_value(logline, FW_DESTINATION, strlen(FW_DESTINATION), FW_DELIMITER, strlen(FW_DELIMITER))) == NULL)
    return(-7);
  snprintf(fwlog_ptr->cDestination, sizeof(fwlog_ptr->cDestination), "%s", cValuePtr);

  // IP Length
  if( (cValuePtr = get_token_value(logline, FW_IPLENGTH, strlen(FW_IPLENGTH), FW_DELIMITER, strlen(FW_DELIMITER))) == NULL)
    return(-8);
  if(isdigit(*cValuePtr))
    fwlog_ptr->uiIPLength = (u_int) atoi(cValuePtr);
  else
    fwlog_ptr->uiIPLength = 0;


  // TOS
  if( (cValuePtr = get_token_value(logline, FW_TOS, strlen(FW_TOS), FW_DELIMITER, strlen(FW_DELIMITER))) == NULL)
    return(-9);
  if(isdigit(*cValuePtr))
    fwlog_ptr->uiTOS = (u_int) atoi(cValuePtr);
  else
    fwlog_ptr->uiTOS = 0;

  // Prec
  if( (cValuePtr = get_token_value(logline, FW_PREC, strlen(FW_PREC), FW_DELIMITER, strlen(FW_DELIMITER))) == NULL)
    return(-10);
  if(isdigit(*cValuePtr))
    fwlog_ptr->uiPrec = (u_int) atoi(cValuePtr);
  else
    fwlog_ptr->uiPrec = 0;

  // TTL
  if( (cValuePtr = get_token_value(logline, FW_TTL, strlen(FW_TTL), FW_DELIMITER, strlen(FW_DELIMITER))) == NULL)
    return(-11);
  if(isdigit(*cValuePtr))
    fwlog_ptr->uiTTL = (u_int) atoi(cValuePtr);
  else
    fwlog_ptr->uiTTL = 0;

  // ID
  if( (cValuePtr = get_token_value(logline, FW_ID, strlen(FW_ID), FW_DELIMITER, strlen(FW_DELIMITER))) == NULL)
    return(-12);
  if(isdigit(*cValuePtr))
    fwlog_ptr->uiID = (u_int) atoi(cValuePtr);
  else
    fwlog_ptr->uiID = 0;

  // Protocol
  if( (cValuePtr = get_token_value(logline, FW_PROTOCOL, strlen(FW_PROTOCOL), FW_DELIMITER, strlen(FW_DELIMITER))) == NULL)
    return(-13);
  snprintf(fwlog_ptr->cProtocol, sizeof(fwlog_ptr->cProtocol), "%s", cValuePtr);

  // Source Port
  if( (cValuePtr = get_token_value(logline, FW_SRCPORT, strlen(FW_SRCPORT), FW_DELIMITER, strlen(FW_DELIMITER))) == NULL)
    return(-14);
  if(isdigit(*cValuePtr))
    fwlog_ptr->uiSrcPort = (u_int) atoi(cValuePtr);
  else
    fwlog_ptr->uiSrcPort = 0;

  // Destination Port
  if( (cValuePtr = get_token_value(logline, FW_DSTPORT, strlen(FW_DSTPORT), FW_DELIMITER, strlen(FW_DELIMITER))) == NULL)
    return(-15);
  if(isdigit(*cValuePtr))
    fwlog_ptr->uiDstPort = (u_int) atoi(cValuePtr);
  else
    fwlog_ptr->uiDstPort = 0;

  // Packet Length (TCP, USP, ICMP, ...)
  if( (cValuePtr = get_token_value(logline, FW_PACLENGTH, strlen(FW_PACLENGTH), FW_DELIMITER, strlen(FW_DELIMITER))) == NULL)
    return(-16);
  if(isdigit(*cValuePtr))
    fwlog_ptr->uiPacLength = (u_int) atoi(cValuePtr);
  else
    fwlog_ptr->uiPacLength = 0;


  return(0);
}


#ifdef HAVE_LIBLAUSSRV
/*
** Parse LAuS Messages
*/

#include "syscall.h"

int parse_laus_header(char *logline, LausLogFormat *laus_ptr)
{
  return(0);
}

int parse_laus_login_msg(char *logline, LausLogFormat *laus_ptr)
{
  struct aud_message      *msg =  (struct aud_message *) logline;
  //typedef char amsg_aligned_t[-(ssize_t)(offsetof(LogFormat, cLogLine) & (__alignof__(*amsg) - 1))];
  struct aud_msg_login	  *logmsg;
  typedef char            logmsg_aligned_t[-(ssize_t)(offsetof(struct aud_message, msg_data) &
                                                      (__alignof__(*logmsg) - 1))];


  /* ensemble message */
  if(laus_ptr == NULL || logline == NULL || msg->msg_type != AUDIT_MSG_LOGIN)
    return(-1);

  if (msg->msg_size != sizeof(*msg) + sizeof(*logmsg))
    return(-2);

  logmsg = (struct aud_msg_login *) msg->msg_data;

  memcpy(&laus_ptr->msg, msg, sizeof(struct aud_message));
  memcpy(&laus_ptr->type.msg_login, logmsg, sizeof(struct aud_msg_login));
  
  return(0);
}


int parse_laus_text_msg(char *logline, LausLogFormat *laus_ptr)
{
  struct aud_message  *msg =  (struct aud_message *) logline;
  //typedef char amsg_aligned_t[-(ssize_t)(offsetof(LogFormat, cLogLine) & (__alignof__(*amsg) - 1))];


  if(laus_ptr == NULL || logline == NULL || msg->msg_type != AUDIT_MSG_TEXT)
    return(-1);

  if ( (msg->msg_size - sizeof(*msg)) <= 0)
    return(-2);

  /* ensemble message */
  memcpy(&laus_ptr->msg, msg, sizeof(struct aud_message));
  memcpy(&laus_ptr->type.msg_text, (char *) msg->msg_data, MAX_DATA);

  return(0);
}


int parse_laus_syscall_msg(char *logline, LausLogFormat *laus_ptr)
{
  struct aud_message            *msg =  (struct aud_message *) logline;
  //typedef char amsg_aligned_t[-(ssize_t)(offsetof(LogFormat, cLogLine) & (__alignof__(*amsg) - 1))];
  struct syscall_data           data;
  const struct aud_msg_syscall  *scmsg;
  typedef char scmsg_aligned_t[-(ssize_t)(offsetof(struct aud_message, msg_data) & (__alignof__(*scmsg) - 1))];
  laus_scall                    *scall = &laus_ptr->type.msg_syscall;
  const unsigned char           *args;
  unsigned int                  size;
  u_int32_t                     type, len;
  unsigned int                  nargs;


  if(laus_ptr == NULL || logline == NULL || msg->msg_type != AUDIT_MSG_SYSCALL)
    return(-1);

  if ( (msg->msg_size - sizeof(*msg)) <= 0)
    return(-2);

  /* prepare the data */
  scmsg  = (const struct aud_msg_syscall *) msg->msg_data;
  args   = scmsg->data;
  size   = scmsg->length;
  if (size > msg->msg_size - sizeof(*msg))
  {
    size = msg->msg_size - sizeof(*msg);
    if (size < sizeof(*scmsg))
      return(-1);
  }

  memset(&data, 0, sizeof(data));
  data.major  = scmsg->major;
  data.minor  = scmsg->minor;
  data.result = scmsg->result;

  for (nargs = 0; size > 0 && nargs < MAX_ARGS; nargs++)
  {
    struct syscall_arg	*arg = &data.args[nargs];

    if (size < 8)
      return(-2); // truncated argument

    memcpy(&type, args, 4); args += 4;
    memcpy(&len,  args, 4); args += 4;
    size -= 8;

    if (type == AUDIT_ARG_END)
      break;
    if (len > size)
      len = size;

    /* do not display the NUL byte */
    if (type == AUDIT_ARG_STRING && len && args[len-1] == '\0')
      len--;

    arg->type = type;
    arg->data = args;
    arg->len  = len;

    args += len;
    size -= len;
  }
  data.nargs = nargs;

  /* ok get all we need */
  scall->name = NULL;
  syscall_get(&data, scall);

  /* ensemble message */
  memcpy(&laus_ptr->msg, msg, sizeof(struct aud_message));


  return(0);
}

int parse_laus_netlink_msg(char *logline, LausLogFormat *laus_ptr)
{
  /* XXX thomas: we do not support them now */
  log_mesg(WARN, "libmice_parse: Netlink messages are not supported.\n");
  return(0);
}

int parse_laus_exit_msg(char *logline, LausLogFormat *laus_ptr)
{
  struct aud_message    *msg =  (struct aud_message *) logline;
  //typedef char amsg_aligned_t[-(ssize_t)(offsetof(LogFormat, cLogLine) & (__alignof__(*amsg) - 1))];
  struct aud_msg_exit   *exitmsg;
  typedef char exitmsg_aligned_t[-(ssize_t)(offsetof(struct aud_message, msg_data) & (__alignof__(*exitmsg) - 1))];


  if(laus_ptr == NULL || logline == NULL || msg->msg_type != AUDIT_MSG_EXIT)
    return(-1);

  exitmsg  = (struct aud_msg_exit *) msg->msg_data;

  /* ensemble message */
  memcpy(&laus_ptr->msg, msg, sizeof(struct aud_message));
  memcpy(&laus_ptr->type.msg_exit, exitmsg, sizeof(struct aud_msg_exit));

  return(0);
}

int parse_laus_unknown_msg(char *logline, LausLogFormat *laus_ptr)
{
  struct aud_message  *msg =  (struct aud_message *) logline;
  //typedef char amsg_aligned_t[-(ssize_t)(offsetof(LogFormat, cLogLine) & (__alignof__(*amsg) - 1))];

  log_mesg(WARN, "libmice_parse: unknown message type %d:0x%02x\n", msg->msg_type, msg->msg_type);

  if(Debug)
  {
    //debug_message((char *) msg, sizeof(*msg));
  }

  return(-1);
}
#endif

