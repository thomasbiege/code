#ifndef __LIBMICE_PARSE_HDR__
#define __LIBMICE_PARSE_HDR__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


#ifdef HAVE_LIBLAUSSRV
  #include <time.h>
  #include <linux/audit.h>
  #include <audit.h>
  #include <laus.h>
  #include <laussrv.h>
  #define offsetof(T, mem)  ((caddr_t) &((T *) 0)->mem - (caddr_t) 0)
#endif


#define SCSLOG_DELIMITER  " |"
#define SCSLOG_IDENTIFIER "scslog2syslog"
#define SCSLOG_SYSCALL    "Syscall: "
#define SCSLOG_PROGRAM    "Program: "
#define SCSLOG_PID        "PID: "
#define SCSLOG_UID        "UID: "
#define SCSLOG_EUID       "EUID: "
#define SCSLOG_CALL       "Call: "
#define SCSLOG_COMMENT    "Comment: "

#define FW_DELIMITER      " "
#define FW_IDENTIFIER     "SuSE-FW"
#define FW_ACTION         "SuSE-FW-"
#define FW_IN             "IN="
#define FW_OUT            "OUT="
#define FW_MAC            "MAC="
#define FW_SOURCE         "SRC="
#define FW_DESTINATION    "DST="
#define FW_IPLENGTH       "LEN="
#define FW_TOS            "TOS="
#define FW_PREC           "PREC="
#define FW_TTL            "TTL="
#define FW_ID             "ID="
#define FW_PROTOCOL       "PROTO="
#define FW_SRCPORT        "SPT="
#define FW_DSTPORT        "DPT="
#define FW_PACLENGTH      "LEN="    // appears twice, we should use more
                                    // sophistocated parsing




char  *get_token_value(char *logline, char *token_id, size_t token_len,
                       char *delim, size_t delim_len);
int    parse_scslog_entry(char *logline, SCSLogFormat *scslog_ptr);
int    parse_iptables_entry(char *logline, FirewallLogFormat *fwlog_ptr);
int    parse_syslog_entry(char *logline);

#ifdef HAVE_LIBLAUSSRV
int    parse_laus_header(char *logline, LausLogFormat *laus_ptr);
int    parse_laus_login_msg(char *logline, LausLogFormat *laus_ptr);
int    parse_laus_text_msg(char *logline, LausLogFormat *laus_ptr);
int    parse_laus_syscall_msg(char *logline, LausLogFormat *laus_ptr);
int    parse_laus_netlink_msg(char *logline, LausLogFormat *laus_ptr);
int    parse_laus_exit_msg(char *logline, LausLogFormat *laus_ptr);
int    parse_laus_unknown_msg(char *logline, LausLogFormat *laus_ptr);
#endif


#endif
