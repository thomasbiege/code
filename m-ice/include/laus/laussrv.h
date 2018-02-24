/*
 * Utility functions for audit tools
 *
 * Copyright (C) 2003 SuSE Linux AG
 * Written by okir@suse.de
 */

#ifndef AUDIT_TOOLS_H
#define AUDIT_TOOLS_H


#ifdef __cplusplus
extern "C" {
#endif

/* Default logfile location */
#define PATH_LOGFILE		"/var/log/audit"



#define AUDPR_PRIVILEGES	0x00000001
#define AUDPR_PROCESSID		0x00000002
#define AUDPR_LOGINID		0x00000004
#define AUDPR_AUDITID		0x00000008
#define AUDPR_EVNAME		0x00000010
#define AUDPR_SEQNR		0x00000020
#define AUDPR_TIME		0x00000300
#define AUDPR_TIME_FMT_UNIX	0x00000100
#define AUDPR_TIME_FMT_ISO8601	0x00000200
#define AUDPR_TIME_FMT_RAW	0x00000300
#define AUDPR_FILEHDR		0x00000400

#define AUDPR_UID_ALL           0x00001000
#define AUDPR_GID_ALL           0x00002000

#define AUDPR_FOLLOW		0x04000000
#define AUDREC_TRUNC		0x80000000

#define AUDPR_PRINT_ALL		AUDPR_FILEHDR |\
				AUDPR_PRIVILEGES |\
				AUDPR_PROCESSID |\
				AUDPR_LOGINID |\
				AUDPR_AUDITID |\
				AUDPR_EVNAME |\
				AUDPR_SEQNR |\
				AUDPR_UID_ALL |\
				AUDPR_GID_ALL

typedef int		audit_callback_fn_t(const struct aud_message *, int);

extern int		audit_process_log(const char *, audit_callback_fn_t *, int);
extern void		audit_print_caption(int flags);
extern void		audit_print_header(const struct aud_message *, int flags);
extern int		audit_print(const struct aud_message *msg, int flags);

extern unsigned int	syscall_max(void);
extern const char *	syscall_code_to_name(unsigned int);
extern int		syscall_name_to_code(const char *);
extern unsigned int	socketcall_max(void);
extern const char *	socketcall_code_to_name(unsigned int);
extern int		socketcall_name_to_code(const char *);
extern unsigned int	ipccall_max(void);
extern const char *	ipccall_code_to_name(unsigned int);
extern int		ipccall_name_to_code(const char *);
extern unsigned int	event_min(void);
extern unsigned int	event_max(void);
extern const char *	event_code_to_name(unsigned int);
extern int		event_name_to_code(const char *);

extern void		audit_check_biarch(char **argv);

extern int		laus_version(void);
extern int		laus_api_version(void);

#ifdef __cplusplus
}; // end of extern "C"
#endif

#endif /* AUDIT_TOOLS_H */
