/***************************************************************************
                          liblaus.h  -  description
                             -------------------
    copyright            : (C) 2003 by Thomas Biege / SuSE Linux AG
    email                : thomas@suse.de
 ***************************************************************************/

/*

Description of error codes:
        ENODEV : auditing not available at all or disabled globally
        EUNATCH: failed because auditing not attached for this process
        EBUSY  : tried to attach an already-attached process
        EPERM  : insufficient privileges
        EACCES : action not permitted (overwriting session ID or login UID)
        EINVAL : simple low-level errors such as nonexistent IOCTL number
        ENOBUFS: out of memory
        EFAULT : error copying data from user space

*/

#ifndef __LAUS_HDR__
#define __LAUS_HDR__

#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <linux/laus_audit.h>
#include <laus_tags.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AUDIT_API_VERSION_OLD	0x20030801
#define LAUS_VERSION		0x20030807

#define PATH_FILTER_CONFIG	PATH_CONFIG_DIR "/filter.conf"

#define AUDIT_QLENCFG_PATH      "/proc/sys/dev/audit/max-messages"


/*
 * User space generated audit records
 */
enum {
        AUDIT_MSG_TEXT = AUDIT_MSG_USERBASE,
};


/*
 * File header of the audit log file
 */
struct laus_file_header {
	u_int32_t		h_version;
	u_int32_t		h_msgversion;
	u_int32_t		h_count;	/* 0 for stream files */
	char			h_hostname[256];
};

/*
 * Record headers used in the audit log file
 */
struct laus_record_header {
	time_t			r_time;
	size_t			r_size;

	/* Followed by kernel message */
};

/* Flags for laus_exec() */
#define LAUS_FLG_NONE		0x0000
#define LAUS_FLG_DETACH		0x0001		/* detach child-process */


/* ID Numbers for Audit-Session-ID to identify a Service */
#define LAUS_ASID_LOGIN		0x0001
#define LAUS_ASID_SSHD		0x0002
#define LAUS_ASID_FTPD		0x0003


/* Our public functions */
extern int		laus_init(void);
extern int		laus_open(const char *dev_file);
extern int		laus_api_version(void);
extern int		laus_registerauditdaemon(void);
extern pid_t		laus_exec(int flags, char *prog, ...);
extern int		laus_attach(void);
extern int		laus_detach(void);
extern int		laus_suspend(void);
extern int		laus_resume(void);
extern int		laus_setauditid(void);
extern int		laus_setsession(uid_t uid,
				const char *hostname,
				const char *hostaddr,
				const char *terminal);
extern int		laus_setauditdaemon(void);
extern int		laus_clrpolicy(void);
extern int		laus_setpolicy(int syscall, int policy, int filter);
extern int		laus_clrfilter(void);
extern int		laus_setfilter(struct audit_filter *filter);
extern int		laus_read(void *buffer, size_t size);
extern const char *	laus_strerror(int code);
extern int		laus_log(const char *audit_tag, const char *fmt, ...)
			__attribute__ ((format (printf, 2, 3)));
extern int		laus_textmessage(const char *);
extern int		laus_usermessage(int, const void *, size_t);
extern int		laus_version(void);
extern int		laus_reset(void);
extern int		laus_close(void);


#ifdef __cplusplus
}; // end of extern "C"
#endif

#endif

