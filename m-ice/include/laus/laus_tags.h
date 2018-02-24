/*
 * Declarations for applications using the Linux Auditing System
 * Copyright (C) SuSE Linux AG, 2003
 *
 */

#ifndef LAUS_TAGS_H
#define LAUS_TAGS_H

/*
** Audit Tags
*/
#define NO_TAG		NULL
#define AUDIT_start	"AUDIT_start"
#define AUDIT_stop	"AUDIT_stop"
#define AUDIT_disklow	"AUDIT_disklow"
#define AUDIT_diskfail	"AUDIT_diskfail"
#define AUDCONF_alter	"AUDCONF_alter"
#define AUDCONF_reload	"AUDCONF_reload"
#define AUTH_pwchange	"AUTH_pwchange"
#define AUTH_success	"AUTH_success"
#define AUTH_failure	"AUTH_failure"
#define FILE_mode	"FILE_mode"
#define FILE_owner	"FILE_owner"
#define FILE_chpriv	"FILE_chpriv"
#define FILE_fchmod	"FILE_fchmod"
#define FILE_fchown	"FILE_fchown"
#define FILE_link	"FILE_link"
#define FILE_mknod	"FILE_mknod"
#define FILE_open	"FILE_open"
#define FILE_create	"FILE_create"
#define FILE_rename	"FILE_rename"
#define FILE_truncate	"FILE_truncate"
#define FILE_unlink	"FILE_unlink"
#define FS_rmdir	"FS_rmdir"
#define FS_mount	"FS_mount"
#define FS_umount	"FS_umount"
#define MSG_owner	"MSG_owner"
#define MSG_mode	"MSG_mode"
#define MSG_delete	"MSG_delete"
#define MSG_create	"MSG_create"
#define SEM_owner	"SEM_owner"
#define SEM_create	"SEM_create"
#define SEM_delete	"SEM_delete"
#define SEM_mode	"SEM_mode"
#define SHM_create	"SHM_create"
#define SHM_delete	"SHM_delete"
#define SHM_owner	"SHM_owner"
#define SHM_mode	"SHM_mode"
#define PRIV_userchange	"PRIV_userchange"
#define PROC_execute	"PROC_execute"
#define PROC_realuid	"PROC_realuid"
#define PROC_auditid	"PROC_auditid"
#define PROC_setuserids "PROC_setuserids"
#define PROC_realgid	"PROC_realgid"
#define PROC_setgroups	"PROC_setgroups"
#define PROC_privilege	"PROC_privilege"
#define SYS_timechange	"SYS_timechange"
#define ADMIN_amtu	"ADMIN_amtu"

#endif /* LAUS_TAGS_H */
