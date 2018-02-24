/*
 * Handle system call names
 *
 * Copyright (C) 2003, SuSE Linux AG
 * Written by okir@suse.de
 * modified for LAuS by Thomas Biege
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_LIBLAUSSRV

#define _GNU_SOURCE

#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/resource.h>
#include <stropts.h>
#include <sched.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/route.h>

/* This is quite messy */
#ifdef HAVE_SYS_CAPABILITY_H
#include <sys/capability.h>
#else
#include <linux/capability.h>
/* Cleaning up for ppc */
#undef htonl
#undef ntohl
#undef htons
#undef ntohs
#endif

#include <laus.h>
#include <laussrv.h>
#include "syscall.h"

#include <asm/unistd.h>
#ifdef __powerpc64__
  typedef unsigned int u32;
  typedef signed int s32;
#endif
#if !defined(__ia64__)
  #include <asm/ipc.h>
#endif
#include <linux/sys.h>
#include <linux/net.h>

#ifndef offsetof
#define offsetof(t, m)  ((size_t) &(((t *) 0)->m))
#endif

typedef int    syscall_print_fn_t(int, const void *, size_t);

#define MAX_ARGS  8
struct syscall_info {
  const char *    name;
  syscall_print_fn_t  *arg[MAX_ARGS];
};


/*
 * System call table. This table does the mapping of
 * system call numbers to names and vice versa, and holds
 * additional information for pretty-printing arguments.
 *
 * We try to handle the __NR_socketcall and __NR_ipc
 * kludges transparently here.
 *
 * Note that NR_syscalls seems to be off in ia64 user space
 */
#if defined  (__ia64__)
#define __syscall_end  (1300+1)
#else
#define __syscall_end  (NR_syscalls + 1)
#endif

/*
 * Define bogus __NR_xxx values for socketcall and ipc
 */
enum {
  __extra_syscall_base = __syscall_end + 1,

  __socketcall_base,
#ifdef __NR_socketcall
  __NR_socket = __socketcall_base + SYS_SOCKET,
  __NR_bind = __socketcall_base + SYS_BIND,
  __NR_connect = __socketcall_base + SYS_CONNECT,
  __NR_listen = __socketcall_base + SYS_LISTEN,
  __NR_accept = __socketcall_base + SYS_ACCEPT,
  __NR_socketpair = __socketcall_base + SYS_SOCKETPAIR,
  __NR_setsockopt = __socketcall_base + SYS_SETSOCKOPT,
  __NR_getsockopt = __socketcall_base + SYS_GETSOCKOPT,
  __NR_getsockname = __socketcall_base + SYS_GETSOCKNAME,
  __NR_getpeername = __socketcall_base + SYS_GETPEERNAME,
  __NR_send = __socketcall_base + SYS_SEND,
  __NR_recv = __socketcall_base + SYS_RECV,
  __NR_sendto = __socketcall_base + SYS_SENDTO,
  __NR_recvfrom = __socketcall_base + SYS_RECVFROM,
  __NR_sendmsg = __socketcall_base + SYS_SENDMSG,
  __NR_recvmsg = __socketcall_base + SYS_RECVMSG,
  __socketcall_end = __socketcall_base + 32,
#else
  __socketcall_end = __socketcall_base,
#endif

  __ipccall_base,
#ifdef __NR_ipc
  __NR_semop  = __ipccall_base + SEMOP,
  __NR_semget  = __ipccall_base + SEMGET,
  __NR_semctl  = __ipccall_base + SEMCTL,
  __NR_msgsnd  = __ipccall_base + MSGSND,
  __NR_msgrcv  = __ipccall_base + MSGRCV,
  __NR_msgget  = __ipccall_base + MSGGET,
  __NR_msgctl  = __ipccall_base + MSGCTL,
  __NR_shmat  = __ipccall_base + SHMAT,
  __NR_shmdt  = __ipccall_base + SHMDT,
  __NR_shmget  = __ipccall_base + SHMGET,
  __NR_shmctl  = __ipccall_base + SHMCTL,
  __ipccall_end = __ipccall_base + 32,
#else
  __ipccall_end = __ipccall_base,
#endif

  __last_syscall
};

#define syscall(n, args...)  [__NR_##n] = { #n, { args } }

static struct syscall_info syscall_table[__last_syscall] = {
#ifdef __NR_exit
  syscall(exit),
#endif
#ifdef __NR_fork
  syscall(fork),
#endif
#ifdef __NR_read
  syscall(read),
#endif
#ifdef __NR_write
  syscall(write),
#endif
#ifdef __NR_open
  syscall(open, NULL, NULL, NULL),
#endif
#ifdef __NR_close
  syscall(close),
#endif
#ifdef __NR_waitpid
  syscall(waitpid),
#endif
#ifdef __NR_creat
  syscall(creat, NULL, NULL),
#endif
#ifdef __NR_link
  syscall(link),
#endif
#ifdef __NR_unlink
  syscall(unlink),
#endif
#ifdef __NR_execve
  syscall(execve),
#endif
#ifdef __NR_chdir
  syscall(chdir),
#endif
#ifdef __NR_time
  syscall(time),
#endif
#ifdef __NR_mknod
  syscall(mknod, NULL, NULL, NULL),
#endif
#ifdef __NR_chmod
  syscall(chmod, NULL, NULL),
#endif
#ifdef __NR_lchown
  syscall(lchown, NULL, NULL, NULL),
#endif
#ifdef __NR_break
  syscall(break),
#endif
#ifdef __NR_oldstat
  syscall(oldstat),
#endif
#ifdef __NR_lseek
  syscall(lseek),
#endif
#ifdef __NR_getpid
  syscall(getpid),
#endif
#ifdef __NR_mount
  syscall(mount),
#endif
#ifdef __NR_umount
  syscall(umount),
#endif
#ifdef __NR_setuid
  syscall(setuid),
#endif
#ifdef __NR_getuid
  syscall(getuid),
#endif
#ifdef __NR_stime
  syscall(stime, NULL),
#endif
#ifdef __NR_ptrace
  syscall(ptrace),
#endif
#ifdef __NR_alarm
  syscall(alarm),
#endif
#ifdef __NR_oldfstat
  syscall(oldfstat),
#endif
#ifdef __NR_pause
  syscall(pause),
#endif
#ifdef __NR_utime
  syscall(utime),
#endif
#ifdef __NR_stty
  syscall(stty),
#endif
#ifdef __NR_gtty
  syscall(gtty),
#endif
#ifdef __NR_access
  syscall(access),
#endif
#ifdef __NR_nice
  syscall(nice),
#endif
#ifdef __NR_ftime
  syscall(ftime),
#endif
#ifdef __NR_sync
  syscall(sync),
#endif
#ifdef __NR_kill
  syscall(kill, NULL, NULL),
#endif
#ifdef __NR_rename
  syscall(rename),
#endif
#ifdef __NR_mkdir
  syscall(mkdir, NULL, NULL),
#endif
#ifdef __NR_rmdir
  syscall(rmdir),
#endif
#ifdef __NR_dup
  syscall(dup),
#endif
#ifdef __NR_pipe
  syscall(pipe),
#endif
#ifdef __NR_times
  syscall(times),
#endif
#ifdef __NR_prof
  syscall(prof),
#endif
#ifdef __NR_brk
  syscall(brk),
#endif
#ifdef __NR_setgid
  syscall(setgid),
#endif
#ifdef __NR_getgid
  syscall(getgid),
#endif
#ifdef __NR_signal
  syscall(signal),
#endif
#ifdef __NR_geteuid
  syscall(geteuid),
#endif
#ifdef __NR_getegid
  syscall(getegid),
#endif
#ifdef __NR_acct
  syscall(acct),
#endif
#ifdef __NR_umount2
  syscall(umount2),
#endif
#ifdef __NR_lock
  syscall(lock),
#endif
#ifdef __NR_ioctl
  syscall(ioctl),
#endif
#ifdef __NR_fcntl
  syscall(fcntl),
#endif
#ifdef __NR_mpx
  syscall(mpx),
#endif
#ifdef __NR_setpgid
  syscall(setpgid),
#endif
#ifdef __NR_ulimit
  syscall(ulimit),
#endif
#ifdef __NR_oldolduname
  syscall(oldolduname),
#endif
#ifdef __NR_umask
  syscall(umask, NULL),
#endif
#ifdef __NR_chroot
  syscall(chroot),
#endif
#ifdef __NR_ustat
  syscall(ustat),
#endif
#ifdef __NR_dup2
  syscall(dup2),
#endif
#ifdef __NR_getppid
  syscall(getppid),
#endif
#ifdef __NR_getpgrp
  syscall(getpgrp),
#endif
#ifdef __NR_setsid
  syscall(setsid),
#endif
#ifdef __NR_sigaction
  syscall(sigaction),
#endif
#ifdef __NR_sgetmask
  syscall(sgetmask),
#endif
#ifdef __NR_ssetmask
  syscall(ssetmask),
#endif
#ifdef __NR_setreuid
  syscall(setreuid, NULL, NULL),
#endif
#ifdef __NR_setregid
  syscall(setregid, NULL, NULL),
#endif
#ifdef __NR_sigsuspend
  syscall(sigsuspend),
#endif
#ifdef __NR_sigpending
  syscall(sigpending),
#endif
#ifdef __NR_sethostname
  syscall(sethostname, NULL),
#endif
#ifdef __NR_setrlimit
  syscall(setrlimit, NULL, NULL),
#endif
#ifdef __NR_getrlimit
  syscall(getrlimit),
#endif
#ifdef __NR_getrusage
  syscall(getrusage),
#endif
#ifdef __NR_gettimeofday
  syscall(gettimeofday),
#endif
#ifdef __NR_settimeofday
  syscall(settimeofday, NULL, NULL),
#endif
#ifdef __NR_getgroups
  syscall(getgroups),
#endif
#ifdef __NR_setgroups
  syscall(setgroups, NULL, NULL),
#endif
#ifdef __NR_select
  syscall(select),
#endif
#ifdef __NR_symlink
  syscall(symlink),
#endif
#ifdef __NR_oldlstat
  syscall(oldlstat),
#endif
#ifdef __NR_readlink
  syscall(readlink),
#endif
#ifdef __NR_uselib
  syscall(uselib),
#endif
#ifdef __NR_swapon
  syscall(swapon),
#endif
#ifdef __NR_reboot
  syscall(reboot),
#endif
#ifdef __NR_readdir
  syscall(readdir),
#endif
#ifdef __NR_mmap
  syscall(mmap),
#endif
#ifdef __NR_munmap
  syscall(munmap),
#endif
#ifdef __NR_truncate
  syscall(truncate),
#endif
#ifdef __NR_ftruncate
  syscall(ftruncate),
#endif
#ifdef __NR_fchmod
  syscall(fchmod, NULL, NULL),
#endif
#ifdef __NR_fchown
  syscall(fchown, NULL, NULL, NULL),
#endif
#ifdef __NR_getpriority
  syscall(getpriority),
#endif
#ifdef __NR_setpriority
  syscall(setpriority),
#endif
#ifdef __NR_profil
  syscall(profil),
#endif
#ifdef __NR_statfs
  syscall(statfs),
#endif
#ifdef __NR_fstatfs
  syscall(fstatfs),
#endif
#ifdef __NR_ioperm
  syscall(ioperm, NULL),
#endif
#ifdef __NR_socketcall
  syscall(socketcall),
#endif
#ifdef __NR_syslog
  syscall(syslog),
#endif
#ifdef __NR_setitimer
  syscall(setitimer),
#endif
#ifdef __NR_getitimer
  syscall(getitimer),
#endif
#ifdef __NR_stat
  syscall(stat),
#endif
#ifdef __NR_lstat
  syscall(lstat),
#endif
#ifdef __NR_fstat
  syscall(fstat),
#endif
#ifdef __NR_olduname
  syscall(olduname),
#endif
#ifdef __NR_iopl
  syscall(iopl),
#endif
#ifdef __NR_vhangup
  syscall(vhangup),
#endif
#ifdef __NR_idle
  syscall(idle),
#endif
#ifdef __NR_vm86old
  syscall(vm86old),
#endif
#ifdef __NR_wait4
  syscall(wait4),
#endif
#ifdef __NR_swapoff
  syscall(swapoff),
#endif
#ifdef __NR_sysinfo
  syscall(sysinfo),
#endif
#ifdef __NR_ipc
  syscall(ipc),
#endif
#ifdef __NR_fsync
  syscall(fsync),
#endif
#ifdef __NR_sigreturn
  syscall(sigreturn),
#endif
#ifdef __NR_clone
  syscall(clone, NULL),
#endif
#ifdef __NR_setdomainname
  syscall(setdomainname, NULL),
#endif
#ifdef __NR_uname
  syscall(uname),
#endif
#ifdef __NR_modify_ldt
  syscall(modify_ldt),
#endif
#ifdef __NR_adjtimex
  syscall(adjtimex),
#endif
#ifdef __NR_mprotect
  syscall(mprotect),
#endif
#ifdef __NR_sigprocmask
  syscall(sigprocmask),
#endif
#ifdef __NR_create_module
  syscall(create_module),
#endif
#ifdef __NR_init_module
  syscall(init_module),
#endif
#ifdef __NR_delete_module
  syscall(delete_module),
#endif
#ifdef __NR_get_kernel_syms
  syscall(get_kernel_syms),
#endif
#ifdef __NR_quotactl
  syscall(quotactl),
#endif
#ifdef __NR_getpgid
  syscall(getpgid),
#endif
#ifdef __NR_fchdir
  syscall(fchdir),
#endif
#ifdef __NR_bdflush
  syscall(bdflush),
#endif
#ifdef __NR_sysfs
  syscall(sysfs),
#endif
#ifdef __NR_personality
  syscall(personality),
#endif
#ifdef __NR_afs_syscall
  syscall(afs_syscall),
#endif
#ifdef __NR_setfsuid
  syscall(setfsuid),
#endif
#ifdef __NR_setfsgid
  syscall(setfsgid),
#endif
#ifdef __NR__llseek
  syscall(_llseek),
#endif
#ifdef __NR_getdents
  syscall(getdents),
#endif
#ifdef __NR__newselect
  syscall(_newselect),
#endif
#ifdef __NR_flock
  syscall(flock),
#endif
#ifdef __NR_msync
  syscall(msync),
#endif
#ifdef __NR_readv
  syscall(readv),
#endif
#ifdef __NR_writev
  syscall(writev),
#endif
#ifdef __NR_getsid
  syscall(getsid),
#endif
#ifdef __NR_fdatasync
  syscall(fdatasync),
#endif
#ifdef __NR__sysctl
  syscall(_sysctl),
#endif
#ifdef __NR_mlock
  syscall(mlock),
#endif
#ifdef __NR_munlock
  syscall(munlock),
#endif
#ifdef __NR_mlockall
  syscall(mlockall),
#endif
#ifdef __NR_munlockall
  syscall(munlockall),
#endif
#ifdef __NR_sched_setparam
  syscall(sched_setparam),
#endif
#ifdef __NR_sched_getparam
  syscall(sched_getparam),
#endif
#ifdef __NR_sched_setscheduler
  syscall(sched_setscheduler),
#endif
#ifdef __NR_sched_getscheduler
  syscall(sched_getscheduler),
#endif
#ifdef __NR_sched_yield
  syscall(sched_yield),
#endif
#ifdef __NR_sched_get_priority_max
  syscall(sched_get_priority_max),
#endif
#ifdef __NR_sched_get_priority_min
  syscall(sched_get_priority_min),
#endif
#ifdef __NR_sched_rr_get_interval
  syscall(sched_rr_get_interval),
#endif
#ifdef __NR_nanosleep
  syscall(nanosleep),
#endif
#ifdef __NR_mremap
  syscall(mremap),
#endif
#ifdef __NR_setresuid
  syscall(setresuid, NULL, NULL, NULL),
#endif
#ifdef __NR_getresuid
  syscall(getresuid),
#endif
#ifdef __NR_vm86
  syscall(vm86),
#endif
#ifdef __NR_query_module
  syscall(query_module),
#endif
#ifdef __NR_poll
  syscall(poll),
#endif
#ifdef __NR_nfsservctl
  syscall(nfsservctl),
#endif
#ifdef __NR_setresgid
  syscall(setresgid, NULL, NULL, NULL),
#endif
#ifdef __NR_getresgid
  syscall(getresgid),
#endif
#ifdef __NR_prctl
  syscall(prctl),
#endif
#ifdef __NR_rt_sigreturn
  syscall(rt_sigreturn),
#endif
#ifdef __NR_rt_sigaction
  syscall(rt_sigaction),
#endif
#ifdef __NR_rt_sigprocmask
  syscall(rt_sigprocmask),
#endif
#ifdef __NR_rt_sigpending
  syscall(rt_sigpending),
#endif
#ifdef __NR_rt_sigtimedwait
  syscall(rt_sigtimedwait),
#endif
#ifdef __NR_rt_sigqueueinfo
  syscall(rt_sigqueueinfo),
#endif
#ifdef __NR_rt_sigsuspend
  syscall(rt_sigsuspend),
#endif
#ifdef __NR_pread
  syscall(pread),
#endif
#ifdef __NR_pwrite
  syscall(pwrite),
#endif
#ifdef __NR_chown
  syscall(chown, NULL, NULL, NULL),
#endif
#ifdef __NR_getcwd
  syscall(getcwd),
#endif
#ifdef __NR_capget
  syscall(capget),
#endif
#ifdef __NR_capset
  syscall(capset, NULL, NULL),
#endif
#ifdef __NR_sigaltstack
  syscall(sigaltstack),
#endif
#ifdef __NR_sendfile
  syscall(sendfile, NULL, NULL, NULL),
#endif
#ifdef __NR_getpmsg
  syscall(getpmsg),
#endif
#ifdef __NR_putpmsg
  syscall(putpmsg),
#endif
#ifdef __NR_vfork
  syscall(vfork),
#endif
#ifdef __NR_ugetrlimit
  syscall(ugetrlimit),
#endif
#ifdef __NR_mmap2
  syscall(mmap2),
#endif
#ifdef __NR_truncate64
  syscall(truncate64),
#endif
#ifdef __NR_ftruncate64
  syscall(ftruncate64),
#endif
#ifdef __NR_stat64
  syscall(stat64),
#endif
#ifdef __NR_lstat64
  syscall(lstat64),
#endif
#ifdef __NR_fstat64
  syscall(fstat64),
#endif
#ifdef __NR_pciconfig_read
  syscall(pciconfig_read),
#endif
#ifdef __NR_pciconfig_write
  syscall(pciconfig_write),
#endif
#ifdef __NR_pciconfig_iobase
  syscall(pciconfig_iobase),
#endif
#ifdef __NR_multiplexer
  syscall(multiplexer),
#endif
#ifdef __NR_lchown32
  syscall(lchown32, NULL, NULL, NULL),
#endif
#ifdef __NR_getuid32
  syscall(getuid32),
#endif
#ifdef __NR_getgid32
  syscall(getgid32),
#endif
#ifdef __NR_geteuid32
  syscall(geteuid32),
#endif
#ifdef __NR_getegid32
  syscall(getegid32),
#endif
#ifdef __NR_setreuid32
  syscall(setreuid32, NULL, NULL),
#endif
#ifdef __NR_setregid32
  syscall(setregid32, NULL, NULL),
#endif
#ifdef __NR_getgroups32
  syscall(getgroups32),
#endif
#ifdef __NR_setgroups32
  syscall(setgroups32, NULL, NULL),
#endif
#ifdef __NR_fchown32
  syscall(fchown32, NULL, NULL, NULL),
#endif
#ifdef __NR_setresuid32
  syscall(setresuid32, NULL, NULL, NULL),
#endif
#ifdef __NR_getresuid32
  syscall(getresuid32),
#endif
#ifdef __NR_setresgid32
  syscall(setresgid32, NULL, NULL, NULL),
#endif
#ifdef __NR_getresgid32
  syscall(getresgid32),
#endif
#ifdef __NR_chown32
  syscall(chown32, NULL, NULL, NULL),
#endif
#ifdef __NR_setuid32
  syscall(setuid32),
#endif
#ifdef __NR_setgid32
  syscall(setgid32),
#endif
#ifdef __NR_setfsuid32
  syscall(setfsuid32),
#endif
#ifdef __NR_setfsgid32
  syscall(setfsgid32),
#endif
#ifdef __NR_pivot_root
  syscall(pivot_root),
#endif
#ifdef __NR_mincore
  syscall(mincore),
#endif
#ifdef __NR_madvise
  syscall(madvise),
#endif
#ifdef __NR_madvise1
  syscall(madvise1),
#endif
#ifdef __NR_getdents64
  syscall(getdents64),
#endif
#ifdef __NR_fcntl64
  syscall(fcntl64),
#endif
#ifdef __NR_security
  syscall(security),
#endif
#ifdef __NR_tuxcall
  syscall(tuxcall),
#endif
#ifdef __NR_io_setup
  syscall(io_setup),
#endif
#ifdef __NR_io_destroy
  syscall(io_destroy),
#endif
#ifdef __NR_io_getevents
  syscall(io_getevents),
#endif
#ifdef __NR_io_submit
  syscall(io_submit),
#endif
#ifdef __NR_io_cancel
  syscall(io_cancel),
#endif
#ifdef __NR_set_tid_address
  syscall(set_tid_address),
#endif
#ifdef __NR_fadvise64
  syscall(fadvise64),
#endif
#ifdef __NR_exit_group
  syscall(exit_group),
#endif
#ifdef __NR_lookup_dcookie
  syscall(lookup_dcookie),
#endif
#ifdef __NR_epoll_create
  syscall(epoll_create),
#endif
#ifdef __NR_epoll_ctl
  syscall(epoll_ctl),
#endif
#ifdef __NR_epoll_wait
  syscall(epoll_wait),
#endif
/* Some platforms have __NR_sys_epoll_* instead of __NR_epoll_* */
#ifdef __NR_sys_epoll_create
  syscall(sys_epoll_create),
#endif
#ifdef __NR_sys_epoll_ctl
  syscall(sys_epoll_ctl),
#endif
#ifdef __NR_sys_epoll_wait
  syscall(sys_epoll_wait),
#endif
#ifdef __NR_remap_file_pages
  syscall(remap_file_pages),
#endif
#ifdef __NR_timer_create
  syscall(timer_create),
#endif
#ifdef __NR_timer_settime
  syscall(timer_settime),
#endif
#ifdef __NR_timer_gettime
  syscall(timer_gettime),
#endif
#ifdef __NR_timer_getoverrun
  syscall(timer_getoverrun),
#endif
#ifdef __NR_timer_delete
  syscall(timer_delete),
#endif
#ifdef __NR_clock_settime
  syscall(clock_settime),
#endif
#ifdef __NR_clock_gettime
  syscall(clock_gettime),
#endif
#ifdef __NR_clock_getres
  syscall(clock_getres),
#endif
#ifdef __NR_clock_nanosleep
  syscall(clock_nanosleep),
#endif
#ifdef __NR_swapcontext
  syscall(swapcontext),
#endif
#ifdef __NR_tgkill
  syscall(tgkill),
#endif
#ifdef __NR_utimes
  syscall(utimes),
#endif
#ifdef __NR_statfs64
  syscall(statfs64),
#endif
#ifdef __NR_fstatfs64
  syscall(fstatfs64),
#endif
#ifdef __NR_gettid
  syscall(gettid),
#endif
#ifdef __NR_readahead
  syscall(readahead),
#endif
#ifdef __NR_setxattr
  syscall(setxattr, NULL, NULL, NULL),
#endif
#ifdef __NR_lsetxattr
  syscall(lsetxattr),
#endif
#ifdef __NR_fsetxattr
  syscall(fsetxattr, NULL, NULL, NULL),
#endif
#ifdef __NR_getxattr
  syscall(getxattr),
#endif
#ifdef __NR_lgetxattr
  syscall(lgetxattr),
#endif
#ifdef __NR_fgetxattr
  syscall(fgetxattr),
#endif
#ifdef __NR_listxattr
  syscall(listxattr),
#endif
#ifdef __NR_llistxattr
  syscall(llistxattr),
#endif
#ifdef __NR_flistxattr
  syscall(flistxattr),
#endif
#ifdef __NR_removexattr
  syscall(removexattr),
#endif
#ifdef __NR_lremovexattr
  syscall(lremovexattr),
#endif
#ifdef __NR_fremovexattr
  syscall(fremovexattr),
#endif
#ifdef __NR_tkill
  syscall(tkill),
#endif
#ifdef __NR_sendfile64
  syscall(sendfile64),
#endif
#ifdef __NR_futex
  syscall(futex),
#endif
#ifdef __NR_sched_setaffinity
  syscall(sched_setaffinity),
#endif
#ifdef __NR_sched_getaffinity
  syscall(sched_getaffinity),
#endif
#ifdef __NR_set_thread_area
  syscall(set_thread_area),
#endif
#ifdef __NR_get_thread_area
  syscall(get_thread_area),
#endif
#ifdef __NR_alloc_hugepages
  syscall(alloc_hugepages),
#endif
#ifdef __NR_free_hugepages
  syscall(free_hugepages),
#endif

/*
 * Socket calls
 */
syscall(socket, NULL, NULL),
syscall(bind, NULL, NULL),
syscall(connect, NULL, NULL),
syscall(listen),
syscall(accept),
syscall(socketpair, NULL),
syscall(setsockopt),
syscall(getsockopt),
syscall(getsockname),
syscall(getpeername),
#ifdef __NR_send
syscall(send),
#endif
#ifdef __NR_recv
syscall(recv),
#endif
syscall(sendto),
syscall(recvfrom),
syscall(sendmsg),
syscall(recvmsg),

/*
 * SysV IPC calls
 */
syscall(semop),
syscall(semget, NULL),
syscall(semctl, NULL, NULL, NULL /* cmd */),
syscall(msgsnd, NULL, NULL, NULL, NULL),
syscall(msgrcv, NULL, NULL, NULL, NULL, NULL),
syscall(msgget, NULL, NULL /* flags */ ),
syscall(msgctl, NULL, NULL, NULL /* msgqid_ds */),
syscall(shmat, NULL),
syscall(shmdt, NULL),
syscall(shmget, NULL),
syscall(shmctl, NULL),
};

/*
 * Handle system call/code translations
 */
static __inline__ const char *
__code_to_name(unsigned int code, unsigned int low, unsigned int high)
{
  code += low;
  return (code < high)? syscall_table[code].name : NULL;
}

static __inline__ int
__name_to_code(const char *name, unsigned int low, unsigned int high)
{
  unsigned int  n;

  for (n = low; n < high; n++) {
    if (syscall_table[n].name
     && !strcmp(syscall_table[n].name, name))
      return n - low;
  }
  return -1;
}

unsigned int
syscall_max(void)
{
  return __syscall_end;
}

const char *
syscall_code_to_name(unsigned int code)
{
  return __code_to_name(code, 0, __syscall_end);
}

int
syscall_name_to_code(const char *name)
{
  return __name_to_code(name, 0, __syscall_end);
}

unsigned int
socketcall_max(void)
{
  return __socketcall_end - __socketcall_base;
}

const char *
socketcall_code_to_name(unsigned int code)
{
  return __code_to_name(code, __socketcall_base, __socketcall_end);
}

int
socketcall_name_to_code(const char *name)
{
  return __name_to_code(name, __socketcall_base, __socketcall_end);
}

unsigned int
ipccall_max(void)
{
  return __ipccall_end - __ipccall_base;
}

const char *
ipccall_code_to_name(unsigned int code)
{
  return __code_to_name(code, __ipccall_base, __ipccall_end);
}

int
ipccall_name_to_code(const char *name)
{
  return __name_to_code(name, __ipccall_base, __ipccall_end);
}

/*
 * Print various types of system call arguments
 */
static const void *get_value(const void *p, size_t len, u_int64_t *res)
{
  const unsigned char  *addr;

  addr = (const unsigned char *) p;
  if (len == 1) {
    *res = *addr;
  } else if (len == 2) {
    u_int16_t tmp;

    memcpy(&tmp, addr, 2);
    *res = tmp;
  } else if (len == 4) {
    u_int32_t tmp;

    memcpy(&tmp, addr, 4);
    *res = tmp;
  } else if (len == 8) {
    u_int64_t tmp;

    memcpy(&tmp, addr, 8);
    *res = tmp;
  }

  return addr + len;
}

static int get_immediate(int type, const void *p, size_t len, u_int64_t *res)
{
  if (type != AUDIT_ARG_IMMEDIATE)
    return -1;

  get_value(p, len, res);
  return 0;
}

void get_result(long result, struct laus_scall_result *res)
{
  res->type  = SCRESULTTYPE_NUL;
  res->value = 0;
  
  if(result < -1024)
  {
    /* looks like an address */
    res->type  = SCRESULTTYPE_PTR;
    res->value = result;
  }
  else if(result < 0)
  {
    res->type  = SCRESULTTYPE_ERR;
    res->value = result;
  }
  else
  {
    res->type  = SCRESULTTYPE_INT;
    res->value = result;
  }
}

struct syscall_info * syscall_get_name(unsigned int major, unsigned int minor, char *name, size_t name_len)
{
  struct syscall_info   *info = NULL;
  unsigned int          num = major;

  
#ifdef __NR_socketcall
  if (major == __NR_socketcall)
  {
    num = __socketcall_base + minor;
    if (num >= __socketcall_end)
    {
      snprintf(name, name_len, "socketcall", minor);
      return NULL;
    }
  } else
#endif
#ifdef __NR_ipc
  if (major == __NR_ipc)
  {
    num = __ipccall_base + minor;
    if (num >= __ipccall_end)
    {
      snprintf(name, name_len, "ipc", minor);
      return NULL;
    }
  } else
#endif
  if (num >= __syscall_end)
    num = __last_syscall;

  if (num < __last_syscall && syscall_table[num].name)
  {
    info = &syscall_table[num];
    snprintf(name, name_len, "%s", info->name);
  }
  else
  {
    snprintf(name, name_len, "UNKNOWN");
  }

  return(info);
}


int syscall_get(struct syscall_data *sc, struct laus_scall *scall)
{
  struct syscall_info *info;
  char                name[256] = {0};
  size_t              name_len = sizeof(name);


  if(sc == NULL || scall == NULL)
    return(-1);
      
  /* get the syscall name */
  info = syscall_get_name(sc->major, sc->minor, name, name_len);

  scall->name   = strdup(name);
  scall->major  = sc->major;
  scall->minor  = sc->minor;
  scall->nargs  = sc->nargs;
  
  /* we are not interessted in the arguments right now... */

  /* ... but in the return value */
  switch (sc->major)
  {
    case __NR_exit:
      scall->result.value = -666L;
      break;
    case __NR_execve:
      if (sc->result == 0)
        scall->result.value = -666L;
      break;
    default:
      get_result(sc->result, &(scall->result));
  }

  return(0);
}
#endif
