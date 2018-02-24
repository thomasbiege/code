/***************************************************************************
                          libsecprog.c  -  description
                             -------------------
    begin                : Thu Jan 6 2000
    autho                : (C) 2000 by Thomas Biege
    email                : thomas@uin4d.de
 ***************************************************************************/

#include "secprog.h"

#define ST2CPPST  \
do{ \
  stptr->st_dev     = stbuf.st_dev; \
  stptr->st_ino     = stbuf.st_ino; \
  stptr->st_mode    = stbuf.st_mode; \
  stptr->st_nlink   = stbuf.st_nlink; \
  stptr->st_uid     = stbuf.st_uid; \
  stptr->st_gid     = stbuf.st_gid; \
  stptr->st_rdev    = stbuf.st_rdev; \
  stptr->st_size    = stbuf.st_size; \
  stptr->st_blksize = stbuf.st_blksize; \
  stptr->st_blocks  = stbuf.st_blocks; \
  stptr->st_atime   = stbuf.st_atime; \
  stptr->st_mtime   = stbuf.st_mtime; \
  stptr->st_ctime   = stbuf.st_ctime; \
}while(0);

u_int se_closefds = TRUE;


//-----------------------------------------------------------------------------

extern int setlimits(sl_limit slim)
{
  struct rlimit rst;

  rst.rlim_cur = 0;

  rst.rlim_max = slim.fsize;
  if(setrlimit(RLIMIT_FSIZE, &rst) < 0)
    return(-1);

  rst.rlim_max = slim.data;
  if(setrlimit(RLIMIT_DATA, &rst) < 0)
    return(-1);

  rst.rlim_max = slim.stack;
  if(setrlimit(RLIMIT_STACK, &rst) < 0)
    return(-1);

  rst.rlim_max = slim.core;
  if(setrlimit(RLIMIT_CORE, &rst) < 0)
    return(-1);

  rst.rlim_max = slim.rss;
  if(setrlimit(RLIMIT_RSS, &rst) < 0)
    return(-1);

  rst.rlim_max = slim.nofile;
  if(setrlimit(RLIMIT_NOFILE, &rst) < 0)
    return(-1);

  rst.rlim_max = slim.nproc;
  if(setrlimit(RLIMIT_NPROC, &rst) < 0)
    return(-1);

  rst.rlim_max = slim.memlock;
  if(setrlimit(RLIMIT_MEMLOCK, &rst) < 0)
    return(-1);

  return(0);
}


//-----------------------------------------------------------------------------

extern int close_stdfds(void)
{
  int fd = 0;

  while(fd < 2)
  {
    if( (fd = open("/dev/null", 0600)) < 0)
      return(-1);
  }
  return(0);
}


//-------------------------------------------------------------------------------


extern char *s_strncpy(char *dest, char *src, size_t n)
{
  char *s;

  if(strlen(src) < n)
	{
#ifdef SS_DEBUG
		syslog(LOG_USER|LOG_INFO, "SECSTRNCPY: size n bigger then strlen(src)\n");
#endif
    return(NULL);
	}

  s = strncpy(dest, src, n);
  dest[n-1] = '\0';

// noch besser: strlcpy und strlcat von openbsd zu uebernehmen

  return(s);
}

extern char *s_strncat(char *dest, char *src, size_t n)
{
  char *s;

  if(strlen(src) < n)
	{
#ifdef SS_DEBUG
		syslog(LOG_USER|LOG_INFO, "SECSTRNCPY: size n bigger then strlen(src)\n");
#endif
    return(NULL);
	}

  s = strncat(dest, src, n-1);

  return(s);
}


//-----------------------------------------------------------------------

/*
 *  I don't use mkstemp(3) because it doesn't apply to the POSIX standard
 */

extern int safe_tmpfile(char *filename)
{
  char  *fn;
  int   fd;


  if( (fn = tmpnam(filename)) == NULL)
	{
#ifdef ST_DEBUG
		syslog(LOG_USER|LOG_INFO, "safe_tmpfile: tmpnam() returns NULL\n");
#endif
    return(-1);
	}

  if((fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600)) == -1)
    return(-2);

  if(unlink(fn) == -1)
  {
    close(fd);
    return(-3);
  }

  return(fd);
}

extern FILE *s_tmpfile(void)
{
  int fd;

  if( (fd = safe_tmpfile(NULL)) < 0)
    return(NULL);

  return(fdopen(fd, "w+b"));
}


//--------------------------------------------------------------------------

/*
** use sigprotection() to block signals while processing
** security critical code sequences
*/

extern int sigprotection(u_int toggle, sigset_t *sp_blockmask)
{
	static sigset_t sp_savedmask;
	static u_int    sp_status = SP_OFF;

  switch(toggle)
  {
    case SP_ON:
      if(sp_status != SP_ON)
      {
        if(sp_blockmask == NULL)
          return(-1);

        sp_status = SP_ON;
        if(sigprocmask(SIG_BLOCK, sp_blockmask, &sp_savedmask) < 0)
          return(-1);
      }
      break;
    case SP_OFF:
      if(sp_status != SP_OFF)
      {
        sp_status = SP_OFF;
        if(sigprocmask(SIG_SETMASK, &sp_savedmask, NULL) < 0)
          return(-1);
      }
      break;
    default:
      return(-1);
  }

  return(0);
}


//---------------------------------------------------------------------------

/*
** provided by Marc Heuse <marc@suse.de>
*/

extern int safe_reopen (char *file, int mode)
{
  struct stat st;
  struct stat st2;
  int fd;

  if (lstat(file, &st) < 0)
  { // does not exit -> safe creation
    if ((fd = open(file, mode | O_EXCL | O_CREAT, 0600)) < 0)
      return(-1);
  }
  else
  { // it exists - allow only regular file which are not hardlinked
    if ((! S_ISREG(st.st_mode)) || st.st_nlink != 1)
      return(-1); // OK, lets open
    if ((fd = open(file, mode | O_NOFOLLOW)) < 0)
      return(-1);
    fstat(fd, &st2); // recheck that it's the same file ...
    if (st2.st_dev != st.st_dev || st2.st_ino != st.st_ino || st2.st_uid != st.st_uid || st2.st_nlink != 1)
    {
      close(fd);
      return(-1);
    }
  }

  return(fd);
}


//-------------------------------------------------------------------------------

extern int s_execv(const char *filename, char *const argv[])
{
  char *username, *cwd;
  size_t size = 0;
  long oldval = 0L;
  struct passwd *pwent;
  int i;
#ifdef OPEN_MAX
  static long maxopenfd = OPEN_MAX;
#else
  static long maxopenfd = 0L;
#endif
#define OPEN_MAX_LINUX 1024L  // Linux
	enum
	{
		PATH    = 0,
		IFS     = 1,
		USER    = 2,
		LOGNAME = 3,
		HOME    = 4,
		PWD     = 5,
		SHELL   = 6,
		TERM    = 7,
		TMPDIR  = 8,
		EOA  		= 9,
	};
	char *safeenv[ENVENTLEN+1] =
  {
    "PATH=/bin:/sbin:/usr/bin:/usr/sbin",
    "IFS= \t\n",
    "USER=",
    "LOGNAME=",
    "HOME=",
    "PWD=",
    "SHELL=",
    "TERM=",
    "TMPDIR=/tmp",
		"\0"
  };

	
	if((username = getlogin()) == NULL)
	{
#ifdef SE_DEBUG
		syslog(LOG_USER|LOG_INFO, "SE: getlogin() returns NULL\n");
#endif
		return(-1);
	}

	if((pwent = getpwuid(getuid())) == NULL)
	{
#ifdef SE_DEBUG
		syslog(LOG_USER|LOG_INFO, "SE: getpwuid() returns NULL\n");
#endif
		return(-1);
	}

	if(strcmp(username, pwent->pw_name))
	{
#ifdef SE_DEBUG
		syslog(LOG_USER|LOG_INFO, "SE: Username associated with controlling "
                              "terminal differs from Username associated "
															"with real UID. Maybe the SUID process called "
															"setuid(SUID).\n");
#endif
		return(-1);
	}

  if((cwd = getcwd(NULL, size)) == NULL)
  {
#ifdef SE_DEBUG
    syslog(LOG_USER|LOG_INFO, "SE: getwd() returns NULL. Maybe CWD isn't readable.\n");
#endif
    return(-1);
  }

  /*
  ** prepare the environment for the exec() call
  */
  s_strncpy(safeenv[USER],    pwent->pw_name,  ENVENTLEN);
  s_strncpy(safeenv[LOGNAME], pwent->pw_name,  ENVENTLEN);
  s_strncpy(safeenv[HOME],    pwent->pw_dir,   ENVENTLEN);
  s_strncpy(safeenv[PWD],			cwd,              ENVENTLEN);
  free(cwd);
  s_strncpy(safeenv[SHELL],   pwent->pw_shell,  ENVENTLEN);
  s_strncpy(safeenv[TERM],    ctermid(NULL),    ENVENTLEN);
  s_strncpy(safeenv[TMPDIR],  "/tmp",           ENVENTLEN);
	
  // sets close_on_exec on all FDs except stdin, stdout and stderr
	if(se_closefds)
  {
    if(maxopenfd == 0)
      if((maxopenfd = sysconf(_SC_OPEN_MAX)) < 0)
        maxopenfd = OPEN_MAX_LINUX;   // I don't care about errno here

    for (i = 3; i <= maxopenfd; i++)
    {
      oldval = fcntl(i , F_GETFD, 0L);
      (void) fcntl(i, F_SETFD, (oldval != -1) ? (oldval |= FD_CLOEXEC) : FD_CLOEXEC);
    }
	}
	return(execve(filename, argv, safeenv));
}


//----------------------------------------------------------------------------------

extern int setupsbitproc(void)
{
  sl_limit slst = {0};

  se_closefds = TRUE;
  if(close_stdfds() < 0)
    return(-1);

  slst.core = 0;
  if(setlimits(slst) < 0)
    return(-1);

  return(0);
}

//----------------------------------------------------------------------------------

/*
** This is a secure but NOT 100% compatible replacement for popen()
** Note:        - don't use pclose() use fclose() for closing the returned
**                filedesc.!!!
**
** Known Bugs:  - doesn't work on Solaris
** Credits:     - Andreas Pfaller <a.pfaller@pop.gun.de> for fixing a SEGV when
**                calling strtok()
*/

#define __SEC_POPEN_TOKEN " "

extern FILE *s_popen(char *cmd, const char *type)
{
  pid_t pid;
  int pfd[2];
  int rpipe = 0, wpipe = 0, i;
  char **argv;
  char *ptr;
  char *cmdcpy;


  if(cmd == NULL || cmd == "")
    return(NULL);

  if(strcmp(type, "r") && strcmp(type, "w"))
    return(NULL);

  if ((cmdcpy = strdup(cmd)) == NULL)
    return(NULL);

  argv = NULL;
  if( (ptr = strtok(cmd, __SEC_POPEN_TOKEN)) == NULL)
  {
    free(cmdcpy);
    return(NULL);
  }

  for(i = 0;; i++)
  {
    if( ( argv = (char **) realloc(argv, (i+1) * sizeof(char *)) ) == NULL)
    {
      free(cmdcpy);
      return(NULL);
    }

    if( (*(argv+i) = (char *) malloc((strlen(ptr)+1) * sizeof(char))) == NULL)
    {
      free(cmdcpy);
      return(NULL);
    }

    strcpy(argv[i], ptr);

    if( (ptr = strtok(NULL, __SEC_POPEN_TOKEN)) == NULL)
    {
      if( ( argv = (char **) realloc(argv, (i+2) * sizeof(char *))) == NULL)
      {
        free(cmdcpy);
        return(NULL);
      }
      argv[i+1] = NULL;
      break;
    }
  }


  if(type[0] == 'r')
    rpipe = 1;
  else
    wpipe = 1;

  if (pipe(pfd) < 0)
  {
    free(cmdcpy);
    return(NULL);
  }

	if((pid = fork()) < 0)
  {
    close(pfd[0]);
    close(pfd[1]);
    free(cmdcpy);
    return(NULL);
  }

	if(pid == 0)    // child
  {
    if((pid = fork()) < 0)
    {
      close(pfd[0]);
      close(pfd[1]);
      free(cmdcpy);
      return(NULL);
    }
    if(pid > 0)
    {
      exit(0);  // child nr. 1 exits
    }

    // child nr. 2
    if(rpipe)
    {
      close(pfd[0]);  // close reading end, we don't need it
      if (pfd[1] != STDOUT_FILENO)
        dup2(pfd[1], STDOUT_FILENO);  // redirect stdout to writing end of pipe
	    dup2(STDOUT_FILENO, STDERR_FILENO);
	  }
    else
    {
      close(pfd[1]);  // close writing end, we don't need it
      if (pfd[0] != STDIN_FILENO)
        dup2(pfd[0], STDOUT_FILENO);    // redirect stdin to reading end of pipe
	  }

    if(strchr(argv[0], '/') == NULL)
      execvp(argv[0], argv);  // search in $PATH
    else
      execv(argv[0], argv);

    close(pfd[0]);
    close(pfd[1]);
    free(cmdcpy);
    return(NULL);  // exec failed.. ooops!
  }
  else          // parent
  {
    waitpid(pid, NULL, 0); // wait for child nr. 1

    if(rpipe)
    {
      close(pfd[1]);
      free(cmdcpy);
      return(fdopen(pfd[0], "r"));
    }
    else
    {
      close(pfd[0]);
      free(cmdcpy);
      return(fdopen(pfd[1], "r"));
    }

  }
}
