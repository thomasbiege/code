/*
** slightly modified code used for the LAuS project
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <err.h>


static int  read_pidfile(const char *pathname);

int make_pidfile(const char *pathname, int force)
{
  char  pids[32], tempname[PATH_MAX+NAME_MAX+1] = {0}, *sp;
  int  fd, res;
  pid_t  pid;


  if(  !force
     && (pid = read_pidfile(pathname)) > 0
     && kill(pid, 0) < 0 && errno == ESRCH)
  {
    warnx("Removed stale lock '%s'", pathname);
    unlink(pathname);
  }

  if(strlen(pathname) + sizeof("fenceXXXXXX") > sizeof(tempname))
    return(-100);
  strcpy(tempname, pathname);
  if ((sp = strrchr(tempname, '/')) != 0) {
    sp += 1;
  } else {
    sp = tempname;
  }
  strcpy(sp, "fenceXXXXXX");

  if ((fd = mkstemp(tempname)) < 0)
    return(-101);

  fchmod(fd, 0644);

  sprintf(pids, "%u\n", getpid());
  write(fd, pids, strlen(pids));
  close(fd);

  if (force)
    res = rename(tempname, pathname);
  else
    res = link(tempname, pathname);

  if (res < 0)
    warnx("Failed to lock '%s': %m", pathname);
  unlink(tempname);
  return(res);
}

static int
read_pidfile(const char *pathname)
{
  char  buffer[32];
  int  n, fd, pid;

  if ((fd = open(pathname, O_RDONLY)) < 0)
    return -1;

  n = read(fd, buffer, sizeof(buffer)-1);
  close(fd);

  if (n > 0)
  {
    buffer[n] = '\0';
    pid = atoi(buffer);
    if (pid > 0)
      return pid;
  }

  return -1;
}
