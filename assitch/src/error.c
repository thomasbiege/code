#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include "error.h"

int             _debug;

/* --- local funktions --- */
static void 
err_message(int sys_mesg, const char *fmt, va_list az)
{
	int             error_no = errno;
	char            puffer[MAX_CHARS];

	vsprintf(puffer, fmt, az);
	if (sys_mesg)
		sprintf(puffer + strlen(puffer), ": %s ", strerror(error_no));

	fflush(stdout);
	fprintf(stderr, "%s\n", puffer);
	fflush(NULL);		/* flush all O-Buffers */

	return;
}

static void 
log_message(int sys_mesg, int prio, const char *fmt, va_list az)
{
	int             error_no = errno;
	char            puffer[MAX_CHARS];

	vsprintf(puffer, fmt, az);
	if (sys_mesg)
		sprintf(puffer + strlen(puffer), ": %s ", strerror(error_no));

	if (_debug)
	{
		fflush(stdout);
		fprintf(stderr, "%s\n", puffer);
		fflush(NULL);
	}
	else
	{
		strcat(puffer, "\n");
		syslog(prio, puffer);
	}

	return;
}


/* --- global funktions --- */
void 
err_mesg(int iID, const char *ccFmt,...)
{
	va_list         az;

	va_start(az, ccFmt);
	switch (iID)
	{
	case WARN:
	case FATAL:
		err_message(0, ccFmt, az);
		break;
	case WARN_SYS:
	case FATAL_SYS:
		err_message(1, ccFmt, az);
		break;
	default:
		exit(3);
	}
	va_end(az);

	if (iID == WARN || iID == WARN_SYS)
		return;
	if (iID == DUMP)
		abort();

	exit(1);
}

void 
log_mesg(int iID, const char *ccFmt,...)
{
	va_list         az;

	va_start(az, ccFmt);
	switch (iID)
	{
	case WARN:
	case FATAL:
		log_message(0, LOG_ERR, ccFmt, az);
		break;
	case WARN_SYS:
	case FATAL_SYS:
		log_message(1, LOG_ERR, ccFmt, az);
		break;
	default:
		log_message(1, LOG_ERR, "Incorrect parameters for 'log_mesg()' ...", az);
		exit(3);
	}
	va_end(az);

	if (iID == WARN || iID == WARN_SYS)
		return;

	exit(2);
}

/* --- init syslog() --- */
void 
log_open(const char *ccID, int iOption, int iFacility)
{
	if (_debug == 0)
		openlog(ccID, iOption, iFacility);
}
