#include <sys/types.h>
#include <sys/times.h>
#include <sys/time.h>
#include <stddef.h>

void 
delay(u_long ms)
{
	struct timeval  tv;

	if (!ms)
		return;

	tv.tv_sec = ms / 1000000L;
	tv.tv_usec = ms % 1000000L;
	select(0, NULL, NULL, NULL, &tv);
}
