#include <sys/times.h>
#include <unistd.h>

void 
delay(double ms)
{
	clock_t         start_time, akt_time;
	double          ticks;

	ticks = sysconf(_SC_CLK_TCK);

	akt_time = start_time = times(NULL);
	while ((akt_time - start_time) / ticks < ms)
		akt_time = times(NULL);
}
