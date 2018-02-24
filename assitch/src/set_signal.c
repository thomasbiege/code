#include <signal.h>
#include <unistd.h>

/*
** Set Signal Handler (reliable)
*/
int 
set_signal(int sig, void (*fkt_ptr) (int))
{
	struct sigaction sig_act;

	sig_act.sa_handler = fkt_ptr;
	sigemptyset(&sig_act.sa_mask);
	sig_act.sa_flags = 0;

#ifdef SA_INTERRUPT		/* Solaris */
	sig_act.sa_flags |= SA_INTERRUPT;	/* don't restart read()-call */
#endif

	return (sigaction(sig, &sig_act, NULL));
}
