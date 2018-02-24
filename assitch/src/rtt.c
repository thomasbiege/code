/*
** Timer routines for round-trip timing of datagrams.
**
**    rtt_init()      Called to init everything for a given "connection".
**    rtt_newpack()   Called before each new packet is transmitted on a
**                    "connection". Init.s retransmit counter to 0.
**    rtt_start()     Called before each packet either transmitted or
**                    retransmitted. Calculates the timeout value for the
**                    packet and starts the timer to calculate the RTT.
**    rtt_stop()      Called after a packet has been received.
**    rtt_timeout()   Called after a timeout has occurred. Tells you
**                    if you should retransmit again, or give up.
**
** The difference between rtt_init() and rtt_newpack() is that the former
** knows nothing about the "connection", while the latter makes use of
** previous RTT information for a given "connection".
*/

#include <sys/types.h>
#include <rtt.h>
#include <error.h>

int             exp_backoff[RTT_MAXNREXMT + 1] = {1, 2, 4};

/*
** indexed by rtt_nrexmt: 0, 1, 2, ..., RTT_MAXNREXMT.
** [0] entry (==1) is not used;
** [1] entry (==2) is used the second time a packet is sent; ...
*/

int             rtt_d_flag = 0;	/* can be set nonzero by caller */
int             rtt_to;


/*
** Init. an RTT structure.
** This function is called before the first packet is transmitted.
*/
int 
rtt_init(register struct rtt_struct * ptr)	/* ptr to caller's structure */
{
	ptr->rtt_rtt = 0;
	ptr->rtt_srtt = 0;
	ptr->rtt_rttdev = 1.5;	/* first timeout at (srtt + (2 * rttdev)) = 3
				 * sec. */
	ptr->rtt_nxtrto = 0;
}

/*
** Init. the retransmit counter before a packet is transmitted the first time
*/
void 
rtt_newpack(register struct rtt_struct * ptr)	/* ptr to caller's structure */
{
	ptr->rtt_nrexmt = 0;
}

/*
** Start our RTT timer.
** This should be called right before the alarm() call before a packet
** is received. We calculate the integer alarm() value to use for the
** timeout (RTO) and return it as the value of the function.
*/
int 
rtt_start(register struct rtt_struct * ptr)	/* ptr to caller's structure */
{
	register int    rexmt;

	if (ptr->rtt_nrexmt > 0)
	{
		/*
	        ** This is a retransmission. No need to obtain the starting time, as we
	        ** won't use the RTT for anything.
	        ** Just apply the exponential back off and return.
	        */

		ptr->rtt_currto *= exp_backoff[ptr->rtt_nrexmt];
		return (ptr->rtt_currto);
	}

#ifdef BSD
	if (gettimeofday(&ptr->time_start, (struct timezone *) 0) < 0)
		err_mesg(FATAL_SYS, "rtt_start: gettimeofday() error\n");
#endif

#ifdef SYS5
	if ((ptr->time_start = times(&ptr->tms_start)) == -1)
		err_mesg(FATAL_SYS, "rtt_start: times() error\n");
#endif

	if (ptr->rtt_nxtrto > 0)
	{
		/*
	        ** This is the first transmission of a packet AND the last packet
	        ** had to be retransmitted. Therefore, we'll use the final RTO for
	        ** the previous packet as the starting RTO for this packet. If that
	        ** RTO is OK for this packet, then we'll start updating the RTT
	        ** estimators (Schaetzungen).
	        */

		ptr->rtt_currto = ptr->rtt_nxtrto;
		ptr->rtt_nxtrto = 0;
		return (ptr->rtt_currto);
	}

	/*
        ** Calculate the timeout value based on current estimators:
        **    smoothed RTT plus twice the deviation.
        */

	rexmt = (int) (ptr->rtt_srtt + (2.0 * ptr->rtt_rttdev) + 0.5);
	if (rexmt < RTT_RXTMIN)
		rexmt = RTT_RXTMIN;
	else if (rexmt > RTT_RXTMAX)
		rexmt = RTT_RXTMAX;

	return (ptr->rtt_currto = rexmt);
}

/*
** A response was received.
** Stop the timer and update the appropriate values in the structure based
** on this packet's RTT. We calculate the RTT, then update the smoothed
** RTT and the RTT variance.
** This function should be called right after turning off the timer with
** alarm(0), or right after a timeout occurs.
*/
void 
rtt_stop(register struct rtt_struct * ptr)	/* ptr to caller's structure */
{
	double          start, stop, err;

	if (ptr->rtt_nrexmt > 0)
	{
		/*
	        ** The response was for a packet that has been retransmitted.
	        ** We don't know which transmission the response corresponds to.
	        ** We didn't record the stop time here. We also don't update
	        ** our estimators.
	        ** We do, however, save the RTO corresponding to this response,
	        ** and it'll be used for the next packet.
	        */

		ptr->rtt_nxtrto = ptr->rtt_currto;
		return;
	}

	ptr->rtt_nxtrto = 0;	/* for next call to rtt_start() */

#ifdef BSD
	if (gettimeofday(&ptr->time_stop, (struct timezone *) 0) < 0)
		err_mesg(FATAL_SYS, "rtt_stop: gettimeofday() error\n");

	/* convert seconds in milli-seconds */
	start = ((double) ptr->time_start.tv_sec) * 1000000.0 + ptr->time_start.tv_usec;
	stop = ((double) ptr->time_stop.tv_sec) * 1000000.0 + ptr->time_stop.tv_usec;
	ptr->rtt_rtt = (stop - start) / 1000000.0;	/* in seconds */
#endif

#ifdef SYS5
	if ((ptr->time_stop = times(&ptr->tms_stop)) == -1)
		err_mesg(FATAL_SYS, "rtt_stop: times() error\n");
	ptr->rtt_rtt = (double) (ptr->time_stop - ptr->time_start) / (double) TICKS;
	/* in seconds */
#endif

	/*
        ** Update our estimators of RTT and mean deviation of RTT.
        ** See Jacobson's SIGCOMM '88 paper, Appendix A, for the details.
        ** This appendix also contains a fixed-point, integer implementation
        ** (that is actually used in all post-4.3 TCP code).
        ** We'll use floating point here for simplicity.
        **
        ** First
        **      err = (rtt - old_srtt)
        **          = difference between this measured value and current estimator.
        **
        ** and
        **      new_srtt = old_srtt * 7 / 8 + rtt / 8.
        ** Then
        **      nre_srtt = old_Srtt + err / 8.
        **
        ** Also
        **      new_rttdev = old_rttdev + ( |err| - old_rttdev ) / 4.
        */

	err = ptr->rtt_rtt - ptr->rtt_srtt;
	ptr->rtt_srtt += err / 8;

	if (err < 0.0)
		err = -err;	/* |err| */

	ptr->rtt_rttdev += (err - ptr->rtt_rttdev) / 4;

}

/*
** A timeout has occurred.
** This function should be called right after the timeout alarm accurs.
** Return -1 if it's time to give up, else return 0.
*/
int 
rtt_timeout(register struct rtt_struct * ptr)	/* ptr to caller's structure */
{
	rtt_stop(ptr);

	if (++ptr->rtt_nrexmt > RTT_MAXNREXMT)
		return (-1);

	return (0);
}

/*
** Print debugging information on stderr, if the "rtt_d_flag" is nonzero.
*/
void 
rtt_debug(register struct rtt_struct * ptr)	/* ptr to caller's structure */
{
	if (rtt_d_flag == 0)
		return;

	fprintf(stderr, "rtt = %.5f, srtt = %.3, rttdev = %.3f, currto = %d\n", ptr->rtt_rtt, ptr->rtt_srtt, ptr->rtt_rttdev, ptr->rtt_currto);
	fflush(stderr);
}

/*
** Signal handler for timeouts (SIGALARM).
** This func. is called when the alarm() value that was set counts down to
** zero. This indicates that we haven't received a response from the server
** to the last datagram we sent.
** All we do is set a flag and return from the signal handler.
** The occurrence of the signal interrupts the recvfrom() system call
** (errno = EINTR) above, and we then check the tout_flag flag.
*/
void 
rtt_alarm(int signr)
{
	rtt_to = 1;		/* set flag for function above */
}
