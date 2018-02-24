#ifdef	unix			/* NOT true for Xenix */
#define	UNIX	1
#ifdef	vax			/* true for BSD on a VAX */
#define	VAX	1		/* Hardware */
#define BSD	1		/* OS */
#else
#ifdef	pyr
#define	PYRAMID	1		/* Hardware */
#define BSD	1		/* OS */
#else
#ifdef	mc68k			/* Assume AT&T Unix PC, aka 7300 or 3b1 */
#define	UNIXPC	1		/* HW */
#define SYS5	1		/* OS */
#else
#ifdef	i386			/* AT&T System 5 Release 3.2 on the Intel
				 * 80386 */
#define IBMPC	1		/* HW */
#define SYS5	1		/* OS */
#else
#ifdef	accel
#define CELERITY	1	/* HW */
#define BSD	1		/* OS */
#else
What type of Unix System is this.
#endif
#endif
#endif
#endif
#endif
#endif

#ifdef	M_XENIX			/* true for SCO Xenix */
#define	UNIX	1		/* OS */
#define XENIX	1		/* dito */
#define SYS5	1		/* eh? */
#define IBMPC	1		/* HW */
#endif

/*
** Define replacement names for the BSD names that we use.
*/

#ifdef	SYS5
#define	rindex	strrchr
#define index	strchr

#define	u_char	unchar
#define u_short	ushort
#define	u_int	uint
#define u_long	ulong
#endif

#ifdef	MICROSOFT
#define rindex  strrchr
#define index   strchr

#define u_char  unchar
#define u_short ushort
#define u_int   uint
#define u_long  ulong
#endif
