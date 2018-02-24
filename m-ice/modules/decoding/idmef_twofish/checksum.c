/***************************************************************************
                          checksum.c  -  description
                             -------------------
    begin                : Sat May 5 2001
    copyright            : (C) 2001 by Thomas Biege
    email                : thomas@uin4d.de
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include "checksum.h"

u_short in_chksum(u_short *ptr, int nbytes)
{
  register long           sum;            /* assumes long == 32 bits */
  u_short                 oddbyte;
  register u_short        answer;         /* assumes u_short == 16 bits */

  /*
  * Our algorithm is simple, using a 32-bit accumulator (sum),
  * we add sequential 16-bit words to it, and at the end, fold back
  * all the carry bits from the top 16 bits into the lower 16 bits.
  */

  sum = 0;
  while (nbytes > 1)
  {
    sum += *ptr++;
    nbytes -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nbytes == 1)
  {
    oddbyte = 0;            /* make sure top half is zero */
    *((unsigned char *) &oddbyte) = *(unsigned char *) ptr;   /* one byte only */
    sum += oddbyte;
  }

  /*
   * Add back carry outs from top 16 bits to low 16 bits.
   */

  sum  = (sum >> 16) + (sum & 0xffff);    /* add high-16 to low-16 */
  sum += (sum >> 16);                     /* add carry */
  answer = ~sum;          /* ones-complement, then truncate to 16 bits */

  return((u_short) answer);
}
