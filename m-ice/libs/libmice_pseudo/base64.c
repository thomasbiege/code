#include <stdio.h>

/* This library ignores incoming line breaks, but does not add line
   breaks to encoded data. 

   It also treats a null terminator in a base64-encoded string as the
   end of input, even though the base64 specification doesn't prevent
   you from including nulls in such a situation.  This is intentional.
   In practice, this shouldn't matter; it's good as a convenience, so
   that people don't have to keep around the length of an encoded
   string.  If you don't like the behavior, it's easy to fix it.

   John Viega, Nov 19, 2000 
*/

/* Given a 6 bit binary value, get a base 64 character. */
static char b64table[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz"
                           "0123456789+/";

/* Given a base 64 character, return the original 6 bit binary value. 
 * We treat a null in the input as end of string and = as padding 
 * signifying the end of string.  Everything else is ignored.
 */
static char b64revtb[256] = { 
  -3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*0-15*/ 
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*16-31*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, /*32-47*/
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -2, -1, -1, /*48-63*/
  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, /*64-79*/
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, /*80-95*/
  -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /*96-111*/
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, /*112-127*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*128-143*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*144-159*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*160-175*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*176-191*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*192-207*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*208-223*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*224-239*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1  /*240-255*/
};

/* Accepts a binary buffer with an associated size.
   Returns a base64 encoded, null-terminated string.
 */
unsigned char *base64_encode(unsigned char *input, int len) {
  unsigned char *output, *p;
  int mod = len % 3;
  int i = 0;
 
  if( (p = output = (unsigned char *)malloc(((len/3)+(mod?1:0))*4 + 1)) == NULL)
    return(NULL);
  while(i < len - mod) {
    *p++ = b64table[input[i++] >> 2];
    *p++ = b64table[((input[i-1] << 4) | (input[i++] >> 4)) & 0x3f];
    *p++ = b64table[((input[i-1] << 2) | (input[i]>>6)) & 0x3f];
    *p++ = b64table[input[i++] & 0x3f];
  }
  if(!mod) {
    *p = 0;
    return output;
  }
  *p++ = b64table[input[i++] >> 2];
  *p++ = b64table[((input[i-1] << 4) | (input[i] >> 4)) & 0x3f];
  *p++ = (mod == 1) ? '=' : b64table[(input[i] << 2) & 0x3f];
  *p++ = '=';
  *p = 0;
  return output;
}

static unsigned int raw_base64_decode(unsigned char *in,
			      unsigned char *out, int *err) {
  unsigned char buf[3];
  unsigned char pad = 0;
  unsigned int result = 0;
  char x;

  *err = 0;
  while(1) {
  ch1:
    switch(x = b64revtb[*in++]) {
    case -3: /* NULL TERMINATOR */
      return result;
    case -2: /* PADDING CHAR... INVALID HERE */
      *err = 1;
      return result;
    case -1:
      goto ch1;
    default:
      buf[0] = x<<2;
    }
  ch2:
    switch(x = b64revtb[*in++]) {
    case -3: /* NULL TERMINATOR... INVALID HERE */
    case -2: /* PADDING CHAR... INVALID HERE */
      *err = 1;
      return result;
    case -1:
      goto ch2;
    default:
      buf[0] |= (x>>4);
      buf[1] = x<<4;
    }
  ch3:
    switch(x = b64revtb[*in++]) {
    case -3: /* NULL TERMINATOR... INVALID HERE */
      *err = 1;
      return result;
    case -2:
      /* Make sure there's appropriate padding. */
      if(*in != '=') {
	*err = 1;
	return result;
      }
      buf[2] = 0;
      pad = 2;
      result += 1;
      goto assembled;
    case -1:
      goto ch3;
    default:
      buf[1] |= (x>>2);
      buf[2] = x<<6;
    }
  ch4:
    switch(x = b64revtb[*in++]) {
    case -3: /* NULL TERMINATOR... INVALID HERE */
      *err = 1;
      return result;
    case -2:
      pad = 1;
      result += 2;
      /* assert(buf[2] == 0) */
      goto assembled;
    case -1:
      goto ch4;
    default:
      buf[2] |= x;
    }
    result += 3;
  assembled:
    for(x=0;x<3-pad;x++) {
      *out++ = buf[x];
    }
    if(pad) {
      return result;
    }
  }
}

/* If err is non-zero on exit, then there was an incorrect padding
   error.  We allocate enough space for all circumstances, but when
   there is padding, or there are characters outside the character 
   set in the string (which we are supposed to ignore), then we 
   end up allocating too much space.  You can realloc to the 
   correct length if you wish.
 */

unsigned char *base64_decode(unsigned char *buf, unsigned int *len)
{
  unsigned char *outbuf;
  int err;

  if( (outbuf = (unsigned char *)malloc(3*(strlen(buf)/4+1))) == NULL)
    return(NULL);

  *len = raw_base64_decode(buf, outbuf, &err);

  if(err != 0)
    return(NULL);
    
  return outbuf;
}
