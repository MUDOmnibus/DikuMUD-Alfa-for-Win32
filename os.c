/*! \file os.c
  The intent of this source file is to put implementations of
  operating system and compiler dependent functions.

  All other authors credits and licenses included in sections separated by
  hyphens.  All other code under Mesh Public License.

 \author Jon A. Lambert
 \date 12/16/2005
 \version 0.5
 \remarks
  This source code copyright (C) 2005 by Jon A. Lambert
  All rights reserved.

  Mesh Public License
  Copyright(c) 2004, 2005 Jon A. Lambert. All rights reserved.

  Permission is hereby granted, free of charge, to any person obtaining a
  copy of this software and associated documentation files, the rights to
  use, copy, modify, create derivative works, merge, publish, distribute,
  sublicense, and/or sell copies of this software, and to permit persons
  to whom the software is furnished to do so, subject to the following
  conditions:

  1. Redistribution in source code must retain the copyright information
  and attributions in the original source code, the above copyright notice,
  this list of conditions, the CONTRIBUTORS file and the following
  disclaimer.

  2. Redistribution in binary form must reproduce the above copyright
  notice, this list of conditions, and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The rights granted to you under this license automatically terminate
  should you attempt to assert any patent claims against the licensor or
  contributors, which in any way restrict the ability of any party to use
  this software or portions thereof in any form under the terms of this
  license.

  Disclaimer:
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

#include "os.h"

/* Nothing in here is for Linux or BSD... so far */
#if defined WIN32


/*
  Windows fgets depends on finding strings terminated by CRLF sequence.
  This one will operate like unixes and depend on LF terminating string.

 \author Jon A. Lambert

 \remarks
  If the user coverts their files to dos/windows style line endings
  intentionally or unintentionally then all bets are off with this.

  This could be modified to an all purpose routine to catch any sort of
  text file line-endings.

  When porting make sure all files are opened in binary mode.
  (Ex. rb, wb, r+b etc.)
 */
char *fgets_win (char *buf, int n, FILE * fp)
{
  int c;
  char *s;

  if ((n < 2) || (buf == NULL))
    return NULL;

  s = buf;
  while (--n > 0 && (c = getc (fp)) != EOF) {
    *s++ = c;
    if (c == '\n')
      break;
  }
  if (c == EOF && s == buf) {
    return NULL;
  }
  *s = 0;
  return buf;
}

/*
  Not implemented in windows, although all the structural support is
  found in winsock.h

 \author Jon A. Lambert

 \remarks
  This version has millisecond granularity.
 */
void gettimeofday (struct timeval *tp, struct timezone *tzp)
{
  tp->tv_sec = time (NULL);
  tp->tv_usec = (GetTickCount () % 1000) * 1000;
}


/*-------------------------------------------------------------------*/

/*
 Crypt is from Andy Tanenbaum's book "Computer Networks", rewritten in C.

 \author Andy Tanenbaum

 \remarks
  This does generate the exact same password string as glibc and newlib
  so your files containg passwords are portable.  I am not sure about
  FreeBSD.
 */
/*
  Copyright (c) 1987,1997, Prentice Hall
  All rights reserved.

  Redistribution and use of the MINIX operating system in source and
  binary forms, with or without modification, are permitted provided
  that the following conditions are met:

     * Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.

     * Redistributions in binary form must reproduce the above
       copyright notice, this list of conditions and the following
       disclaimer in the documentation and/or other materials provided
       with the distribution.

     * Neither the name of Prentice Hall nor the names of the software
       authors or contributors may be used to endorse or promote
       products derived from this software without specific prior
       written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS, AUTHORS, AND
  CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
  IN NO EVENT SHALL PRENTICE HALL OR ANY AUTHORS OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
  OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


struct block {
  unsigned char b_data[64];
};

struct ordering {
  unsigned char o_data[64];
};

static struct block key;

static struct ordering InitialTr = {
  58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
};

static struct ordering FinalTr = {
  40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
};

static struct ordering swap = {
  33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
  49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
  17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
};

static struct ordering KeyTr1 = {
  57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
  10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
  14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
};

static struct ordering KeyTr2 = {
  14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
  23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
};

static struct ordering etr = {
  32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
  8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
};

static struct ordering ptr = {
  16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
  2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
};

static unsigned char s_boxes[8][64] = {
  {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
      0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
      4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
      15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    },

  {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
      3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
      0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
      13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    },

  {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
      13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
      13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
      1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    },

  {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
      13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
      10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
      3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    },

  {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
      14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
      4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
      11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    },

  {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
      10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
      9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
      4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    },

  {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
      13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
      1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
      6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    },

  {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
      1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
      7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
      2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    },
};

static int rots[] = {
  1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
};

static void transpose (struct block *data, struct ordering *t, int n)
{
  struct block x;

  x = *data;

  while (n-- > 0) {
    data->b_data[n] = x.b_data[t->o_data[n] - 1];
  }
}

static void rotate (struct block *key)
{
  register unsigned char *p = key->b_data;
  register unsigned char *ep = &(key->b_data[55]);
  int data0 = key->b_data[0], data28 = key->b_data[28];

  while (p++ < ep)
    *(p - 1) = *p;
  key->b_data[27] = (char) data0;
  key->b_data[55] = (char) data28;
}

static struct ordering *EP = &etr;

static void f (int i, struct block *key, struct block *a, struct block *x)
{
  struct block e, ikey, y;
  int k;
  register unsigned char *p, *q, *r;

  e = *a;
  transpose (&e, EP, 48);
  for (k = rots[i]; k; k--)
    rotate (key);
  ikey = *key;
  transpose (&ikey, &KeyTr2, 48);
  p = &(y.b_data[48]);
  q = &(e.b_data[48]);
  r = &(ikey.b_data[48]);
  while (p > y.b_data) {
    *--p = *--q ^ *--r;
  }
  q = x->b_data;
  for (k = 0; k < 8; k++) {
    register int xb, r;

    r = *p++ << 5;
    r += *p++ << 3;
    r += *p++ << 2;
    r += *p++ << 1;
    r += *p++;
    r += *p++ << 4;

    xb = s_boxes[k][r];

    *q++ = (char) (xb >> 3) & 1;
    *q++ = (char) (xb >> 2) & 1;
    *q++ = (char) (xb >> 1) & 1;
    *q++ = (char) (xb & 1);
  }
  transpose (x, &ptr, 32);
}

void definekey (char *k)
{

  key = *((struct block *) k);
  transpose (&key, &KeyTr1, 56);
}

void encrypt (char *blck, int edflag)
{
  register struct block *p = (struct block *) blck;
  register int i;

  transpose (p, &InitialTr, 64);
  for (i = 15; i >= 0; i--) {
    int j = edflag ? i : 15 - i;
    register int k;
    struct block b, x;

    b = *p;
    for (k = 31; k >= 0; k--) {
      p->b_data[k] = b.b_data[k + 32];
    }
    f (j, &key, p, &x);
    for (k = 31; k >= 0; k--) {
      p->b_data[k + 32] = b.b_data[k] ^ x.b_data[k];
    }
  }
  transpose (p, &swap, 64);
  transpose (p, &FinalTr, 64);
}

char *crypt (char *pw, char *salt)
{

  char pwb[66];
  static char result[16];
  register char *p = pwb;
  struct ordering new_etr;
  register int i;

  while (*pw && p < &pwb[64]) {
    register int j = 7;

    while (j--) {
      *p++ = (*pw >> j) & 01;
    }
    pw++;
    *p++ = 0;
  }
  while (p < &pwb[64])
    *p++ = 0;

  definekey (p = pwb);

  while (p < &pwb[66])
    *p++ = 0;

  new_etr = etr;
  EP = &new_etr;
  for (i = 0; i < 2; i++) {
    register char c = *salt++;
    register int j;

    result[i] = c;
    if (c > 'Z')
      c -= 6 + 7 + '.';         /* c was a lower case letter */
    else if (c > '9')
      c -= 7 + '.';             /* c was upper case letter */
    else
      c -= '.';                 /* c was digit, '.' or '/'. */
    /* now, 0 <= c <= 63 */
    for (j = 0; j < 6; j++) {
      if ((c >> j) & 01) {
        int t = 6 * i + j;
        int temp = new_etr.o_data[t];
        new_etr.o_data[t] = new_etr.o_data[t + 24];
        new_etr.o_data[t + 24] = (char) temp;
      }
    }
  }

  if (result[1] == 0)
    result[1] = result[0];

  for (i = 0; i < 25; i++)
    encrypt (pwb, 0);
  EP = &etr;

  p = pwb;
  pw = result + 2;
  while (p < &pwb[66]) {
    register int c = 0;
    register int j = 6;

    while (j--) {
      c <<= 1;
      c |= *p++;
    }
    c += '.';                   /* becomes >= '.' */
    if (c > '9')
      c += 7;                   /* not in [./0-9], becomes upper */
    if (c > 'Z')
      c += 6;                   /* not in [A-Z], becomes lower */
    *pw++ = (char) c;
  }
  *pw = 0;
  return result;
}

/*-------------------------------------------------------------------*/

#if defined __LCC__ || defined _MSC_VER

/*
  POSIX directory functions - opendir, readdir, closedir
  These are not implemented in either LCC or Visual C++ RTL.

 \author Jon A. Lambert

 \remarks
  Error checking is pretty poor here, so you might want to validate or
  run the name through some escape checking if you allow user tainted
  data to go into opendir.
  No rewindir... yet.
 */
struct directory {
  WIN32_FIND_DATA find_data;
  int *find_handle;
  struct dirent entry;
};

DIR *opendir (char const *name)
{
  DIR *dir;
  int attrib;
  char findname[260];

  if (name == NULL)
    return NULL;

  attrib = GetFileAttributes (name);
  if (attrib == 0xffffffff || (attrib & FILE_ATTRIBUTE_DIRECTORY == 0))
    return NULL;

  dir = malloc (sizeof (DIR));
  strcpy (findname, name);
  strcat (findname, "\\*.*");

  dir->find_handle = (int *) FindFirstFileA (findname, &dir->find_data);
  if (dir->find_handle == INVALID_HANDLE_VALUE) {
    free (dir);
    dir = NULL;
  }
  return dir;
}

struct dirent *readdir (DIR * dir)
{
  if (dir->find_handle == INVALID_HANDLE_VALUE)
    return NULL;
  strcpy (dir->entry.d_name, dir->find_data.cFileName);
  if (!FindNextFileA (dir->find_handle, &dir->find_data)) {
    FindClose (dir->find_handle);
    dir->find_handle = INVALID_HANDLE_VALUE;
  }
  return &dir->entry;
}

int closedir (DIR * dir)
{
  if (dir == NULL)
    return -1;
  if (dir->find_handle != (int *) -1)
    FindClose (dir->find_handle);
  free (dir);
  return 0;
}

/*-------------------------------------------------------------------*/

/*
  regex - Regular expression pattern matching  and replacement

 \author Ozan S. Yigit

 \remarks
  This is less functional than PCRE, Gnu's or Spencer's regex.

 */
/*
 * regex - Regular expression pattern matching  and replacement
 *
 * By:  Ozan S. Yigit (oz)
 *      Dept. of Computer Science
 *      York University
 *
 * These routines are the PUBLIC DOMAIN equivalents of regex
 * routines as found in 4.nBSD UN*X, with minor extensions.
 *
 * These routines are derived from various implementations found
 * in software tools books, and Conroy's grep. They are NOT derived
 * from licensed/restricted software.
 * For more interesting/academic/complicated implementations,
 * see Henry Spencer's regexp routines, or GNU Emacs pattern
 * matching module.
 *
 * Modification history:
 *
 * $Log: regex.c,v $
 * Revision 1.4  1991/10/17  03:56:42  oz
 * miscellaneous changes, small cleanups etc.
 *
 * Revision 1.3  1989/04/01  14:18:09  oz
 * Change all references to a dfa: this is actually an nfa.
 *
 * Revision 1.2  88/08/28  15:36:04  oz
 * Use a complement bitmap to represent NCL.
 * This removes the need to have seperate
 * code in the pmatch case block - it is
 * just CCL code now.
 *
 * Use the actual CCL code in the CLO
 * section of pmatch. No need for a recursive
 * pmatch call.
 *
 * Use a bitmap table to set char bits in an
 * 8-bit chunk.
 *
 * Interfaces:
 *  re_comp:    compile a regular expression into a NFA.
 *
 *      char *re_comp(s)
 *      char *s;
 *
 *  re_exec:    execute the NFA to match a pattern.
 *
 *      int re_exec(s)
 *      char *s;
 *
 *  re_modw     change re_exec's understanding of what a "word"
 *      looks like (for \< and \>) by adding into the
 *      hidden word-syntax table.
 *
 *      void re_modw(s)
 *      char *s;
 *
 *  re_subs:    substitute the matched portions in a new string.
 *
 *      int re_subs(src, dst)
 *      char *src;
 *      char *dst;
 *
 *  re_fail:    failure routine for re_exec.
 *
 *      void re_fail(msg, op)
 *      char *msg;
 *      char op;
 *
 * Regular Expressions:
 *
 *  [1] char matches itself, unless it is a special
 *           character (metachar): . \ [ ] * + ^ $
 *
 *  [2] .   matches any character.
 *
 *  [3] \   matches the character following it, except
 *      when followed by a left or right round bracket,
 *      a digit 1 to 9 or a left or right angle bracket.
 *      (see [7], [8] and [9])
 *      It is used as an escape character for all
 *      other meta-characters, and itself. When used
 *      in a set ([4]), it is treated as an ordinary
 *      character.
 *
 *  [4] [set]   matches one of the characters in the set.
 *      If the first character in the set is "^",
 *      it matches a character NOT in the set, i.e.
 *      complements the set. A shorthand S-E is
 *      used to specify a set of characters S upto
 *      E, inclusive. The special characters "]" and
 *      "-" have no special meaning if they appear
 *      as the first chars in the set.
 *          examples:        match:
 *
 *                  [a-z]    any lowercase alpha
 *
 *                  [^]-]    any char except ] and -
 *
 *                  [^A-Z]   any char except uppercase
 *                           alpha
 *
 *                  [a-zA-Z] any alpha
 *
 *  [5] *   any regular expression form [1] to [4], followed by
 *          closure char (*) matches zero or more matches of
 *          that form.
 *
 *  [6] +   same as [5], except it matches one or more.
 *
 *  [7]     a regular expression in the form [1] to [10], enclosed
 *      as \(form\) matches what form matches. The enclosure
 *      creates a set of tags, used for [8] and for
 *      pattern substution. The tagged forms are numbered
 *      starting from 1.
 *
 *  [8] a \ followed by a digit 1 to 9 matches whatever a
 *      previously tagged regular expression ([7]) matched.
 *
 *  [9] \<  a regular expression starting with a \< construct
 *      \>  and/or ending with a \> construct, restricts the
 *      pattern matching to the beginning of a word, and/or
 *      the end of a word. A word is defined to be a character
 *      string beginning and/or ending with the characters
 *      A-Z a-z 0-9 and _. It must also be preceded and/or
 *      followed by any character outside those mentioned.
 *
 *  [10]    a composite regular expression xy where x and y
 *      are in the form [1] to [10] matches the longest
 *      match of x followed by a match for y.
 *
 *  [11]    ^   a regular expression starting with a ^ character
 *      $   and/or ending with a $ character, restricts the
 *      pattern matching to the beginning of the line,
 *      or the end of line. [anchors] Elsewhere in the
 *      pattern, ^ and $ are treated as ordinary characters.
 *
 *
 * Acknowledgements:
 *
 *  HCR's Hugh Redelmeier has been most helpful in various
 *  stages of development. He convinced me to include BOW
 *  and EOW constructs, originally invented by Rob Pike at
 *  the University of Toronto.
 *
 * References:
 *      Software tools          Kernighan & Plauger
 *      Software tools in Pascal        Kernighan & Plauger
 *      Grep [rsx-11 C dist]            David Conroy
 *      ed - text editor        Un*x Programmer's Manual
 *      Advanced editing on Un*x    B. W. Kernighan
 *      RegExp routines         Henry Spencer
 *
 * Notes:
 *
 *  This implementation uses a bit-set representation for character
 *  classes for speed and compactness. Each character is represented
 *  by one bit in a 128-bit block. Thus, CCL always takes a
 *  constant 16 bytes in the internal nfa, and re_exec does a single
 *  bit comparison to locate the character in the set.
 *
 * Examples:
 *
 *  pattern:    foo*.*
 *  compile:    CHR f CHR o CLO CHR o END CLO ANY END END
 *  matches:    fo foo fooo foobar fobar foxx ...
 *
 *  pattern:    fo[ob]a[rz]
 *  compile:    CHR f CHR o CCL bitset CHR a CCL bitset END
 *  matches:    fobar fooar fobaz fooaz
 *
 *  pattern:    foo\\+
 *  compile:    CHR f CHR o CHR o CHR \ CLO CHR \ END END
 *  matches:    foo\ foo\\ foo\\\  ...
 *
 *  pattern:    \(foo\)[1-3]\1  (same as foo[1-3]foo)
 *  compile:    BOT 1 CHR f CHR o CHR o EOT 1 CCL bitset REF 1 END
 *  matches:    foo1foo foo2foo foo3foo
 *
 *  pattern:    \(fo.*\)-\1
 *  compile:    BOT 1 CHR f CHR o CLO ANY END EOT 1 CHR - REF 1 END
 *  matches:    foo-foo fo-fo fob-fob foobar-foobar ...
 */

#define MAXNFA  1024
#define MAXTAG  10

#define OKP     1
#define NOP     0

#define CHR     1
#define ANY     2
#define CCL     3
#define BOL     4
#define EOL     5
#define BOT     6
#define EOT     7
#define BOW 8
#define EOW 9
#define REF     10
#define CLO     11

#define END     0

/*
 * The following defines are not meant to be changeable.
 * They are for readability only.
 */
#define MAXCHR  128
#define CHRBIT  8
#define BITBLK  MAXCHR/CHRBIT
#define BLKIND  0170
#define BITIND  07

#define ASCIIB  0177

#ifdef NO_UCHAR
typedef char CHAR;
#else
typedef unsigned char CHAR;
#endif

static int tagstk[MAXTAG];      /* subpat tag stack.. */
static CHAR nfa[MAXNFA];        /* automaton..       */
static int sta = NOP;           /* status of lastpat */

static CHAR bittab[BITBLK];     /* bit table for CCL */
                    /* pre-set bits...   */
static CHAR bitarr[] = { 1, 2, 4, 8, 16, 32, 64, 128 };


#ifdef DEBUG
static void nfadump (CHAR *);
void symbolic (char *);
#endif

static void chset (CHAR c)
{
  bittab[(CHAR) ((c) & BLKIND) >> 3] |= bitarr[(c) & BITIND];
}

#define badpat(x)   (*nfa = END, x)
#define store(x)    *mp++ = x

char *re_comp (char *pat)
{
  register char *p;             /* pattern pointer   */
  register CHAR *mp = nfa;      /* nfa pointer       */
  register CHAR *lp;            /* saved pointer..   */
  register CHAR *sp = nfa;      /* another one..     */

  register int tagi = 0;        /* tag stack index   */
  register int tagc = 1;        /* actual tag count  */

  register int n;
  register CHAR mask;           /* xor mask -CCL/NCL */
  int c1, c2;

  if (!pat || !*pat)
    if (sta)
      return 0;
    else
      return badpat ("No previous regular expression");
  sta = NOP;

  for (p = pat; *p; p++) {
    lp = mp;
    switch (*p) {

    case '.':                  /* match any char..  */
      store (ANY);
      break;

    case '^':                  /* match beginning.. */
      if (p == pat)
        store (BOL);
      else {
        store (CHR);
        store (*p);
      }
      break;

    case '$':                  /* match endofline.. */
      if (!*(p + 1))
        store (EOL);
      else {
        store (CHR);
        store (*p);
      }
      break;

    case '[':                  /* match char class.. */
      store (CCL);

      if (*++p == '^') {
        mask = 0377;
        p++;
      } else
        mask = 0;

      if (*p == '-')            /* real dash */
        chset (*p++);
      if (*p == ']')            /* real brac */
        chset (*p++);
      while (*p && *p != ']') {
        if (*p == '-' && *(p + 1) && *(p + 1) != ']') {
          p++;
          c1 = *(p - 2) + 1;
          c2 = *p++;
          while (c1 <= c2)
            chset ((CHAR) c1++);
        }
#ifdef EXTEND
        else if (*p == '\\' && *(p + 1)) {
          p++;
          chset (*p++);
        }
#endif
        else
          chset (*p++);
      }
      if (!*p)
        return badpat ("Missing ]");

      for (n = 0; n < BITBLK; bittab[n++] = (char) 0)
        store (mask ^ bittab[n]);

      break;

    case '*':                  /* match 0 or more.. */
    case '+':                  /* match 1 or more.. */
      if (p == pat)
        return badpat ("Empty closure");
      lp = sp;                  /* previous opcode */
      if (*lp == CLO)           /* equivalence..   */
        break;
      switch (*lp) {

      case BOL:
      case BOT:
      case EOT:
      case BOW:
      case EOW:
      case REF:
        return badpat ("Illegal closure");
      default:
        break;
      }

      if (*p == '+')
        for (sp = mp; lp < sp; lp++)
          store (*lp);

      store (END);
      store (END);
      sp = mp;
      while (--mp > lp)
        *mp = mp[-1];
      store (CLO);
      mp = sp;
      break;

    case '\\':                 /* tags, backrefs .. */
      switch (*++p) {

      case '(':
        if (tagc < MAXTAG) {
          tagstk[++tagi] = tagc;
          store (BOT);
          store (tagc++);
        } else
          return badpat ("Too many \\(\\) pairs");
        break;
      case ')':
        if (*sp == BOT)
          return badpat ("Null pattern inside \\(\\)");
        if (tagi > 0) {
          store (EOT);
          store (tagstk[tagi--]);
        } else
          return badpat ("Unmatched \\)");
        break;
      case '<':
        store (BOW);
        break;
      case '>':
        if (*sp == BOW)
          return badpat ("Null pattern inside \\<\\>");
        store (EOW);
        break;
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        n = *p - '0';
        if (tagi > 0 && tagstk[tagi] == n)
          return badpat ("Cyclical reference");
        if (tagc > n) {
          store (REF);
          store (n);
        } else
          return badpat ("Undetermined reference");
        break;
#ifdef EXTEND
      case 'b':
        store (CHR);
        store ('\b');
        break;
      case 'n':
        store (CHR);
        store ('\n');
        break;
      case 'f':
        store (CHR);
        store ('\f');
        break;
      case 'r':
        store (CHR);
        store ('\r');
        break;
      case 't':
        store (CHR);
        store ('\t');
        break;
#endif
      default:
        store (CHR);
        store (*p);
      }
      break;

    default:                   /* an ordinary char  */
      store (CHR);
      store (*p);
      break;
    }
    sp = lp;
  }
  if (tagi > 0)
    return badpat ("Unmatched \\(");
  store (END);
  sta = OKP;
  return 0;
}


static char *bol;
char *bopat[MAXTAG];
char *eopat[MAXTAG];
static char *pmatch (char *, CHAR *);

/*
 * re_exec:
 *  execute nfa to find a match.
 *
 *  special cases: (nfa[0])
 *      BOL
 *          Match only once, starting from the
 *          beginning.
 *      CHR
 *          First locate the character without
 *          calling pmatch, and if found, call
 *          pmatch for the remaining string.
 *      END
 *          re_comp failed, poor luser did not
 *          check for it. Fail fast.
 *
 *  If a match is found, bopat[0] and eopat[0] are set
 *  to the beginning and the end of the matched fragment,
 *  respectively.
 *
 */

int re_exec (char *lp)
{
  register CHAR c;
  register char *ep = 0;
  register CHAR *ap = nfa;

  bol = lp;

  bopat[0] = 0;
  bopat[1] = 0;
  bopat[2] = 0;
  bopat[3] = 0;
  bopat[4] = 0;
  bopat[5] = 0;
  bopat[6] = 0;
  bopat[7] = 0;
  bopat[8] = 0;
  bopat[9] = 0;

  switch (*ap) {

  case BOL:                    /* anchored: match from BOL only */
    ep = pmatch (lp, ap);
    break;
  case CHR:                    /* ordinary char: locate it fast */
    c = *(ap + 1);
    while (*lp && *lp != c)
      lp++;
    if (!*lp)                   /* if EOS, fail, else fall thru. */
      return 0;
  default:                     /* regular matching all the way. */
#ifdef OLD
    while (*lp) {
      if ((ep = pmatch (lp, ap)))
        break;
      lp++;
    }
#else /* match null string */
    do {
      if ((ep = pmatch (lp, ap)))
        break;
      lp++;
    }
    while (*lp);
#endif
    break;
  case END:                    /* munged automaton. fail always */
    return 0;
  }
  if (!ep)
    return 0;

  bopat[0] = lp;
  eopat[0] = ep;
  return 1;
}

/*
 * pmatch: internal routine for the hard part
 *
 *  This code is partly snarfed from an early grep written by
 *  David Conroy. The backref and tag stuff, and various other
 *  innovations are by oz.
 *
 *  special case optimizations: (nfa[n], nfa[n+1])
 *      CLO ANY
 *          We KNOW .* will match everything upto the
 *          end of line. Thus, directly go to the end of
 *          line, without recursive pmatch calls. As in
 *          the other closure cases, the remaining pattern
 *          must be matched by moving backwards on the
 *          string recursively, to find a match for xy
 *          (x is ".*" and y is the remaining pattern)
 *          where the match satisfies the LONGEST match for
 *          x followed by a match for y.
 *      CLO CHR
 *          We can again scan the string forward for the
 *          single char and at the point of failure, we
 *          execute the remaining nfa recursively, same as
 *          above.
 *
 *  At the end of a successful match, bopat[n] and eopat[n]
 *  are set to the beginning and end of subpatterns matched
 *  by tagged expressions (n = 1 to 9).
 *
 */

#ifndef re_fail
/*
 * re_fail:
 *  default internal error handler for re_exec.
 *
 *  should probably do something like a longjump to recover
 *  gracefully.
 */
void re_fail (char *s, char c)
{
  fprintf (stderr, "%s [opcode %o]\n", s, c);
  exit (1);
}
#endif

/*
 * character classification table for word boundary operators BOW
 * and EOW. the reason for not using ctype macros is that we can
 * let the user add into our own table. see re_modw. This table
 * is not in the bitset form, since we may wish to extend it in the
 * future for other character classifications.
 *
 *  TRUE for 0-9 A-Z a-z _
 */
static CHAR chrtyp[MAXCHR] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 0, 0,
  0, 0, 0, 0, 0, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 0, 0, 0, 0, 1, 0, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 0, 0, 0, 0, 0
};

#define inascii(x)  (0177&(x))
#define iswordc(x)  chrtyp[inascii(x)]
#define isinset(x,y)    ((x)[((y)&BLKIND)>>3] & bitarr[(y)&BITIND])

/*
 * skip values for CLO XXX to skip past the closure
 */

#define ANYSKIP 2               /* [CLO] ANY END ...         */
#define CHRSKIP 3               /* [CLO] CHR chr END ...     */
#define CCLSKIP 18              /* [CLO] CCL 16bytes END ... */

static char *pmatch (char *lp, CHAR * ap)
{
  register int op, c, n;
  register char *e;             /* extra pointer for CLO */
  register char *bp;            /* beginning of subpat.. */
  register char *ep;            /* ending of subpat..    */
  char *are;                    /* to save the line ptr. */

  while ((op = *ap++) != END)
    switch (op) {

    case CHR:
      if (*lp++ != *ap++)
        return 0;
      break;
    case ANY:
      if (!*lp++)
        return 0;
      break;
    case CCL:
      c = *lp++;
      if (!isinset (ap, c))
        return 0;
      ap += BITBLK;
      break;
    case BOL:
      if (lp != bol)
        return 0;
      break;
    case EOL:
      if (*lp)
        return 0;
      break;
    case BOT:
      bopat[*ap++] = lp;
      break;
    case EOT:
      eopat[*ap++] = lp;
      break;
    case BOW:
      if (lp != bol && iswordc (lp[-1]) || !iswordc (*lp))
        return 0;
      break;
    case EOW:
      if (lp == bol || !iswordc (lp[-1]) || iswordc (*lp))
        return 0;
      break;
    case REF:
      n = *ap++;
      bp = bopat[n];
      ep = eopat[n];
      while (bp < ep)
        if (*bp++ != *lp++)
          return 0;
      break;
    case CLO:
      are = lp;
      switch (*ap) {

      case ANY:
        while (*lp)
          lp++;
        n = ANYSKIP;
        break;
      case CHR:
        c = *(ap + 1);
        while (*lp && c == *lp)
          lp++;
        n = CHRSKIP;
        break;
      case CCL:
        while ((c = *lp) && isinset (ap + 1, c))
          lp++;
        n = CCLSKIP;
        break;
      default:
        re_fail ("closure: bad nfa.", *ap);
        return 0;
      }

      ap += n;

      while (lp >= are) {
        if (e = pmatch (lp, ap))
          return e;
        --lp;
      }
      return 0;
    default:
      re_fail ("re_exec: bad nfa.", (CHAR)op);
      return 0;
    }
  return lp;
}

/*
 * re_modw:
 *  add new characters into the word table to change re_exec's
 *  understanding of what a word should look like. Note that we
 *  only accept additions into the word definition.
 *
 *  If the string parameter is 0 or null string, the table is
 *  reset back to the default containing A-Z a-z 0-9 _. [We use
 *  the compact bitset representation for the default table]
 */

static CHAR deftab[16] = {
  0, 0, 0, 0, 0, 0, 0377, 003, 0376, 0377, 0377, 0207,
  0376, 0377, 0377, 007
};

void re_modw (char *s)
{
  register int i;

  if (!s || !*s) {
    for (i = 0; i < MAXCHR; i++)
      if (!isinset (deftab, i))
        iswordc (i) = 0;
  } else
    while (*s)
      iswordc (*s++) = 1;
}

/*
 * re_subs:
 *  substitute the matched portions of the src in dst.
 *
 *  &   substitute the entire matched pattern.
 *
 *  \digit  substitute a subpattern, with the given tag number.
 *      Tags are numbered from 1 to 9. If the particular
 *      tagged subpattern does not exist, null is substituted.
 */
int re_subs (char *src, char *dst)
{
  register char c;
  register int pin;
  register char *bp;
  register char *ep;

  if (!*src || !bopat[0])
    return 0;

  while (c = *src++) {
    switch (c) {

    case '&':
      pin = 0;
      break;

    case '\\':
      c = *src++;
      if (c >= '0' && c <= '9') {
        pin = c - '0';
        break;
      }

    default:
      *dst++ = c;
      continue;
    }

    if ((bp = bopat[pin]) && (ep = eopat[pin])) {
      while (*bp && bp < ep)
        *dst++ = *bp++;
      if (bp < ep)
        return 0;
    }
  }
  *dst = (char) 0;
  return 1;
}

#ifdef DEBUG
/*
 * symbolic - produce a symbolic dump of the nfa
 */
symbolic (char *s)
{
  printf ("pattern: %s\n", s);
  printf ("nfacode:\n");
  nfadump (nfa);
}

static nfadump (CHAR * ap)
{
  register int n;

  while (*ap != END)
    switch (*ap++) {
    case CLO:
      printf ("CLOSURE");
      nfadump (ap);
      switch (*ap) {
      case CHR:
        n = CHRSKIP;
        break;
      case ANY:
        n = ANYSKIP;
        break;
      case CCL:
        n = CCLSKIP;
        break;
      }
      ap += n;
      break;
    case CHR:
      printf ("\tCHR %c\n", *ap++);
      break;
    case ANY:
      printf ("\tANY .\n");
      break;
    case BOL:
      printf ("\tBOL -\n");
      break;
    case EOL:
      printf ("\tEOL -\n");
      break;
    case BOT:
      printf ("BOT: %d\n", *ap++);
      break;
    case EOT:
      printf ("EOT: %d\n", *ap++);
      break;
    case BOW:
      printf ("BOW\n");
      break;
    case EOW:
      printf ("EOW\n");
      break;
    case REF:
      printf ("REF: %d\n", *ap++);
      break;
    case CCL:
      printf ("\tCCL [");
      for (n = 0; n < MAXCHR; n++)
        if (isinset (ap, (CHAR) n)) {
          if (n < ' ')
            printf ("^%c", n ^ 0x040);
          else
            printf ("%c", n);
        }
      printf ("]\n");
      ap += BITBLK;
      break;
    default:
      printf ("bad nfa. opcode %o\n", ap[-1]);
      exit (1);
      break;
    }
}
#endif

/*-------------------------------------------------------------------*/

#endif // defined __LCC__ || defined _MSC_VER

#endif // WIN32
