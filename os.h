/*! \file os.h
  The intent of this header file is to put operating system and compiler
  specific portability changes in one place.

 \author Jon A. Lambert
 \date 12/16/2005
 \version 0.5
 \remarks
  This source code copyright (C) 2004,2005 by Jon A. Lambert
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

#ifndef OS_H
#define OS_H

/*-----------------------------------------------------------------------*/
/* COMMON DEFINITIONS SECTION                                            */
/*-----------------------------------------------------------------------*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <signal.h>
#include <time.h>               /* Gentoo complains */
#include <sys/types.h>
#include <limits.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/stat.h>

/*-----------------------------------------------------------------------*/
/* WINDOWS DEFINITIONS SECTION                                           */
/*-----------------------------------------------------------------------*/
#ifdef WIN32                    /* Windows portability */

#define ARG_MAX (16384 - 256)
#define FD_SETSIZE 1024
#define NOFILE FD_SETSIZE
#include <winsock2.h>
#include <process.h>

#if defined __LCC__ || defined _MSC_VER
#include <direct.h>
#endif
#if defined __BORLANDC__
#include <dir.h>
#endif

#if defined __LCC__ || defined _MSC_VER
typedef struct directory DIR;
struct dirent {
  char d_name[260];
};
DIR *opendir (const char *name);
int closedir (DIR * dir);
struct dirent *readdir (DIR * dir);
#else
#include <dirent.h>
#endif

#if defined __BORLANDC__
/* if you have regcomp() and regex() instead of re_comp() and re_exec() */
#define REGEX
#define regcmp regcomp
#define regex regexec
#endif
#if defined __LCC__ || defined _MSC_VER
extern char *re_comp (char *);
extern int re_exec (char *);
#endif

#undef EWOULDBLOCK
#undef EADDRINUSE
#undef ETIMEDOUT
#undef ECONNRESET
#undef EMSGSIZE
#undef EHOSTUNREACH
#undef ENETUNREACH
#define EWOULDBLOCK       WSAEWOULDBLOCK
#define EADDRINUSE        WSAEADDRINUSE
#define ETIMEDOUT         WSAETIMEDOUT
#define ECONNRESET        WSAECONNRESET
#define EMSGSIZE          WSAEMSGSIZE
#define EHOSTUNREACH      WSAEHOSTUNREACH
#define ENETUNREACH       WSAENETRESET

#undef EPIPE
#undef EINVAL
#define EPIPE             WSAENOTCONN
#define EINVAL            WSAEINVAL

#undef ECONNREFUSED
#define ECONNREFUSED      WSAECONNABORTED
#undef EINTR
#undef EMFILE
#define EINTR             WSAEINTR
#define EMFILE            WSAEMFILE
#define GETERROR     WSAGetLastError()
#define WIN32STARTUP \
    { \
      WSADATA wsaData; \
      int err = WSAStartup(0x202,&wsaData); \
      if (err) \
        fprintf(stderr,"Error(WSAStartup):%d\n",err); \
    }
#define WIN32CLEANUP WSACleanup();

#define close(X) closesocket(X)
#define index(s, c) strchr((s), (c))
#define bcopy(s, d, n)   memcpy((d), (s), (n))
#define bcmp(s, d, n)   memcmp((d), (s), (n))
#define bzero(s, n)      memset((s), 0, (n))
#define getdtablesize() FD_SETSIZE
#define OS_RAND rand
#define OS_SRAND srand

#if defined __DMC__
#define snprintf _snprintf
#endif
#if defined _MSC_VER
#define stat _stat
#define mkdir _mkdir
#define chdir _chdir
#define fstat _fstat
#define isatty _isatty
#define fileno _fileno
#define unlink _unlink
#define snprintf _snprintf
#define strdup _strdup
#define getpid _getpid
#define strcasecmp(s1, s2) _stricmp((s1), (s2))
#define strncasecmp(s1, s2, s3) _strnicmp((s1), (s2), (s3))
#else
#define strcasecmp(s1, s2) stricmp((s1), (s2))
#define strncasecmp(s1, s2, s3) strncmpi((s1), (s2), (s3))
#endif
#define popen _popen
#define pclose _pclose


/* defined in os.c */
#ifndef __LCC__                 /* simply does not like our prototype ? */
extern void gettimeofday (struct timeval *tp, struct timezone *tzp);
#endif
extern char *crypt (char *pw, char *salt);
#define FGETS fgets_win
extern char *fgets_win (char *buf, int n, FILE * fp);

#if defined __TINYC__
#define isascii __isascii
#endif

/*-----------------------------------------------------------------------*/
/* UNIX DEFINITION SECTION                                               */
/*-----------------------------------------------------------------------*/
#else /* Unix portability - some a consequence of above */

#include <sys/time.h>           /* Redhat and BSD need this */
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/wait.h>
#ifndef __FreeBSD__
#include <crypt.h>
#endif
#include <dirent.h>
#define GETERROR  errno
#define INVALID_SOCKET -1       /* 0 on Windows */
#define SOCKET_ERROR -1
#define SOCKET int
#define WIN32STARTUP
#define WIN32CLEANUP
#define OS_RAND random
#define OS_SRAND srandom
#define FGETS fgets
#define closesocket(X) close(X)
/* if you have regcomp() and regex() instead of re_comp() and re_exec() */
#define REGEX
#define regcmp regcomp
#define regex regexec

#endif

/*-----------------------------------------------------------------------*/
/* COMMON DEFINITION SECTION                                             */
/*-----------------------------------------------------------------------*/
#if defined _POSIX_ARG_MAX
#define MAXCMDLEN _POSIX_ARG_MAX
#elif defined ARG_MAX
#define MAXCMDLEN ARG_MAX
#elif defined NCARGS
#define MAXCMDLEN  NCARGS
#else
#error Cannot determine maximum command argument size
#endif

#ifndef MAXPATHLEN
#ifdef MAXPATH
#define MAXPATHLEN MAXPATH
#else
#define MAXPATHLEN 260
#endif
#endif

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN MAXGETHOSTSTRUCT
#endif

#if !defined NOFILE
#if defined OPEN_MAX
#define NOFILE OPEN_MAX
#else
#error Cannot determine maximum open files
#endif
#endif

#endif /* OS_H */
