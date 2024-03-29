/* $Id$ */
/*
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/


#ifndef __UTIL_H__
#define __UTIL_H__

#define TIMEBUF_SIZE 26

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef WIN32
# include <sys/time.h>
# include <sys/types.h>
# ifdef LINUX
#  include <sys/syscall.h>
# endif
#endif
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <string.h>
#include <ctype.h>

#include "sf_types.h"
#include "sflsq.h"
/* Macros *********************************************************************/

/* specifies that a function does not return
 * used for quieting Visual Studio warnings */
#ifdef _MSC_VER
# if _MSC_VER >= 1400
#  define NORETURN __declspec(noreturn)
# else
#  define NORETURN
# endif
#else
# define NORETURN
#endif

#if !defined(__GNUC__) || __GNUC__ < 2 || \
    (__GNUC__ == 2 && __GNUC_MINOR__ < 5)
#define	__attribute__(x)	/* delete __attribute__ if non-gcc or gcc1 */
#endif

#define SNORT_SNPRINTF_SUCCESS 0
#define SNORT_SNPRINTF_TRUNCATION 1
#define SNORT_SNPRINTF_ERROR -1

#define SNORT_STRNCPY_SUCCESS 0
#define SNORT_STRNCPY_TRUNCATION 1
#define SNORT_STRNCPY_ERROR -1

#define SNORT_STRNLEN_ERROR -1

#define SECONDS_PER_DAY  86400  /* number of seconds in a day  */
#define SECONDS_PER_HOUR  3600  /* number of seconds in a hour */
#define SECONDS_PER_MIN     60     /* number of seconds in a minute */

#define STD_BUF  1024

#define COPY4(x, y) \
    x[0] = y[0]; x[1] = y[1]; x[2] = y[2]; x[3] = y[3];

#define COPY16(x,y) \
    x[0] = y[0]; x[1] = y[1]; x[2] = y[2]; x[3] = y[3]; \
    x[4] = y[4]; x[5] = y[5]; x[6] = y[6]; x[7] = y[7]; \
    x[8] = y[8]; x[9] = y[9]; x[10] = y[10]; x[11] = y[11]; \
    x[12] = y[12]; x[13] = y[13]; x[14] = y[14]; x[15] = y[15];



#define DOE_BUF_URI     0x01
#define DOE_BUF_STD     0x02

/* Externs ********************************************************************/
extern uint32_t *netmasks;


/* Data types *****************************************************************/

/* Self preservation memory control struct */
typedef struct _SPMemControl
{
    unsigned long memcap;
    unsigned long mem_usage;
    void *control;
    int (*sp_func)(struct _SPMemControl *);

    unsigned long fault_count;

} SPMemControl;


extern uint8_t doe_buf_flags;
extern const uint8_t *doe_ptr;

extern uint16_t detect_flags;


/* Public function prototypes *************************************************/
void StoreSnortInfoStrings(void);
void GetTime(char *);
int gmt2local(time_t);
char *copy_argv(char **);
void strip(char *);
double CalcPct(uint64_t, uint64_t);
void ReadPacketsFromFile(void);
void InitBinFrag(void);
void GoDaemon(void);
void SignalWaitingParent(void);
char *read_infile(char *);
void ClosePidFile(void);
void InitGroups(int, int);
void SetChroot(char *, char **);
void DropStats(int);
void *SPAlloc(unsigned long, struct _SPMemControl *);
#ifndef __GNUC__
#define __attribute__(x)  /*NOTHING*/
#endif
void LogMessage(const char *, ...) __attribute__((format (printf, 1, 2)));
void WarningMessage(const char *, ...) __attribute__((format (printf, 1, 2)));
void ErrorMessage(const char *, ...) __attribute__((format (printf, 1, 2)));
typedef struct _ThrottleInfo
{
    time_t lastUpdate;
    /*Within this duration (in seconds), maximal one distinct message is logged*/
    uint32_t duration_to_log;
    uint64_t count;
}ThrottleInfo;

NORETURN void FatalError(const char *, ...) __attribute__((format (printf, 1, 2)));
int SnortSnprintf(char *, size_t, const char *, ...) __attribute__((format (printf, 3, 4)));
int SnortSnprintfAppend(char *, size_t, const char *, ...) __attribute__((format (printf, 3, 4)));

char *SnortStrdup(const char *);
int SnortStrncpy(char *, const char *, size_t);
char *SnortStrndup(const char *, size_t);
int SnortStrnlen(const char *, int);
const char *SnortStrnPbrk(const char *s, int slen, const char *accept);
const char *SnortStrnStr(const char *s, int slen, const char *searchstr);
const char *SnortStrcasestr(const char *s, int slen, const char *substr);

void *SnortAlloc(unsigned long);
void *SnortAlloc2(size_t, const char *, ...);
char *CurrentWorkingDir(void);
char *GetAbsolutePath(char *dir);
char *StripPrefixDir(char *prefix, char *dir);
void PrintPacketData(const uint8_t *, const uint32_t);


void TimeStats(void);

#ifndef WIN32
SF_LIST * SortDirectory(const char *);
int GetFilesUnderDir(const char *, SF_QUEUE *, const char *);
#endif

/***********************************************************
 If you use any of the functions in this section, you need
 to call free() on the char * that is returned after you are
 done using it. Otherwise, you will have created a memory
 leak.
***********************************************************/
char *hex(const u_char *, int);
char *fasthex(const u_char *, int);
long int xatol(const char *, const char *);
unsigned long int xatou(const char *, const char *);
unsigned long int xatoup(const char *, const char *); // return > 0

static inline long SnortStrtol(const char *nptr, char **endptr, int base)
{
    long iRet;
    errno = 0;
    iRet = strtol(nptr, endptr, base);

    return iRet;
}

static inline unsigned long SnortStrtoul(const char *nptr, char **endptr, int base)
{
        unsigned long iRet;
        errno = 0;
        iRet = strtoul(nptr, endptr, base);

        return iRet;
}

// Checks to make sure we're not going to evaluate a negative number for which
// strtoul() gladly accepts and parses returning an underflowed wrapped unsigned
// long without error.
//
// Buffer passed in MUST be NULL terminated.
//
// Returns
//  int
//    -1 if buffer is nothing but spaces or first non-space character is a
//       negative sign.  Also if errno is EINVAL (which may be due to a bad
//       base) or there was nothing to convert.
//     0 on success
//
// Populates pointer to uint32_t value passed in which should
// only be used on a successful return from this function.
//
// Also will set errno to ERANGE on a value returned from strtoul that is
// greater than UINT32_MAX, but still return success.
//
static inline int SnortStrToU32(const char *buffer, char **endptr,
        uint32_t *value, int base)
{
    unsigned long int tmp;

    if ((buffer == NULL) || (endptr == NULL) || (value == NULL))
        return -1;

    // Only positive numbers should be processed and strtoul will
    // eat up white space and process '-' and '+' so move past
    // white space and check for a negative sign.
    while (isspace((int)*buffer))
        buffer++;

    // If all spaces or a negative sign is found, return error.
    // XXX May also want to exclude '+' as well.
    if ((*buffer == '\0') || (*buffer == '-'))
        return -1;

    tmp = SnortStrtoul(buffer, endptr, base);

    // The user of the function should check for ERANGE in errno since this
    // function can be used such that an ERANGE error is acceptable and
    // value gets truncated to UINT32_MAX.
    if ((errno == EINVAL) || (*endptr == buffer))
        return -1;

    // If value is greater than a UINT32_MAX set value to UINT32_MAX
    // and errno to ERANGE
    if (tmp > UINT32_MAX)
    {
        tmp = UINT32_MAX;
        errno = ERANGE;
    }

    *value = (uint32_t)tmp;

    return 0;
}

static inline long SnortStrtolRange(const char *nptr, char **endptr, int base, long lo, long hi)
{
    long iRet = SnortStrtol(nptr, endptr, base);
    if ((iRet > hi) || (iRet < lo))
        *endptr = (char *)nptr;

    return iRet;
}

static inline unsigned long SnortStrtoulRange(const char *nptr, char **endptr, int base, unsigned long lo, unsigned long hi)
{
    unsigned long iRet = SnortStrtoul(nptr, endptr, base);
    if ((iRet > hi) || (iRet < lo))
        *endptr = (char *)nptr;

    return iRet;
}

static inline int IsEmptyStr(const char *str)
{
    const char *end;

    if (str == NULL)
        return 1;

    end = str + strlen(str);

    while ((str < end) && isspace((int)*str))
        str++;

    if (str == end)
        return 1;

    return 0;
}


static inline void UpdateDoePtr(const uint8_t *ptr, uint8_t update)
{
    doe_ptr = ptr;
    if(update)
        doe_buf_flags = DOE_BUF_STD;
}

#endif /*__UTIL_H__*/
