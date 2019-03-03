#ifndef __WTM_UTIL_BM_H__
#define __WTM_UTIL_BM_H__

/*  I N C L U D E S  ******************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/*  D E F I N E S  *******************************************************/
#define TOKS_BUF_SIZE   100

#define SP_CASE 0
#define SP_NOCASE 1

typedef struct _bm_context{
    int nocase;             /* Toggle case insensitity */
    char *pattern_buf;      /* app layer pattern to match on */
    size_t pattern_size;     /* size of app layer pattern */
    int *skip_stride; /* B-M skip array */
    int *shift_stride; /* B-M shift array */
} bm_context;

/*  P R O T O T Y P E S  *************************************************/
char ** mSplit(const char *, const char *, const int, int *, const char);
void mSplitFree(char ***toks, int numtoks);
int mContainsSubstr(const char *, int, const char *, int);
int mSearch(const char *, int, const char *, int, int *, int *);
int mSearchCI(const char *, int, const char *, int, int *, int *);
int mSearchREG(const char *, int, const char *, int, int *, int *);
int *make_skip(char *, int);
int *make_shift(char *, int);
bm_context *boyer_moore_cxt_init(char  *needle, size_t needle_len, int nocase);
void boyer_moore_cxt_free(void * ptr);
int mSearch2(const char *buf, int blen, const char *ptrn, int plen, int *skip, int *shift, char **doe);
int mSearchCI2(const char *buf, int blen, const char *ptrn, int plen, int *skip, int *shift, char **doe);
int pattern_search(const char *buf, int blen, bm_context * bm_cxt, char **doe);

#endif
