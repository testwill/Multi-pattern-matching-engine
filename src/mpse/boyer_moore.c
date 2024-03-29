/* $Id$ */
/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>

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

/***************************************************************************
 *
 * File: MSTRING.C
 *
 * Purpose: Provide a variety of string functions not included in libc.  Makes
 *          up for the fact that the libstdc++ is hard to get reference
 *          material on and I don't want to write any more non-portable c++
 *          code until I have solid references and libraries to use.
 *
 * History:
 *
 * Date:      Author:  Notes:
 * ---------- ------- ----------------------------------------------
 *  08/19/98    MFR    Initial coding begun
 *  03/06/99    MFR    Added Boyer-Moore pattern match routine, don't use
 *                     mContainsSubstr() any more if you don't have to
 *  12/31/99	JGW    Added a full Boyer-Moore implementation to increase
 *                     performance. Added a case insensitive version of mSearch
 *  07/24/01    MFR    Fixed Regex pattern matcher introduced by Fyodor
 *
 **************************************************************************/
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>

#include "boyer_moore.h"
#include "sf_types.h"
#include "util.h"

static char * mSplitAddTok(const char *, const int, const char *, const char);

#ifdef TEST_MSTRING

int main()
{
    char test[] = "\0\0\0\0\0\0\0\0\0CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0";
    char find[] = "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0";

/*   char test[] = "\x90\x90\x90\x90\x90\x90\xe8\xc0\xff\xff\xff/bin/sh\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
     char find[] = "\xe8\xc0\xff\xff\xff/bin/sh";  */
    int i;
    int toks;
    int *shift;
    int *skip;

/*   shift=make_shift(find,sizeof(find)-1);
     skip=make_skip(find,sizeof(find)-1); */

    return 0;
}

#endif

/****************************************************************
 *
 * Function: mSplit()
 *
 * Purpose: Splits a string into tokens non-destructively.
 *
 * Parameters:
 *  char *
 *      The string to be split
 *  char *
 *      A string of token seperaters
 *  int
 *      The maximum number of tokens to be returned. A value
 *      of 0 means to get them all.
 *  int *
 *      Place to store the number of tokens returned
 *  char
 *      The "escape metacharacter", treat the character after
 *      this character as a literal and "escape" a separator.
 *
 *  Note if max_toks is reached, the last tok in the returned
 *  token array will possibly have separator characters in it.
 *
 *  Returns:
 *      2D char array with one token per "row" of the returned
 *      array.
 *
 ****************************************************************/
char ** mSplit(const char *str, const char *sep_chars, const int max_toks,
               int *num_toks, const char meta_char)
{
    size_t cur_tok = 0;  /* current token index into array of strings */
    size_t tok_start;    /* index to start of token */
    size_t i, j;
    int escaped = 0;
    /* It's rare we'll need more than this even if max_toks is set really
     * high.  Store toks here until finished, then allocate.  If more than
     * this is necessary, then allocate max toks */
    char *toks_buf[TOKS_BUF_SIZE];
    size_t toks_buf_size = TOKS_BUF_SIZE;
    int toks_buf_size_increment = 10;
    char **toks_alloc = NULL;   /* Used if the static buf isn't enough */
    char **toks = toks_buf;     /* Pointer to one of the two above */
    char **retstr;
    char *whitespace = " \t";

    if (num_toks == NULL)
        return NULL;

    *num_toks = 0;

    if ((str == NULL) || (strlen(str) == 0) ||
        ((sep_chars != NULL) && (strlen(sep_chars) == 0)))
    {
        return NULL;
    }

    if (sep_chars == NULL)
        sep_chars = whitespace;

    /* Meta char cannot also be a separator char */
    for (i = 0; i < strlen(sep_chars); i++)
    {
        if (sep_chars[i] == meta_char)
            return NULL;
    }

    /* Move past initial separator characters and whitespace */
    for (i = 0; i < strlen(str); i++)
    {
        for (j = 0; j < strlen(sep_chars); j++)
        {
            if ((str[i] == sep_chars[j]) ||
                isspace((int)str[i]))
            {
                break;
            }
        }

        /* Not a separator character or whitespace */
        if (j == strlen(sep_chars))
            break;
    }

    if (i == strlen(str))
    {
        /* Nothing but separator characters or whitespace in string */
        return NULL;
    }

    /* User only wanted one tok so return the rest of the string in
     * one tok */
    if ((cur_tok + 1) == (size_t)max_toks)
    {
        retstr = (char **) SnortAlloc(sizeof(char *));
        retstr[cur_tok] = SnortStrndup(&str[i], (size_t)(strlen(str) - i));
        if (retstr[cur_tok] == NULL)
        {
            mSplitFree(&retstr, cur_tok + 1);
            return NULL;
        }

        *num_toks = cur_tok + 1;
        return retstr;
    }

    /* Mark the beginning of the next tok */
    tok_start = i;
    for (; i < strlen(str); i++)
    {
        if (!escaped)
        {
            /* Got an escape character.  Don't include it now, but
             * must be a character after it. */
            if (str[i] == meta_char)
            {
                escaped = 1;
                continue;
            }

            /* See if the current character is a separator */
            for (j = 0; j < strlen(sep_chars); j++)
            {
                if (str[i] == sep_chars[j])
                    break;
            }

            /* It's a normal character */
            if (j == strlen(sep_chars))
                continue;

            /* Current character matched a separator character.  Trim off
             * whitespace previous to the separator.  If we get here, there
             * is at least one savable character */
            for (j = i; j > tok_start; j--)
            {
                if (!isspace((int)str[j - 1]))
                    break;
            }

            /* Allocate a buffer.  The length will not have included the
             * meta char of escaped separators */
            toks[cur_tok] = mSplitAddTok(&str[tok_start], j - tok_start, sep_chars, meta_char);

            /* Increment current token index */
            cur_tok++;

            /* Move past any more separator characters or whitespace */
            for (; i < strlen(str); i++)
            {
                for (j = 0; j < strlen(sep_chars); j++)
                {
                    if ((str[i] == sep_chars[j]) ||
                        isspace((int)str[i]))
                    {
                        break;
                    }
                }

                /* Not a separator character or whitespace */
                if (j == strlen(sep_chars))
                    break;
            }

            /* Nothing but separator characters or whitespace left in the string */
            if (i == strlen(str))
            {
                *num_toks = cur_tok;

                if (toks != toks_alloc)
                {
                    retstr = (char **) SnortAlloc(sizeof(char *) * cur_tok);
                    memcpy(retstr, toks, (sizeof(char *) * cur_tok));
                }
                else
                {
                    retstr = toks;
                }

                return retstr;
            }

            /* Reached the size of our current string buffer and need to
             * allocate something bigger.  Only get here once if max toks
             * set to something other than 0 because we'll just allocate
             * max toks in that case. */
            if (cur_tok == toks_buf_size)
            {
                char **tmp;

                if (toks_alloc != NULL)
                    tmp = toks_alloc;
                else
                    tmp = toks_buf;

                if (max_toks != 0)
                    toks_buf_size = max_toks;
                else
                    toks_buf_size = cur_tok + toks_buf_size_increment;

                toks_alloc = (char **) SnortAlloc(sizeof(char *) * toks_buf_size);
                memcpy(toks_alloc, tmp, (sizeof(char *) * cur_tok));
                toks = toks_alloc;

                if (tmp != toks_buf)
                    free(tmp);
            }

            if ((max_toks != 0) && ((cur_tok + 1) == (size_t)max_toks))
            {
                /* Return rest of string as last tok */
                *num_toks = cur_tok + 1;

                /* Already got a ret string */
                if (toks != toks_alloc)
                {
                    retstr = (char **) SnortAlloc(sizeof(char *) * (cur_tok + 1));
                    memcpy(retstr, toks, (sizeof(char *) * (cur_tok + 1)));
                }
                else
                {
                    retstr = toks;
                }

                /* Trim whitespace at end of last tok */
                for (j = strlen(str); j > tok_start; j--)
                {
                    if (!isspace((int)str[j - 1]))
                        break;
                }

                retstr[cur_tok] = SnortStrndup(&str[i], j - i);
                if (retstr[cur_tok] == NULL)
                {
                    mSplitFree(&retstr, cur_tok + 1);
                    return NULL;
                }

                return retstr;
            }

            tok_start = i;
        }
        else
        {
            /* This character is escaped with the meta char */
            escaped = 0;
        }
    }

    /* Last character was an escape character */
    if (escaped)
    {
        for (i = 0; i < cur_tok; i++)
            free(toks[i]);

        if (toks == toks_alloc)
            free(toks_alloc);

        return NULL;
    }

    /* Trim whitespace at end of last tok */
    for (j = i; j > tok_start; j--)
    {
        if (!isspace((int)str[j - 1]))
            break;
    }

    /* Last character was not a separator character so we've got
     * one more tok.  Unescape escaped sepatator characters */
    if (toks != toks_alloc)
    {
        retstr = (char **) SnortAlloc(sizeof(char *) * (cur_tok + 1));
        memcpy(retstr, toks, (sizeof(char *) * (cur_tok + 1)));
    }
    else
    {
        retstr = toks;
    }

    retstr[cur_tok] = mSplitAddTok(&str[tok_start], j - tok_start, sep_chars, meta_char);

    /* Just add one to cur_tok index instead of incrementing
     * since we're done */
    *num_toks = cur_tok + 1;
    return retstr;
}

/* Will not return NULL.  SnortAlloc will fatal if it fails */
static char * mSplitAddTok(const char *str, const int len, const char *sep_chars, const char meta_char)
{
    size_t i, j, k;
    char *tok;
    int tok_len = 0;
    int got_meta = 0;

    /* Get the length of the returned tok
     * Could have a maximum token length and use a fixed sized array and
     * fill it in as we go but don't want to put on that constraint */
    for (i = 0; (int)i < len; i++)
    {
        if (!got_meta)
        {
            if (str[i] == meta_char)
            {
                got_meta = 1;
                continue;
            }
        }
        else
        {
            /* See if the current character is a separator */
            for (j = 0; j < strlen(sep_chars); j++)
            {
                if (str[i] == sep_chars[j])
                    break;
            }

            /* It's a non-separator character, so include
             * the meta character in the return tok */
            if (j == strlen(sep_chars))
                tok_len++;

            got_meta = 0;
        }

        tok_len++;
    }

    /* Allocate it and fill it in */
    tok = (char *)SnortAlloc(tok_len + 1);
    for (i = 0, k = 0; (int)i < len; i++)
    {
        if (!got_meta)
        {
            if (str[i] == meta_char)
            {
                got_meta = 1;
                continue;
            }
        }
        else
        {
            /* See if the current character is a separator */
            for (j = 0; j < strlen(sep_chars); j++)
            {
                if (str[i] == sep_chars[j])
                    break;
            }

            /* It's a non-separator character, so include
             * the meta character in the return tok */
            if (j == strlen(sep_chars))
                tok[k++] = meta_char;

            got_meta = 0;
        }

        tok[k++] = str[i];
    }

    return tok;
}

/****************************************************************
 *
 * Free the buffer allocated by mSplit().
 *
 * char** toks = NULL;
 * int num_toks = 0;
 * toks = (str, " ", 2, &num_toks, 0);
 * mSplitFree(&toks, num_toks);
 *
 * At this point, toks is again NULL.
 *
 ****************************************************************/
void mSplitFree(char ***pbuf, int num_toks)
{
    int i;
    char** buf;  /* array of string pointers */

    if( pbuf==NULL || *pbuf==NULL )
    {
        return;
    }

    buf = *pbuf;

    for( i=0; i<num_toks; i++ )
    {
        if( buf[i] != NULL )
        {
            free( buf[i] );
            buf[i] = NULL;
        }
    }

    free(buf);
    *pbuf = NULL;
}

/****************************************************************
 *
 *  Function: mContainsSubstr(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      b_len => data buffer length
 *      pat => pattern to find
 *      p_len => length of the data in the pattern buffer
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
int mContainsSubstr(const char *buf, int b_len, const char *pat, int p_len)
{
    const char *b_idx;  /* index ptr into the data buffer */
    const char *p_idx;  /* index ptr into the pattern buffer */
    const char *b_end;  /* ptr to the end of the data buffer */
    int m_cnt = 0;      /* number of pattern matches so far... */

    /* mark the end of the strs */
    b_end = (char *) (buf + b_len);

    /* init the index ptrs */
    b_idx = buf;
    p_idx = pat;

    do
    {

        if(*p_idx == *b_idx)
        {

            if(m_cnt == (p_len - 1))
            {
                return 1;
            }
            m_cnt++;
            b_idx++;
            p_idx++;
        }
        else
        {
            if(m_cnt == 0)
            {
                b_idx++;
            }
            else
            {
                b_idx = b_idx - (m_cnt - 1);
            }

            p_idx = pat;

            m_cnt = 0;
        }

    } while(b_idx < b_end);


    /* if we make it here we didn't find what we were looking for */
    return 0;
}


/**
 * \brief Setup a Booyer Moore context.
 *
 * \param str pointer to the pattern string
 * \param size length of the string
 * \retval BmCtx pointer to the newly created Context for the pattern
 * \initonly BoyerMoore contexts should be created at init
 */
bm_context *boyer_moore_cxt_init(char *needle, size_t needle_len, int nocase)
{
    bm_context *idx = SnortAlloc(sizeof(bm_context));
    if (idx == NULL) {
		FatalError("Fatal error encountered in boyer_moore_cxt_init. Exiting...");
        exit(EXIT_FAILURE);
    }

    if(idx->skip_stride)
       free(idx->skip_stride);
    if(idx->shift_stride)
       free(idx->shift_stride);

    if (idx->pattern_buf)
       free(idx->pattern_buf);

    unsigned int i;

    if (nocase == 1) {
        for (i = 0; i < needle_len; i++)
            needle[i] = toupper((int)needle[i]);
    }

    idx->nocase = nocase;
    idx->pattern_buf = SnortStrdup(needle);
    idx->pattern_size = needle_len;

    idx->skip_stride = make_skip(needle, needle_len);

    idx->shift_stride = make_shift(needle, needle_len);
    return idx;
}


void boyer_moore_cxt_free(void * ptr)
{
    bm_context *ctx = (bm_context *)ptr;

    if (ctx == NULL)
        return;

    if (ctx->pattern_buf)
        free(ctx->pattern_buf);
    if(ctx->skip_stride)
        free(ctx->skip_stride);
    if(ctx->shift_stride)
        free(ctx->shift_stride);

    free(ctx);

}

/****************************************************************
 *
 *  Function: make_skip(char *, int)
 *
 *  Purpose: Create a Boyer-Moore skip table for a given pattern
 *
 *  Parameters:
 *      ptrn => pattern
 *      plen => length of the data in the pattern buffer
 *
 *  Returns:
 *      int * - the skip table
 *
 ****************************************************************/
int *make_skip(char *ptrn, int plen)
{
    int  i;
    int *skip = (int *)  SnortAlloc(256* sizeof(int));

    for ( i = 0; i < 256; i++ )
        skip[i] = plen + 1;

    while(plen != 0)
        skip[(unsigned char) *ptrn++] = plen--;

    return skip;
}



/****************************************************************
 *
 *  Function: make_shift(char *, int)
 *
 *  Purpose: Create a Boyer-Moore shift table for a given pattern
 *
 *  Parameters:
 *      ptrn => pattern
 *      plen => length of the data in the pattern buffer
 *
 *  Returns:
 *      int * - the shift table
 *
 ****************************************************************/
int *make_shift(char *ptrn, int plen)
{
    int *shift = (int *)  SnortAlloc(plen * sizeof(int));
    int *sptr = shift + plen - 1;
    char *pptr = ptrn + plen - 1;
    char c;

     c = ptrn[plen - 1];

    *sptr = 1;

    while(sptr-- != shift)
    {
        char *p1 = ptrn + plen - 2, *p2, *p3;

        do
        {
            while(p1 >= ptrn && *p1-- != c);

            p2 = ptrn + plen - 2;
            p3 = p1;

            while(p3 >= ptrn && *p3-- == *p2-- && p2 >= pptr);
        }
        while(p3 >= ptrn && p2 >= pptr);

        *sptr = shift + plen - sptr + p2 - p3;

        pptr--;
    }

    return shift;
}

/****************************************************************
 *
 *  Function: mSearch(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
int mSearch(const char *buf, int blen, const char *ptrn, int plen, int *skip, int *shift)
{
    int b_idx = plen;

    if(plen == 0)
        return 1;

    while(b_idx <= blen)
    {
        int p_idx = plen, skip_stride, shift_stride;

        while(buf[--b_idx] == ptrn[--p_idx])
        {
            if(b_idx < 0)
                return 0;

            if(p_idx == 0)
            {
                UpdateDoePtr(((const uint8_t *)&(buf[b_idx]) + plen), 0);
                return 1;
            }
        }

        skip_stride = skip[(unsigned char) buf[b_idx]];
        shift_stride = shift[p_idx];

        b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
    }

    return 0;
}



/****************************************************************
 *
 *  Function: mSearchCI(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring matching is case insensitive
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
int mSearchCI(const char *buf, int blen, const char *ptrn, int plen, int *skip, int *shift)
{
    int b_idx = plen;

    if(plen == 0)
        return 1;

    while(b_idx <= blen)
    {
        int p_idx = plen, skip_stride, shift_stride;

        while((unsigned char) ptrn[--p_idx] ==
                toupper((unsigned char) buf[--b_idx]))
        {
            if(p_idx == 0)
            {

                UpdateDoePtr(((const uint8_t *)&(buf[b_idx]) + plen), 0);
                return 1;
            }
        }

        skip_stride = skip[toupper((unsigned char) buf[b_idx])];
        shift_stride = shift[p_idx];

        b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
    }

    return 0;
}


/****************************************************************
 *
 *  Function: mSearchREG(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
int mSearchREG(const char *buf, int blen, const char *ptrn, int plen, int *skip, int *shift)
{
    int b_idx = plen;
    int literal = 0;
    int regexcomp = 0;


    if(plen == 0)
        return 1;

    while(b_idx <= blen)
    {
        int p_idx = plen, skip_stride, shift_stride;

        while(buf[--b_idx] == ptrn[--p_idx]
              || (ptrn[p_idx] == '?' && !literal)
              || (ptrn[p_idx] == '*' && !literal)
              || (ptrn[p_idx] == '\\' && !literal))
        {
            if(literal)
                literal = 0;
            if(!literal && ptrn[p_idx] == '\\')
                literal = 1;
            if(ptrn[p_idx] == '*')
            {
                while(p_idx != 0 && ptrn[--p_idx] == '*'); /* fool-proof */

                while(buf[--b_idx] != ptrn[p_idx])
                {
                   regexcomp++;
                    if(b_idx == 0)
                    {
                        return 0;
                    }
                }
            }

            if(p_idx == 0)
            {
                return 1;
            }

            if(b_idx == 0)
                break;
        }

    skip_stride = skip[(unsigned char) buf[b_idx]];
    shift_stride = shift[p_idx];

    b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
    b_idx += regexcomp;
    regexcomp = 0;
    }


    return 0;
}


/****************************************************************
 *
 *  Function: mSearch2(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
int mSearch2(const char *buf, int blen, const char *ptrn, int plen, int *skip, int *shift,  char **doe)
{
    int b_idx = plen;

    if(plen == 0)
        return 1;

    while(b_idx <= blen)
    {
        int p_idx = plen, skip_stride, shift_stride;

        while(buf[--b_idx] == ptrn[--p_idx])
        {
            if(b_idx < 0)
                return 0;

            if(p_idx == 0)
            {
                if (doe) 
                {
                    *doe = ((char *)&(buf[b_idx]) + plen);
                }
                return 1;
            }
        }

        skip_stride = skip[(unsigned char) buf[b_idx]];
        shift_stride = shift[p_idx];

        b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
    }

    return 0;
}



/****************************************************************
 *
 *  Function: mSearchCI2(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring matching is case insensitive
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
int mSearchCI2(const char *buf, int blen, const char *ptrn, int plen, int *skip, int *shift, char **doe)
{
    int b_idx = plen;

    if(plen == 0)
        return 1;

    while(b_idx <= blen)
    {
        int p_idx = plen, skip_stride, shift_stride;

        while((unsigned char) ptrn[--p_idx] ==
                toupper((unsigned char) buf[--b_idx]))
        {
            if(p_idx == 0)
            {
                if (doe) 
                {
                    *doe = ((char *)&(buf[b_idx]) + plen);
                }
                return 1;
            }
        }

        skip_stride = skip[toupper((unsigned char) buf[b_idx])];
        shift_stride = shift[p_idx];

        b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
    }

    return 0;
}

int pattern_search(const char *buf, int blen, bm_context * bm_cxt, char **doe)
{
    int success = 0;

    if (bm_cxt == NULL) {
        return success;
    }

    if (bm_cxt->nocase) {
        success = mSearchCI2(buf, blen, bm_cxt->pattern_buf, bm_cxt->pattern_size, bm_cxt->skip_stride, bm_cxt->shift_stride, doe);
    } else {
        success = mSearch2(buf, blen, bm_cxt->pattern_buf, bm_cxt->pattern_size, bm_cxt->skip_stride, bm_cxt->shift_stride, doe);
    }

    return success;
}
