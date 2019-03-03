#include "mpse/boyer_moore.h"

typedef struct _PatternMatchData
{
    int nocase;             /* Toggle case insensitity */

    int pattern_size;       /* size of app layer pattern */
    char *pattern_buf;      /* app layer pattern to match on */
    int (*search) (char *, int, struct _PatternMatchData *);  /* search function */
    int *skip_stride;       /* B-M skip array */
    int *shift_stride;      /* B-M shift array */

} PatternMatchData;

static void make_precomp(PatternMatchData * idx)
{
    if(idx->skip_stride)
       free(idx->skip_stride);
    if(idx->shift_stride)
       free(idx->shift_stride);

    idx->skip_stride = make_skip(idx->pattern_buf, idx->pattern_size);
    idx->shift_stride = make_shift(idx->pattern_buf, idx->pattern_size);
}

void PatternMatchFree(void *d)
{
    PatternMatchData *pmd = (PatternMatchData *)d;

    if (pmd == NULL)
        return;

    if (pmd->pattern_buf)
        free(pmd->pattern_buf);
    if(pmd->skip_stride)
        free(pmd->skip_stride);
    if(pmd->shift_stride)
        free(pmd->shift_stride);

    free(pmd);
}

int main( int argc, char ** argv )
{
    int pattenLen = 0;
    if (argc > 2) {
        pattenLen = strlen(argv[1]);
    } else {
        printf("usage : ./a.out patten source_str [case_sensitive(sensitive or insensitive)]\n");
        return -1;
    }

    int nocase = SP_NOCASE;
    if (argc > 3) {
        if (strcmp(argv[3], "sensitive") == 0) {
            nocase = SP_CASE;
        } else if(strcmp(argv[3], "insensitive") == 0){
            nocase = SP_NOCASE;
        } else {
            printf("usage : ./a.out patten source_str [case_sensitive(sensitive or insensitive)]\n");
            return -1;      
        }
    }

    bm_context * test_bm_ctx = boyer_moore_cxt_init(argv[1], pattenLen, nocase);

	if(pattern_search(argv[2], strlen(argv[2]), test_bm_ctx, NULL)){
        printf("found it :%s\n", argv[1]);
    } else {
        printf("not found it :%s\n", argv[1]);
    }

    boyer_moore_cxt_free(test_bm_ctx);
    return 0;
}
