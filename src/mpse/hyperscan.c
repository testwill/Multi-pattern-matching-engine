#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hyperscan.h"
#include "util.h"
#include "snort_debug.h"

#define MEMASSERT(p,s) if(!p){fprintf(stderr,"HSSM-No Memory: %s!\n",s);exit(0);}


hs_scratch_t* s_scratch = NULL;

static int hs_match(unsigned int id, unsigned long long from,
                          unsigned long long to, unsigned int flags,
                          void *ctx);

/*static void Print_DFA( ACSM_STRUCT * acsm );*/

/*
*
*/
static void *
HS_MALLOC (int n)
{
  void *p;
  p = calloc (1,n);
#ifdef DEBUG_AC
  if (p)
    max_memory += n;
#endif
  return p;
}

/*
*
*/
static void
HS_FREE (void *p)
{
  if (p)
    free (p);
}

void hssmFree(HSSM_STRUCT * hssm)
{
    HSSM_PATTERN * mlist, *ilist;

    mlist = hssm->hsPatterns;
    while(mlist)
    {
        ilist = mlist;
        mlist = mlist->next;
        HS_FREE(ilist->patrn);
        HS_FREE(ilist);
    }

	hs_free_database(hssm->hs_db);
    HS_FREE (hssm);

}

/*
*
*/
HSSM_STRUCT *hssmNew (void (*userfree)(void *p),
                       void (*optiontreefree)(void **p),
                       void (*neg_list_free)(void **p))
{
  HSSM_STRUCT * p;
  p = (HSSM_STRUCT *) HS_MALLOC (sizeof (HSSM_STRUCT));
  MEMASSERT (p, "hsNew");
  if (p)
  {
    memset (p, 0, sizeof (HSSM_STRUCT));
    p->userfree              = userfree;
    p->optiontreefree        = optiontreefree;
    p->neg_list_free         = neg_list_free;
  }
  return p;
}

/*
*   Add a pattern to the list of patterns for hs
*/
int
hssmAddPattern (HSSM_STRUCT * p, unsigned char *pat, int n, int nocase,
            int offset, int depth, int negative, void * id, int iid)
{
  HSSM_PATTERN * plist;
  plist = (HSSM_PATTERN *) HS_MALLOC (sizeof (HSSM_PATTERN));
  MEMASSERT (plist, "hsAddPattern");
  plist->patrn = (unsigned char *) HS_MALLOC (n);

  memcpy(plist->patrn, pat, n);
  if ( nocase > 0 )
	  plist->flags |= HS_FLAG_CASELESS;

  plist->n = n;
  plist->nocase = nocase;
  plist->negate = negative;
  plist->offset = offset;
  plist->depth = depth;
  plist->next = p->hsPatterns;
  plist->id = iid;  
  plist->user_tree = plist->user_list = NULL;
  
  p->hsPatterns= plist;
  p->numPatterns++;
  
  return 0;
}


int
hssmCompile (HSSM_STRUCT * hssm,
             int (*build_tree)(void * id, void **existing_tree),
             int (*neg_list_func)(void *id, void **list))
{
    int rval = 0;
	int id = 0;
    unsigned *ids = HS_MALLOC(hssm->numPatterns * sizeof(unsigned));
    unsigned* flags = HS_MALLOC(hssm->numPatterns * sizeof(unsigned));
    const char** pats = HS_MALLOC(hssm->numPatterns * sizeof(const char *));
    HSSM_PATTERN * plist;
    hs_compile_error_t* errptr = NULL;
	hs_error_t err;
	if (hssm->hs_db) {
		
		return 0;

	}
	
    for (plist = hssm->hsPatterns; plist != NULL; plist = plist->next)
    {
    	pats[id] = plist->patrn;
		flags[id] = plist->flags;
		ids[id] = plist->id;
		id++;
    }

	printf("patten num :%d\n", hssm->numPatterns);

    if ( hs_compile_multi(pats, flags, ids, hssm->numPatterns, HS_MODE_BLOCK,
            NULL, &hssm->hs_db, &errptr) || !hssm->hs_db )
    {
        printf("can't compile hyperscan pattern database: %s (%d) - '%s'",
            errptr->message, errptr->expression,
            errptr->expression >= 0 ? pats[errptr->expression] : "");
        hs_free_compile_error(errptr);
        rval =  -2;
		goto __end;
    }
	
	printf("compile success\n");
	err = hs_alloc_scratch(hssm->hs_db, &s_scratch);

    if (err > 0)
    {
        printf("can't allocate search scratch space (%d)", err);
        rval =  -3;
		goto __end;
    }

__end:
	if ( NULL != ids) 
		HS_FREE(ids);
	if (NULL != flags)
		HS_FREE(flags);
	if (NULL != pats)
		HS_FREE(pats);
    return rval;
}


int initScanContext(ScanContext *sc, HSSM_STRUCT* m, MpseMatch cb, void* ctx)
{ 
    sc->mpse = m;
    sc->match_cb = cb;
    sc->match_ctx = ctx;
}

int hssmSearch(HSSM_STRUCT* hssm, unsigned char *Tx, int n,
           int (*Match)(void * id, void *tree, int index, void *data, void *neg_list),
           void *data)
{
    ScanContext scan;
	memset(&scan, 0 , sizeof(ScanContext));
	initScanContext(&scan, hssm, Match, data);

    hs_scratch_t* ss = s_scratch;

    // scratch is null for the degenerate case w/o patterns
    assert(!hssm->hs_db || ss);

    hs_scan(hssm->hs_db, (const char*)Tx, n, 0, ss, hs_match, &scan);
	
    return scan.nfound;
}


static int hs_match(unsigned int id, unsigned long long from,
                          unsigned long long to, unsigned int flags,
                          void *ctx)
{
    ScanContext* scan = (ScanContext*)ctx;
	scan->match_cb((void *)id, NULL, to, scan->match_ctx, NULL);
    scan->nfound++;
    return 1;
}


