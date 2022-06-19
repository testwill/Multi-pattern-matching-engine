#ifndef HYPERSCAN_H
#define HYPERSCAN_H

#include <hs/hs_compile.h>
#include <hs/hs_runtime.h>

typedef struct Pattern
{
    unsigned char         *patrn;
    int      n;
    int      nocase;
    int      offset;
    int      depth;
	int id ;
	int negate;
    unsigned flags;
    void* user;
    void* user_tree;
    void* user_list;

	struct Pattern * next;
}HSSM_PATTERN;


/*
* hs machine Struct
*/
typedef struct {

    hs_database_t* hs_db;
	
	HSSM_PATTERN *hsPatterns;

    int numPatterns;
    void (*userfree)(void *p);
    void (*optiontreefree)(void **p);
    void (*neg_list_free)(void **p);

}HSSM_STRUCT;



typedef int (* MpseMatch)(void* user, void* tree, int index, void* context, void* list);


typedef struct 
{
    HSSM_STRUCT* mpse;
    MpseMatch match_cb;
    void* match_ctx;
    int nfound ;

}ScanContext;


HSSM_STRUCT *hssmNew (void (*userfree)(void *p),
                       void (*optiontreefree)(void **p),
                       void (*neg_list_free)(void **p));

void hssmFree(HSSM_STRUCT * hssm);

int hssmAddPattern (HSSM_STRUCT * p, unsigned char *pat, int n, int nocase,
            int offset, int depth, int negative, void * id, int iid);

int hssmCompile (HSSM_STRUCT * hssm,
             int (*build_tree)(void * id, void **existing_tree),
             int (*neg_list_func)(void *id, void **list));

int hssmSearch(HSSM_STRUCT* hssm, unsigned char *Tx, int n,
           int (*Match)(void * id, void *tree, int index, void *data, void *neg_list),
           void *data);

#endif

