#include <stdint.h>
#include <stdio.h>

#include "mpse/mpse.h"
#include "mpse/str_search.h"
#include "mpse/util.h"

typedef struct _SearchToken               
{   
    char *name;
    int   name_len;
    int   search_id;
} SearchToken;

typedef struct _SearchInfo
{
    int id;
    int index;
    int length;
} SearchInfo;

typedef enum _HtmlSearchIdEnum
{
    HTML_JS = 0,
    HTML_EMA,
    HTML_VB,
    HTML_LAST
} HtmlSearchId;

typedef struct Search
{
    char *name;
    int   name_len;

} Search;


const SearchToken patterns[] =
{
    {"JAVASCRIPT",      10, HTML_JS},
    {"ECMASCRIPT",      10, HTML_EMA},
    {"VBSCRIPT",         8, HTML_VB},
    {NULL,               0, 0}
};

void *hi_htmltype_search_mpse = NULL;
Search search[HTML_LAST];
Search *current_search = NULL;

SearchInfo search_info;

void TestSearchInit(void)
{
    const SearchToken *tmp;

    hi_htmltype_search_mpse = search_api->search_instance_new();
    if (hi_htmltype_search_mpse == NULL)
    {
        FatalError("%s(%d) Could not allocate memory for HTTP <script> type search.\n",
                                   __FILE__, __LINE__);
    } 
    for (tmp = &patterns[0]; tmp->name != NULL; tmp++)
    {
        search[tmp->search_id].name = tmp->name;
        search[tmp->search_id].name_len = tmp->name_len;
        search_api->search_instance_add(hi_htmltype_search_mpse, tmp->name, tmp->name_len, tmp->search_id);
    }
    search_api->search_instance_prep(hi_htmltype_search_mpse);
}

void TestSearchFree(void)
{
    if (hi_htmltype_search_mpse != NULL)
        search_api->search_instance_free(hi_htmltype_search_mpse);
}

int TestSearchStrFound(void *id, void *unused, int index, void *data, void *unused2)
{
    int search_id = (int)(uintptr_t)id;

    search_info.id = search_id;
    search_info.index = index;
    search_info.length = current_search[search_id].name_len;

     printf("id :%d, index :%d\n", search_id, index);
    /* Returning non-zero stops search, which is okay since we only look for one at a time */
    return 1;
}

int main( int argc, char ** argv )
{
    if (argc < 2) {
        printf("usage : ./a.out source_str\n");
        return -1;
    }

    TestSearchInit();

    size_t source_len = strlen(argv[1]);

    int script_found;
    current_search = &search[0];

    script_found = search_api->search_instance_find(hi_htmltype_search_mpse, (const char *)argv[1],
                                               source_len, 0 , TestSearchStrFound); 
    if (script_found) {
        printf("found :%s\n", current_search[search_info.id].name);
    } else {
        printf("not found\n");
    }

    TestSearchFree();

    return 0;
}

