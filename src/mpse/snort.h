#ifndef __SNORT_H__
#define __SNORT_H__
#include "sf_types.h"

typedef struct _SnortConfig
{
    int logging_flags;

    unsigned int max_inq;
    uint64_t tot_inq_flush;
    uint64_t tot_inq_inserts;
    uint64_t tot_inq_uinserts;

} SnortConfig;

typedef enum _LoggingFlag
{
    LOGGING_FLAG__VERBOSE         = 0x00000001,      /* -v */
    LOGGING_FLAG__QUIET           = 0x00000002,      /* -q */
    LOGGING_FLAG__SYSLOG          = 0x00000004       /* -M */
#ifdef WIN32
   ,LOGGING_FLAG__SYSLOG_REMOTE   = 0x00000008       /* -s and -E */
#endif

} LoggingFlag;

extern SnortConfig *snort_conf;

static inline int ScLogSyslog(void)
{
    return snort_conf->logging_flags & LOGGING_FLAG__SYSLOG;
}



#endif
