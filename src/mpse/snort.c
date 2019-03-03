/* $Id$ */
/*
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

/*
 *
 * Program: Snort
 *
 * Purpose: Check out the README file for info on what you can do
 *          with Snort.
 *
 * Author: Martin Roesch (roesch@clark.net)
 *
 * Comments: Ideas and code stolen liberally from Mike Borella's IP Grab
 *           program. Check out his stuff at http://www.borella.net.  I
 *           also have ripped some util functions from TCPdump, plus Mike's
 *           prog is derived from it as well.  All hail TCPdump....
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>

#ifndef WIN32
#include <netdb.h>
#else
#include <Iphlpapi.h>
#endif

#ifdef HAVE_GETOPT_LONG
//#define _GNU_SOURCE
/* A GPL copy of getopt & getopt_long src code is now in sfutil */
# undef HAVE_GETOPT_LONG
#endif
#include <getopt.h>

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif

#ifndef WIN32
# include <grp.h>
# include <pwd.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
#endif  /* !WIN32 */

#if !defined(CATCH_SEGV) && !defined(WIN32)
# include <sys/resource.h>
#endif

#include"snort.h"


SnortConfig *snort_conf = NULL;

