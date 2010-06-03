/*
 * Copyright (C) 2008-2010 National Institute of Advanced Industrial Science and Technology
 *
 * Author: Takahiro Hirofuchi
 */
#ifndef LIB_COMMON_H
#define LIB_COMMON_H

/* automatically redefine fstat, lseek, and etc. for 64 bit */
#define _FILE_OFFSET_BITS 64
/* add for off64_t */
#define _LARGEFILE64_SOURCE

#define _GNU_SOURCE

#include <inttypes.h>

/* ---------------------------- */

#include <glib.h>
#include <pthread.h>

#define err(fmt, args...)	do { \
		g_error("(tid:0x%lx) (%-12s) " fmt, \
		pthread_self(), __FUNCTION__,  ##args); \
} while (0)

#define warn(fmt, args...)	do { \
		g_warning(fmt, ##args); \
} while (0)

#define info(fmt, args...)	do { \
		g_message(fmt, ##args); \
} while (0)


/* define dbg() */
#ifdef XNBD_DEBUG

#define dbg(fmt, args...)	do { \
		g_debug("(tid:0x%lx) (%-12s) " fmt, \
		pthread_self(), __FUNCTION__,  ##args); \
} while (0)

#else

#define dbg(fmt, args...)	do {;} while (0)

#endif





#ifndef XNBD_DEBUG
static inline void null_logger(const gchar *domain __attribute__((unused)),
		GLogLevelFlags level __attribute__((unused)),
		const gchar *message __attribute__((unused)),
		gpointer data __attribute__((unused)))
{ ; }
#endif
// void null_logger(const gchar *domain __attribute__((unused)),
// 		GLogLevelFlags level __attribute__((unused)),
// 		const gchar *message __attribute__((unused)),
// 		gpointer data __attribute__((unused)));

void xutil_log_handler(const gchar   *log_domain, GLogLevelFlags log_level,
		const gchar   *message, gpointer       data);

#endif


#if _FILE_OFFSET_BITS == 64
#define OFF_MAX INT64_MAX
#else
#define OFF_MAX INT32_MAX
#endif

