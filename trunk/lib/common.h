/*
 * xNBD - an enhanced Network Block Device program
 *
 * Copyright (C) 2008-2013 National Institute of Advanced Industrial Science
 * and Technology
 *
 * Author: Takahiro Hirofuchi <t.hirofuchi _at_ aist.go.jp>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307, USA.
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

struct custom_log_handler_params {
	int use_syslog;
	int use_fd;
	int fd;
};

void custom_log_handler(const gchar   *log_domain, GLogLevelFlags log_level,
		const gchar   *message, gpointer       data);
#endif

void set_process_name(const char *name);


#if _FILE_OFFSET_BITS == 64
#define OFF_MAX INT64_MAX
#else
#define OFF_MAX INT32_MAX
#endif

