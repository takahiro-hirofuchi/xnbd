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

#include "common.h"



#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <syslog.h>

#if 0
static pid_t mygettid(void)
{
	return syscall(SYS_gettid);
}
#endif

#include <sys/prctl.h>
#include <stdlib.h>

#define ALERT_LEVELS (G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING)

int syslog_level(int glib_log_level)
{
	int level = LOG_INFO;

	switch (glib_log_level & G_LOG_LEVEL_MASK)
	{
		case G_LOG_LEVEL_CRITICAL:
			level = LOG_CRIT;
			break;

		case G_LOG_LEVEL_ERROR:
			level = LOG_ERR;
			break;

		case G_LOG_LEVEL_WARNING:
			level = LOG_WARNING;
			break;

		case G_LOG_LEVEL_MESSAGE:
			level = LOG_NOTICE;
			break;

		case G_LOG_LEVEL_INFO:
			level = LOG_INFO;
			break;

		case G_LOG_LEVEL_DEBUG:
			level = LOG_DEBUG;
			break;

		default:
			level = LOG_CRIT;
	}

	return level | LOG_DAEMON;
}

void custom_log_handler(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer data)
{
	struct custom_log_handler_params *params = data;

	GString *gstring = g_string_new(NULL);

	/* we may not call _any_ GLib functions here */

	{
		char *header = getenv("LOG_HEADER");
		if (header)
			g_string_append(gstring, header);
	}

	{
		char name[20];
		int ret = prctl(PR_GET_NAME, (unsigned long) name);
		if (ret < 0)
			err("PR_GET_NAME, %m");

		g_string_append(gstring, name);
	}

	g_string_append(gstring, "(");

	{
		pid_t pid = getpid();
		pid_t tid = syscall(SYS_gettid);

		if (pid == tid)
			g_string_append_printf(gstring, "%d", pid);
		else
			g_string_append_printf(gstring, "%d.%d", pid, tid);
	}

	g_string_append(gstring, ") ");

	if (log_domain) {
		g_string_append(gstring, log_domain);
		g_string_append(gstring, ">");
	}

	switch (log_level & G_LOG_LEVEL_MASK)
	{
		case G_LOG_LEVEL_ERROR:
			g_string_append(gstring, "ERR");
			break;

		case G_LOG_LEVEL_CRITICAL:
			g_string_append(gstring, "CRIT");
			break;

		case G_LOG_LEVEL_WARNING:
			g_string_append(gstring, "WARN");
			break;

		case G_LOG_LEVEL_MESSAGE:
			g_string_append(gstring, "msg");
			break;

		case G_LOG_LEVEL_INFO:
			g_string_append(gstring, "info");
			break;

		case G_LOG_LEVEL_DEBUG:
			g_string_append(gstring, "dbg");
			break;

		default:
			g_string_append(gstring, "log");
			break;
	}



	if (log_level & G_LOG_FLAG_RECURSION)
		g_string_append(gstring, " (recursed)");

	g_string_append(gstring, ": ");

	//if (log_level & ALERT_LEVELS)
	//	g_string_append(gstring, "** ");


	if (message)
		g_string_append(gstring, message);
	else
		g_string_append(gstring, "(NULL) message");


	gboolean is_fatal = (log_level & G_LOG_FLAG_FATAL) != 0;
	if (is_fatal)
		g_string_append(gstring, "\naborting...\n");
	else
		g_string_append(gstring, "\n");


	//struct xnbd_info *xnbd = (struct xnbd_info *) data;
	//printf("%d %d\n", gstring->len, strlen(gstring->str));

	if (params) {
		if (params->use_syslog)
			syslog(syslog_level(log_level), "%s", gstring->str);
		if (params->use_fd) {
			g_assert(params->fd != -1);
			write(params->fd, gstring->str, gstring->len);
		}
	} else {
		/* compatibility for the past */
		write(2, gstring->str, gstring->len);
	}

	g_string_free(gstring, TRUE);
}


#include <sys/prctl.h>
#include <string.h>

void set_process_name(const char *name)
{
	char comm[16];
	strncpy(comm, name, sizeof(comm));
	int ret = prctl(PR_SET_NAME, (unsigned long) comm, 0l, 0l, 0l);
	if (ret < 0)
		warn("set_name %m");
}
