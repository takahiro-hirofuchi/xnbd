/* 
 * xNBD - an enhanced Network Block Device program
 *
 * Copyright (C) 2008-2011 National Institute of Advanced Industrial Science
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

#include "xnbd.h"
#include <sys/reboot.h>

static void nbddev_watchdog_sigalarm_handler(int signum)
{
	info("sig: signal catched, code %d (%s)", signum, sys_siglist[signum]);

	if (signum != SIGALRM)
		warn("unexpected signal, code %d (%s)", signum, sys_siglist[signum]);
}

/* string is dummy */
const char *recovery_command_internal_reboot_call = "reboot now";


#if 0
static void nbddev_watchdog(const char *devpath, unsigned int timeout)
{
	char *buf = g_malloc(512 + 512);

	if (!timeout)
		return;

	struct sigaction act;
	bzero(&act, sizeof(act));
	act.sa_handler = nbddev_watchdog_sigalarm_handler;
	int ret = sigaction(SIGALRM, &act, NULL);
	if (ret < 0)
		err("sigaction %m");

	uintptr_t modulo = (uintptr_t) buf % 512;
	if (modulo) 
		buf = (char *) ((uintptr_t) buf + (512 - modulo));


	for (;;) {
		alarm(timeout);

		int fd = open(devpath, O_RDONLY | O_DIRECT);
		if (fd < 0)
			err("open %m");

		ssize_t ret = pread(fd, buf, 512, 0);
		if (ret < 0) {
			if (errno == EINTR) {
				warn("I/O watchdog timeout: %s, %d sec", devpath, timeout);
				xnbd_disconnect(devpath);
				break;
			}

			err("read %m");
		}


		alarm(0);

		/* polling interval is the same value as timeout */
		sleep(timeout);

		close(fd);
	}

	g_free(buf);
}
#endif

/*
 * SIGALRM cannot give an immediate interrupt to pread/read from a nbd device.
 * Without O_DIRECT, the situation is the same.  This behavior may be specific
 * to a particular kernel version. So, we fork a child process, and it is
 * dedicated to do polling with pread.
 */

static int watchdog_main(const char *devpath, int notify, unsigned int polling_interval)
{
#if 0
	char *allocated = g_malloc(512 + 512);
	char *buf = allocated;

	/* direct I/O buffer is aligned to a 512-byte boundary */
	uintptr_t modulo = (uintptr_t) buf % 512;
	if (modulo) 
		buf = (char *) ((uintptr_t) buf + (512 - modulo));
#endif

	void *buf;
	const size_t bufsize = 512;
	int ret = posix_memalign(&buf, bufsize, bufsize);
	if (ret)
		err("posix_memalign, ret %d", ret);

	int fd = open(devpath, O_RDONLY | O_DIRECT);
	if (fd < 0)
		err("open %m");

	for (;;) {
		ssize_t ret = pread(fd, buf, bufsize, 0);
		if (ret == 0) {
			info("watchdog detected %s shutdowned", devpath);
			break;
		} else if (ret < 0)
			err("read, ret %zd, %m", ret);

		char msg = 'a';
		ret = write(notify, &msg, 1);
		if (ret != 1)
			err("write, ret %zd, %m", ret);

		sleep(polling_interval);
	}

	close(notify);
	close(fd);
	free(buf);
#if 0
	g_free(allocated);
#endif

	return 0;
}

static void nbddev_watchdog(const char *devpath, unsigned int timeout, unsigned int interval, const char *recovery_command)
{
	int listenfd, notifyfd;

	make_pipe(&notifyfd, &listenfd);

	pid_t pid = fork_or_abort();
	if (pid == 0) {
		/* child */
		close(listenfd);

		watchdog_main(devpath, notifyfd, interval);

		exit(EXIT_SUCCESS);
	}

	/* parent */
	close(notifyfd);

	struct sigaction act;
	bzero(&act, sizeof(act));
	act.sa_handler = nbddev_watchdog_sigalarm_handler;
	int ret = sigaction(SIGALRM, &act, NULL);
	if (ret < 0)
		err("sigaction %m");

	for (int counter = 0; ; counter++) {
		alarm(timeout + interval);

		char msg[100];
		ssize_t ret = read(listenfd, &msg, sizeof(msg));
		if (ret == 0) {
			/* watchdog_main detected shutdown */
			break;
		} else if (ret == -1) {
			if (errno == EINTR) {
				warn("nbd watchdog timeout: %s, %d sec", devpath, timeout);
				if (recovery_command) {
					if (recovery_command == recovery_command_internal_reboot_call) {
						info("restart the system by reboot(2)");
						ret = reboot(RB_AUTOBOOT);
						if (ret < 0)
							warn("internal reboot call failed, %m");
						/* should never return */
					}

					info("spawn recovery command, \"%s\"", recovery_command);
					GError *error = NULL;
					g_spawn_command_line_async(recovery_command, &error);
					if (error)
						warn("%s", error->message);
				}
				break;
			} else
				err("read %m");
		}

		if (counter % 100 == 0)
			info("%s watchdog alive", devpath);

		alarm(0);
	}

	close(listenfd);
}



static const char *help_string = "\
Usage: \n\
  xnbd-watchdog [options] nbd_device \n\
\n\
  xnbd-watchdog --help \n\
\n\
Options: \n\
  --timeout	set a timeout period (default 10) \n\
  --interval	(default 10) \n\
  --recovery-command		invoke a specified command if polling failed \n\
  --recovery-command-reboot	invoke the reboot system call if polling failed \n\
\n\
Example: \n\
  xnbd-watchdog --recovery-command-reboot /dev/nbd0 \n\
";


static void show_help_and_exit(const char *msg)
{
	if (msg)
		g_warning("%s", msg);

	fprintf(stderr, "%s", help_string);
	exit(EXIT_SUCCESS);
}

#include <getopt.h>

static struct option longopts[] = {
	{"help", 	no_argument, NULL, 'h'},
	{"timeout",	required_argument, NULL, 't'},
	{"interval",	required_argument, NULL, 'i'},
	{"recovery-command", 		required_argument, NULL, 'R'},
	{"recovery-command-reboot",	no_argument, NULL, 'H'},
	{NULL, 0, NULL, 0},
};

int main(int argc, char **argv)
{
	const char *recovery_command = NULL;
	unsigned int timeout = 10;
	unsigned int interval = 10;

	for (;;) {
		int c;
		int index = 0;

		c = getopt_long(argc, argv, "ht:i:R:H", longopts, &index);
		if (c == -1) /* all options were parsed */
			break;

		switch (c) {
			case 'h':
				show_help_and_exit("specify one mode");
				break;

			case 't':
				timeout = (unsigned int) atoi(optarg);
				break;

			case 'i':
				interval = (unsigned int) atoi(optarg);
				break;

			case 'R':
				recovery_command = optarg;
				break;

			case 'H':
				recovery_command = recovery_command_internal_reboot_call;
				break;

			case '?':
				show_help_and_exit("unknown option");
				break;

			default:
				err("getopt");
		}
	}

	if (argc - optind != 1)
		show_help_and_exit("command line error");

	const char *devpath = argv[optind];

	pid_t pid = fork_or_abort();
	if (pid == 0) {
		/* watchdog daemon process */
		nbddev_watchdog(devpath, timeout, interval, recovery_command);
		exit(EXIT_SUCCESS);
	}

	info("nbdev watchdog daemon (pid %d)", pid);

	return 0;
}

