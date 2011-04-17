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
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <linux/fs.h>           /* for BLKRRPART */


/* /usr/include/linux/nbd.h */
#define NBD_SET_SOCK    _IO( 0xab, 0 )
#define NBD_SET_BLKSIZE _IO( 0xab, 1 )
#define NBD_SET_SIZE    _IO( 0xab, 2 )
#define NBD_DO_IT       _IO( 0xab, 3 )
#define NBD_CLEAR_SOCK  _IO( 0xab, 4 )
#define NBD_CLEAR_QUE   _IO( 0xab, 5 )
#define NBD_PRINT_DEBUG _IO( 0xab, 6 )
#define NBD_SET_SIZE_BLOCKS     _IO( 0xab, 7 )
#define NBD_DISCONNECT  _IO( 0xab, 8 )
#define NBD_SET_TIMEOUT _IO( 0xab, 9 )

/* /usr/include/linux/fs.h: */
#define BLKROSET   _IO(0x12,93) /* set device read-only (0 = read-write) */


pid_t get_nbd_pid(const char *devname)
{
	pid_t pid;

	if(strncmp(devname, "/dev/", 5) == 0) 
		devname += 5;


	char *pidpath = g_strdup_printf("/sys/block/%s/pid", devname);


	char *buf;
	GError *error = NULL;
	g_file_get_contents(pidpath, &buf, NULL, &error);
	if (error != NULL) {
		// warn("get contents of %s, %s", pidpath, error->message);
		g_error_free(error);
		pid = -1;
	} else {
		pid = atoi(g_strchomp(buf));
		info("%s is ready for read/write, xnbd-server (pid %d)", devname, pid);
	}

	g_free(pidpath);

	return pid;
}

static const uint64_t NBD_MAX_NBLOCKS = (~0UL >> 1);

static void nbddev_set_sizes(int nbd, uint64_t disksize, unsigned long blocksize)
{
	int ret;

	if (disksize / blocksize > NBD_MAX_NBLOCKS)
		err("Device too large.\n");

	unsigned long nblocks = (unsigned long) (disksize / blocksize);

	ret = ioctl(nbd, NBD_SET_BLKSIZE, blocksize);
	if (ret < 0)
		err("NBD_SET_BLKSIZE, ret %d, %m", ret);

	ret = ioctl(nbd, NBD_SET_SIZE_BLOCKS, nblocks);
	if (ret < 0)
		err("NBD_SET_SIZE_BLOCKS, ret %d, %m", ret);

#if 0
	ret = ioctl(nbd, NBD_CLEAR_SOCK);
	if (ret < 0)
		err("NBD_CLEAR_SOCK, ret %d, %m", ret);
#endif

	info("blocksize %lu, disksize %ju (%lu blocks)", blocksize, disksize, nblocks);
}

void nbddev_set_readonly(int nbd)
{
	unsigned long read_only = 1;

	int ret = ioctl(nbd, BLKROSET, &read_only);
	if (ret < 0)
		err("BLKROSET, ret %d, %m", ret);

	info("readyonly enabled");
}

void nbddev_set_timeout(int nbd, unsigned int timeout)
{
	if (!timeout)
		return;

	int ret = ioctl(nbd, NBD_SET_TIMEOUT, (unsigned long) timeout);
	if (ret < 0)
		err("NBD_SET_TIMEOUT, ret %d, %m", ret);

	info("timeout %d", timeout);
}


void nbddev_set_sockfd(int nbd, int sockfd)
{
	int ret = ioctl(nbd, NBD_SET_SOCK, sockfd);
	if (ret < 0)
		err("NBD_SET_SOCK, ret %d, %m", ret);
}


static void xnbd_disconnect(const char *devpath)
{
	int ret;

	pid_t nbd_pid = get_nbd_pid(devpath);
	if (nbd_pid < 0)
		err("%s is not connected", devpath);


	ret = kill(nbd_pid, SIGUSR1);
	if (ret < 0)
		warn("%s is connected ?", devpath);


	int nbd = open(devpath, O_RDWR);
	if (nbd < 0)
		err("open %s, ret %d, %m", devpath, nbd);

	ret = ioctl(nbd, NBD_CLEAR_QUE);
	if (ret < 0)
		err("NBD_CLEAR_QUE, ret %d, %m", ret);

	ret = ioctl(nbd, NBD_DISCONNECT);
	if (ret < 0)
		err("NBD_DISCONNECT, ret %d, %m", ret);

	ret = ioctl(nbd, NBD_CLEAR_SOCK);
	if (ret < 0)
		err("NBD_CLEAR_SOCK, ret %d, %m", ret);

	close(nbd);

	info("%s disconnected", devpath);
}

struct dst_info {
	const char *host;
	const char *port;
};

void dst_add(GList **dst_list, const char *host, const char *port)
{
	struct dst_info *dst = g_malloc(sizeof(struct dst_info));
	dst->host = host;
	dst->port = port;

	*dst_list = g_list_append(*dst_list, dst);
}









/* string is dummy */
const char *recovery_command_internal_reboot_call = "reboot now";

/*
 * 1. xnbd-client quits with exit code 2, if it cannot establish an NBD session
 * with any server specified.
 *
 * 2. After a NBD session is establishd, it starts to serve an NBD device by
 * calling ioctl(NBD_DO_IT). xnbd-client (parent) quits after it checks an NBD
 * device file is actually working. Without this check, the next command like
 * mount may fail.
 *
 * 3. After ioctl(NBD_DO_IT) returns, xnbd-client (child) checks its return
 * code, and calls a specified command for recovery as needed.
 **/


static int xnbd_connect(const char *devpath, unsigned long blocksize, unsigned int timeout, GList *dst_list, int max_retry, const char *recovery_command)
{
	int sockfd;
	off_t disksize;
	uint32_t flags;
	int retry = 0;

	for (;;) {
		int connected = 0;

		for (GList *list = g_list_first(dst_list); list != NULL; list = g_list_next(list)) {
			struct dst_info *dst = (struct dst_info *) list->data;
			const char *host = dst->host;
			const char *port = dst->port;

			info("connecting to %s(%s)", host, port);
			sockfd = net_tcp_connect(host, port);
			if (sockfd < 0) {
				warn("cannot connect to %s(%s)", host, port);
				continue;
			}

			int ret = nbd_negotiate_with_server2(sockfd, &disksize, &flags);
			if (ret < 0) {
				warn("negotiation with %s:%s failed", host, port);
				continue;
			}

			info("connected to %s(%s)", host, port);
			connected = 1;
			break;
		}

		if (connected)
			break;

		if (max_retry == 0 || retry < max_retry) {
			info("sleep for a moment and try again ...");
			sleep(5);
			retry += 1;
			continue;
		} else
			err("cannot establish a NBD session with any server");
	}

	/* so far, we get a negotiated socket */

	int retcode = -3;

	int nbd = open(devpath, O_RDWR);
	if (nbd < 0)
		err("open %s, ret %d, %m", devpath, nbd);

	nbddev_set_sockfd(nbd, sockfd);

	nbddev_set_sizes(nbd, (uint64_t) disksize, blocksize);

	if (flags & NBD_FLAG_READ_ONLY)
		nbddev_set_readonly(nbd);

	nbddev_set_timeout(nbd, timeout);

	/*
	 * signal(7) says the default disposition of SIGCHLD is "Ignore". 
	 * Here, make sure the parent does not ignore SIGCHLD.
	 */
	sigset_t set, oldset;
	sigemptyset(&set);
	sigemptyset(&oldset);
	sigaddset(&set, SIGCHLD);
	sigaddset(&set, SIGUSR1);
	sigprocmask(SIG_BLOCK, &set, &oldset);

	pid_t pid = fork();
	if (pid < 0)
		err("fork() %m");


	if (pid != 0) {
		/* parent */
		for (;;) {
			sigset_t sigs;
			sigpending(&sigs);

			if (sigismember(&sigs, SIGCHLD))
				err("xnbd-client (child) was terminated due to an internal error");

			pid_t nbd_pid = get_nbd_pid(devpath);
			if (nbd_pid < 0) {
				info("wait for a moment ...");
				sleep(1);
			} else
				break;
		}

		/*
		 * re-read partition table.
		 * this may fail if the kernel does not support it.
		 **/
		ioctl(nbd, BLKRRPART);

		close(sockfd);
		close(nbd);

		exit(EXIT_SUCCESS);
	}

	/* set to the default */
	sigprocmask(SIG_BLOCK, &oldset, NULL);

	/*
	 * Before /sys/block/nbd0/pid is created by calling ioctl(NBD_DO_IT),
	 * read/write to /dev/nbd0 fails.
	 **/

	int ret = ioctl(nbd, NBD_DO_IT);
	if (ret < 0) {
		sigset_t sigs;
		sigpending(&sigs);

		if (sigismember(&sigs, SIGUSR1)) {
			info("%s connection was probably terminated by a user", devpath);
			retcode = 0;
		} else {
			warn("unexpected disconnect. NBD_DO_IT returned, ret %d, %m", ret);
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
			retcode = -2;
		}
	}

	ioctl(nbd, NBD_CLEAR_QUE);
	ioctl(nbd, NBD_CLEAR_SOCK);
	close(sockfd);
	close(nbd);

	/*
	 * retcode == 0: terminated by a user (after NBD_DO_IT)
	 *           -2: abnormal termination; for example, server
	 *               termination, and transport error.
	 *               I/O errors have probably occurred. (after NBD_DO_IT)
	 *           -3: never happen with Linux 2.6.x; we should quit. (after NBD_DO_IT)
	 */

	return retcode;
}


#include <getopt.h>

static struct option longopts[] = {
	{"connect",	required_argument, NULL, 'C'},
	{"disconnect",	required_argument, NULL, 'd'},
	{"check",	required_argument, NULL, 'c'},
	{"help", 	no_argument, NULL, 'h'},
	{"timeout",	required_argument, NULL, 't'},
	{"blocksize",	required_argument, NULL, 'b'},
	{"retry",	required_argument, NULL, 'r'},
	{"recovery-command", required_argument, NULL, 'R'},
	{"recovery-command-reboot", no_argument, NULL, 'H'},
	{NULL, 0, NULL, 0},
};

enum {
	cmd_unknown = -1,
	cmd_connect = 0,
	cmd_disconnect,
	cmd_check,
	cmd_help,
} cmd = cmd_unknown;



static const char *help_string = "\
Usage: \n\
  xnbd-client [bs=...] [timeout=...] host port nbd_device \n\
\n\
  xnbd-client --connect [options] nbd_device host port [host port] ... \n\
  xnbd-client -C [options] nbd_device host port [host port] ... \n\
\n\
  xnbd-client --disconnect nbd_device \n\
  xnbd-client -d nbd_device \n\
\n\
  xnbd-client --check nbd_device \n\
  xnbd-client -c nbd_device \n\
\n\
  xnbd-client --help \n\
\n\
Options: \n\
  --timeout	set a timeout period (default 0, disabled) (DO NOT USE NOW) \n\
  --blocksize   select blocksize from 512, 1024, 2048, and 4096 (default 1024) \n\
  --retry	set the maximum count of retries to connect to a server (default 1) \n\
  --recovery-command		invoke a specified command on unexpected disconnection \n\
  --recovery-command-reboot	invoke the reboot system call on unexpected disconnection \n\
\n\
Example: \n\
  xnbd-client fe80::250:45ff:fe00:ab8f%%eth0 8998 /dev/nbd0 \n\
     This command line is compatible with nbd-client. But xnbd-client supports IPv6. \n\
\n\
  xnbd-client --connect /dev/nbd0 fe80::250:45ff:fe00:ab8f%%eth0 8998 10.1.1.1 8900 \n\
     This automatically tries the next server if the first one does not accept connection. \n\
";


static void show_help_and_exit(const char *msg)
{
	if (msg)
		g_warning("%s", msg);

	fprintf(stderr, "%s", help_string);
	exit(EXIT_SUCCESS);
}


int main(int argc, char *argv[]) {
	const char *devpath = NULL;
	unsigned int timeout = 0;
	unsigned long blocksize = 1024;
	int max_retry = 1;
	const char *recovery_command = NULL;
	GList *dst_list = NULL;


	for (;;) {
		int c;
		int index = 0;

		c = getopt_long(argc, argv, "C:d:c:ht:b:r:R:H", longopts, &index);
		if (c == -1) /* all options were parsed */
			break;

		switch (c) {
			case 'C':
				if (cmd != cmd_unknown)
					show_help_and_exit("specify one mode");
			
				cmd = cmd_connect;
				devpath = optarg;
				break;

			case 'd':
				if (cmd != cmd_unknown)
					show_help_and_exit("specify one mode");

				cmd = cmd_disconnect;
				devpath = optarg;
				break;

			case 'c':
				if (cmd != cmd_unknown)
					show_help_and_exit("specify one mode");

				cmd = cmd_check;
				devpath = optarg;
				break;

			case 'h':
				if (cmd != cmd_unknown)
					show_help_and_exit("specify one mode");

				cmd = cmd_help;
				break;

			case 't':
				timeout = (unsigned int) atoi(optarg);
				/*
				 * In my environment, NBD_SET_TIMEOUT does not
				 * work with Linux 2.6.32.1 and 2.6.26; when a
				 * timeout period is expired, xnbd-client is
				 * never killed by kernel.
				 *
				 * Moreover, 2.6.32.1 kernel fails to create
				 * partition device files of a connected
				 * device.
				 * 
				 **/
				err("--timeout is currently disabled due to kernel bug. Use xnbd-watchdog instead!");
				break;

			case 'b':
				blocksize = (unsigned long) atoi(optarg);
				break;

			case 'r':
				max_retry = atoi(optarg);
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


	if (cmd == cmd_unknown) {
		/* compatible mode */

		for (int i = optind ; i < argc; i++) {
			int matched;

			matched = sscanf(argv[i], "bs=%lu", &blocksize);
			if (matched) 
				continue;

			matched = sscanf(argv[i], "timeout=%u", &timeout);
			if (matched > 0)
				continue;

			/* end of options and start of args */

			optind = i;
			break;
		}

		if (argc - optind != 3)
			show_help_and_exit("command line error");

		const char *host = argv[optind];
		optind += 1;

		const char *port = argv[optind];
		optind += 1;

		devpath = argv[optind];

		info("bs=%lu timeout=%d %s %s %s", blocksize, timeout, host, port, devpath);
		dst_add(&dst_list, host, port);

		xnbd_connect(devpath, blocksize, timeout, dst_list, 1, recovery_command);

		exit(EXIT_SUCCESS);
	}

	info("cmd %s mode", longopts[cmd].name);

	switch (cmd) {
		case cmd_connect:
			/* do it later */
			break;

		case cmd_check:
			if (argc - optind != 0)
				show_help_and_exit("command line error");

			pid_t nbd_pid = get_nbd_pid(devpath); /* exit */
			if (nbd_pid != -1) {
				printf("%d\n", nbd_pid);
				exit(EXIT_SUCCESS);
			} else
				exit(EXIT_FAILURE);
			break;

		case cmd_disconnect:
			if (argc - optind != 0)
				show_help_and_exit("command line error");

			xnbd_disconnect(devpath);
			exit(EXIT_SUCCESS);
			break;

		case cmd_help:
			show_help_and_exit(NULL);
			break;

		case cmd_unknown:
		default:
			err("never happen");
	}


	/* handle the case in which cmd == cmd_connect */

	if ((argc -optind) % 2 != 0)
		show_help_and_exit("incomplete pairs of host and port");

	for (int i = optind; i < argc; i += 2) {
		const char *host = argv[i];
		const char *port = argv[i + 1];

		dst_add(&dst_list, host, port);
		info("bs=%lu timeout=%d %s %s %s", blocksize, timeout, host, port, devpath);
	}

	xnbd_connect(devpath, blocksize, timeout, dst_list, 1, recovery_command);


	return 0;
}
