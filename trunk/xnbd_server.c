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
#include "xnbd_common.h"

/* IPTOS */
#include <netinet/in.h>
#include <netinet/ip.h>























/* called once in the master process */
void xnbd_initialize(struct xnbd_info *xnbd)
{
	switch (xnbd->cmd) {
		case xnbd_cmd_proxy:
			g_assert(xnbd->proxy_rhost);
			g_assert(xnbd->proxy_rport);
			g_assert(xnbd->proxy_diskpath);
			g_assert(xnbd->proxy_bmpath);

			xnbd_proxy_start(xnbd);

			break;

		case xnbd_cmd_cow_target:
			g_assert(xnbd->cow_diskpath);

			xnbd->cow_ds = xnbd_cow_target_open_disk(xnbd->cow_diskpath, 1, 0);
			xnbd->disksize = xnbd->cow_ds->disksize;
			xnbd->nblocks = get_disk_nblocks(xnbd->disksize);

			break;

		case xnbd_cmd_target:
			g_assert(xnbd->target_diskpath);

			xnbd_target_open_disk(xnbd->target_diskpath, xnbd);
			xnbd->nblocks = get_disk_nblocks(xnbd->disksize);

			break;

		case xnbd_cmd_version:
		case xnbd_cmd_help:
		case xnbd_cmd_unknown:
		default:
			err("not reached");
	}



	// monitor_init(xnbd->nblocks);


	info("xnbd master initialization done");
}



void xnbd_shutdown(struct xnbd_info *xnbd)
{
	info("xnbd_shutdowning ...");

	if (xnbd->cmd == xnbd_cmd_target)
		close(xnbd->target_diskfd);


	if (xnbd->cmd == xnbd_cmd_cow_target)
		xnbd_cow_target_close_disk(xnbd->cow_ds, 1);


	if (xnbd->cmd == xnbd_cmd_proxy)
		xnbd_proxy_stop(xnbd);




	// monitor_shutdown();
}


void do_service(struct xnbd_session *ses)
{
	int ret;
	struct xnbd_info *xnbd = ses->xnbd;
	

	switch (xnbd->cmd) {
		case xnbd_cmd_target:
			ret = xnbd_target_session_server(ses);
			break;

		case xnbd_cmd_cow_target:
			ret = xnbd_cow_target_session_server(ses);
			break;

		case xnbd_cmd_proxy:
			ret = xnbd_proxy_session_server(ses);
			break;

		case xnbd_cmd_version:
		case xnbd_cmd_help:
		case xnbd_cmd_unknown:
		default:
			err("not reached");
	}


	info("shutdown xnbd master done (cmd %d), ret %d", xnbd->cmd, ret);
}





struct xnbd_session *find_session_with_pid(struct xnbd_info *xnbd, pid_t pid)
{
	int found = 0;
	struct xnbd_session *ses = NULL;

	for (GList *list = g_list_first(xnbd->sessions); list != NULL; list = g_list_next(list)) {
		ses = (struct xnbd_session *) list->data;
		if (ses->pid == pid) {
			found = 1;
			break;
		}
	}

	if (!found) {
		dbg("session (pid %d) not found", pid);
		return NULL;
	}

	return ses;
}


void free_session(struct xnbd_session *ses)
{

	close(ses->pipe_master_fd);

	/*
	 * In normal cases, just close clientfd. For proxy-to-target mode
	 * change, restart a new session with the existing clientfd.  However,
	 * just close() here, because already did dup() for the clientfd.
	 **/
	close(ses->clientfd);

	g_free(ses);
}



static volatile sig_atomic_t got_sigchld = 0;
static volatile sig_atomic_t got_sighup = 0;
static volatile sig_atomic_t got_sigusr1 = 0;
static volatile sig_atomic_t need_exit = 0;



static void signal_handler(int signum)
{
	dbg("sig: signal catched, code %d (%s)", signum, sys_siglist[signum]);

	if (signum == SIGCHLD)
		got_sigchld = 1;
	else if (signum == SIGHUP)
		got_sighup = 1;
	else if (signum == SIGUSR1)
		got_sigusr1 = 1;
	else
		need_exit = 1;
}

static void set_sigactions()
{
	struct sigaction act;

	bzero(&act, sizeof(act));
	//sigemptyset(&act.sa_mask);
	act.sa_handler = signal_handler;

	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGCHLD, &act, NULL);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGUSR1, &act, NULL);

	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);
}


static struct pollfd ppoll_eventfds[MAXLISTENSOCK];
static nfds_t ppoll_neventfds = 0;

void invoke_new_session(struct xnbd_info *xnbd, int csockfd)
{
	struct xnbd_session *ses = g_malloc0(sizeof(struct xnbd_session));
	ses->clientfd = csockfd;
	ses->xnbd = xnbd;

	/* used for sending msg to the session process */
	make_pipe(&ses->pipe_master_fd, &ses->pipe_worker_fd);

	info("negotiations done");

	pid_t pid = fork(); 
	if (pid == -1)
		err("fork failed");

	if (pid == 0) {
		/* worker child does not need master_fd */
		close(ses->pipe_master_fd);

		if (xnbd->cmd == xnbd_cmd_proxy)
			close(xnbd->proxy_sockpair_master_fd);

		for (nfds_t j = 0; j < ppoll_neventfds; j++) 
			close(ppoll_eventfds[j].fd);

		/* worker child does not need descriptors of the other sessions */
		for (GList *list = g_list_first(xnbd->sessions); list != NULL; list = g_list_next(list)) {
			struct xnbd_session *s = (struct xnbd_session *) list->data;
			dbg("cleanup pid %d", s->pid);
			dbg(" s->pipe_master_fd %d", s->pipe_master_fd);
			dbg(" s->clientfd %d", s->clientfd);
			close(s->clientfd);
			close(s->pipe_master_fd);

			/* pipe_worker_fd was already closed in the master */
		}




		dbg("new connection");
		info("do service %d (cmd %d)", getpid(), xnbd->cmd);
		//{
		//	pid_t mypid = getpid();
		//	char buf[100];
		//	sprintf(buf, "lsof -p %d", mypid);
		//	system(buf);
		//	sleep(10);
		//}


		if (xnbd->tos) {
			const int val = IPTOS_THROUGHPUT;
			int ret = setsockopt(csockfd, IPPROTO_IP, IP_TOS, (const void *) &val, sizeof(val));
			if (ret < 0)
				err("setsockopt, %m");
		}

		do_service(ses);

		close(csockfd);

		info("worker process %d exit", getpid());
		exit(EXIT_SUCCESS);
	}


	close(ses->pipe_worker_fd);

	ses->pid = pid;
	xnbd->sessions = g_list_append(xnbd->sessions, ses);

	/* parent */
	//close(csockfd);
}


void shutdown_all_sessions(struct xnbd_info *xnbd)
{
	info("cleanup %d child process(es)", g_list_length(xnbd->sessions));

	for (;;) {
		GList *list = g_list_first(xnbd->sessions);
		if (!list)
			break;

		struct xnbd_session *s = (struct xnbd_session *) list->data;
		/* request the child to exit */
		info("notify worker (%d) of session termination", s->pid);
		ssize_t ret = write(s->pipe_master_fd, "", 1);
		if (ret < 0)
			warn("notifiy failed");

		/* if everything goes well, we do not need to send SIGKILL */
		ret = waitpid(s->pid, NULL, 0);
		if (ret < 0)
			err("waitpid %d, %m", s->pid);

		free_session(s);
		xnbd->sessions = g_list_remove(xnbd->sessions, s);
		info("session (pid %d) cleared", s->pid);

#if 0
		int exited = 0;
		for (int i = 0; i < 3; i++) {
			int status;
			ret = waitpid(s->pid, &status, WNOHANG);
			if (ret < 0)
				err("no such process %d", s->pid);

			if (ret > 0) {
				exited = 1;
				break;
			}

			sleep(1);
		}

		if (!exited) {
			info("send SIGKILL to %d", s->pid);
			ret = kill(s->pid, SIGKILL);
			if (ret < 0)
				warn("kill pid %d, %s", s->pid, strerror(errno));
		}
#endif
	}
}





static void ppoll_initialize_eventfds(void)
{
	for (nfds_t i = 0; i < MAXLISTENSOCK; i++)
		ppoll_eventfds[i].fd = -1;

	ppoll_neventfds = 0;
}

static void ppoll_add_eventfd(int fd, short events)
{
	nfds_t i = ppoll_neventfds;

	g_assert(ppoll_neventfds < MAXLISTENSOCK-1);

	ppoll_eventfds[i].fd = fd;
	ppoll_eventfds[i].events = events;
	ppoll_neventfds += 1;
}

int master_server(int port, void *data, int connect_fd)
{
	struct xnbd_info *xnbd = (struct xnbd_info *) data;
	int lsock[MAXLISTENSOCK];
	struct addrinfo *ai_head;


	ppoll_initialize_eventfds();


	if (connect_fd == -1) {
		ai_head = net_getaddrinfo(NULL, port, PF_UNSPEC);
		if (!ai_head)
			return 0;

		unsigned int nlistened = net_listen_all_addrinfo(ai_head, lsock);
		if (nlistened <= 0)
			err("no socket to listen to");

		freeaddrinfo(ai_head);

		for (nfds_t i = 0; i < nlistened; i++)
			ppoll_add_eventfd(lsock[i], POLLIN);

	} else {
		if (connect_fd == 0) {
			int ret;
			if (xnbd->readonly)
				ret = nbd_negotiate_with_client_readonly(connect_fd, xnbd->disksize);
			else
				ret = nbd_negotiate_with_client(connect_fd, xnbd->disksize);
			if (ret < 0) {
				warn("negotiation with the client failed");
			} else {
				info("negotiation done (connect_fd = %d)", connect_fd);
			}
		} else {
			info("use already negotiated sockfd %d", connect_fd);
		}
		invoke_new_session(xnbd, connect_fd);
	}



	set_sigactions();

	sigset_t sigs_blocked;
	sigset_t orig_sigmask;
	/*
	 * The master process does not want to get SIGCHLD anytime; when SIGCHLD received, some
	 * system calls may fail with errno == EINTR. Only this ppoll() can be interrupted.
	 */
	sigemptyset(&sigs_blocked);
	/* block SIG_* anytime; only the below ppoll() detects an arrival */
	sigaddset(&sigs_blocked, SIGCHLD);
	sigaddset(&sigs_blocked, SIGINT);
	sigaddset(&sigs_blocked, SIGTERM);
	sigaddset(&sigs_blocked, SIGHUP);
	sigaddset(&sigs_blocked, SIGUSR1);
	pthread_sigmask(SIG_BLOCK, &sigs_blocked, &orig_sigmask);

	GList *socklist = NULL;
	int restarting_for_mode_change = 0;
	int restarting_for_snapshot = 0;

	for (;;) {
		int nready;

		/*
		 * N.B. If compiled with fake ppoll() support, the master
		 * process may deadlock when a child process exited.
		 *
		 * For Debian's 2.6.18 kernels, ppoll() is equivalent to calling
		 * sigprocmask(), poll(), and then sigprocmask(); it is not an
		 * atomic system call.
		 *
		 * In this code, while the master process is running outside
		 * this ppoll(), a delivered signal goes to pending state
		 * until the process accepts the signal.  The handler of the
		 * signal is called just after the process unblocks the signal.
		 *
		 * In this ppoll(), the first sigprocmask() unblocks the
		 * signal. Before the poll(), the signal handler is called.
		 * poll() does not detect the signal, and does not return until
		 * the next event comes.
		 *
		 * This means that ppoll() does not return -1 with errno ==
		 * EINTR, for the signal that deliverred while the process was
		 * running outside ppoll().
		 *
		 * For Debian's 2.6.26 kernels, it's ok.
		 */
		/*
		 * In glibc-2.7, sysdeps/unix/sysv/linux/kernel-features.h says
		 *   pselect/ppoll were introduced just after 2.6.16-rc1.  Due
		 *   to the way the kernel versions are advertised we can only
		 *   rely on 2.6.17 to have the code.  On x86_64 and SH this
		 *   appeared first in 2.6.19-rc1, on ia64 in 2.6.22-rc1 and on
		 *   alpha just after 2.6.22-rc1.
		 **/
		if (need_exit) {
			dbg("need exit");
			break;
		}

		if (got_sigchld) {
			dbg("got sigchld");
			got_sigchld = 0;

			/* SIGCHLD */
			for (;;) {
				int status;
				pid_t pid = waitpid(-1, &status, WNOHANG);

				/* no more exiting child process */
				if (pid < 0)
					break;

				/* pid == 0: no more exiting child process. there still
				 * remains one or more running process(es). */
				if (pid == 0)
					break;

				if (xnbd->cmd == xnbd_cmd_proxy)
					if (pid == xnbd->proxy_pid)
						err("detect abnormal termination of proxy_server");



				struct xnbd_session *ses = find_session_with_pid(xnbd, pid);
				if (!ses)
					err("unknown session pid %d", pid);

				xnbd->sessions = g_list_remove(xnbd->sessions, ses);
				free_session(ses);
				info("session (pid %d) cleared", pid);

				if (WIFEXITED(status))
					info("   with exit status=%d", WEXITSTATUS(status));

				if (WIFSIGNALED(status))
					info("   killed by signal=%d(%s)", WTERMSIG(status), sys_siglist[WTERMSIG(status)]);
			}

			if (connect_fd != -1) {
				info("Using connect_fd. No need to wait for the next event");
				break;
			}
		}

		/* must be after the SIGCHLD handler */
		if ((restarting_for_mode_change || restarting_for_snapshot) && g_list_length(xnbd->sessions) == 0) {
			/* All sessions are stopped. Now start new sessions with existing sockets. */
			info("All sessions are stopped. Now restart.");

			if (restarting_for_mode_change) {
				/* become target mode */
				xnbd_shutdown(xnbd);
				xnbd->cmd = xnbd_cmd_target;
				xnbd->target_diskpath = xnbd->proxy_diskpath;
				xnbd_initialize(xnbd);
			} else {
				/* take a snapshot */
				xnbd_target_make_snapshot(xnbd);
			}


			/*
			 * invoke_new_session() manipulates xnbd->sessions,
			 * adding an entry to it. The fixed list is used here
			 * instead of xnbd->sessions.
			 **/
			for (GList *list = g_list_first(socklist); list != NULL; list = g_list_next(list)) {
				int csockfd = (int) ((long) list->data);  /* See below */
				invoke_new_session(xnbd, csockfd);
			}

			
			/* must be reinitialized with NULL */
			g_list_free(socklist);
			socklist = NULL;

			info("restarting has done");

			if (restarting_for_mode_change)
				restarting_for_mode_change = 0;
			else
				restarting_for_snapshot = 0;
		}


		if (got_sighup || got_sigusr1) {
			if (got_sighup) {
				got_sighup = 0;

				if (xnbd->cmd != xnbd_cmd_proxy) {
					warn("ignoring SIGHUP (mode change) not in proxy mode");
					goto skip_restarting;
				}

				info("got SIGHUP, restart %d process(es)", g_list_length(xnbd->sessions));
				restarting_for_mode_change = 1;
			}

			if (got_sigusr1) {
				got_sigusr1 = 0;

				if (xnbd->cmd != xnbd_cmd_target) {
					warn("ignoring SIGUSR1 (snapshot) not in target mode");
					goto skip_restarting;
				}

				info("got SIGUSR1, restart %d process(es)", g_list_length(xnbd->sessions));
				restarting_for_snapshot = 1;
			}

			/* if there are no sessions, ready for restart */
			if (g_list_length(xnbd->sessions) == 0)
				continue;

			/*
			 * Gracefully shutdown child processes. Notify all
			 * child processes of termination. The child processes
			 * that have exited will send SIGCHLD to the master
			 * process. After the master process knows all the
			 * child processes have exited, it restarts new
			 * sessions.
			 **/
			for (GList *list = g_list_first(xnbd->sessions); list != NULL; list = g_list_next(list)) {
				struct xnbd_session *s = (struct xnbd_session *) list->data;

				dbg("%p\n", s);
				/*
				 * If a new connection is accepted during
				 * restarting, send SIGHUP to the master server
				 * again.
				 *
				 * NOTE: Another design option is to defer
				 * invoking a new session until restarting is
				 * completed.
				 **/
				if (s->notifying)
					continue;

				s->notifying = 1;

				/* preserve connected sockets */
				int csockfd = dup(s->clientfd);
				if (csockfd < 0)
					err("dup %d, %m", csockfd);

				/* it's ok because sizeof(void *) >= sizeof(int); 32bit =, 64bit > */
				socklist = g_list_append(socklist, (void *) ((long) csockfd));

				info("notify worker (%d) of session termination", s->pid);
				ssize_t ret = write(s->pipe_master_fd, "", 1);
				if (ret < 0)
					warn("notifiy failed");
			}

skip_restarting:
			;
		}

		/* SIGCHLD must be blocked here, so that only this ppoll() detects that */
		//raise(SIGCHLD);

		info("start polling");
		nready = ppoll(ppoll_eventfds, ppoll_neventfds, NULL, &orig_sigmask); 
		//printf("poll ready %d\n", nready);
		if (nready == -1) {
			/* signal catched */
			if (errno == EINTR) {
				info("polling signal catched");
				continue;
			} else
				err("poll, %s", strerror(errno));
		}

		for (nfds_t i = 0; i < ppoll_neventfds; i++) {
			int sockfd = ppoll_eventfds[i].fd;

			if (sockfd < 0)
				continue;

			if (ppoll_eventfds[i].revents & (POLLHUP | POLLNVAL)) 
				err("unknown events, %x", ppoll_eventfds[i].revents);

			if (ppoll_eventfds[i].revents & (POLLIN | POLLERR)) {
				/* if POLLERR, the next read() returns -1 */
				/* POLLERR never occurs because we wait new connections */

				int csockfd = net_accept(sockfd);
				if (csockfd < 0) {
					warn("accept() failed");
					continue;
				}

				int ret;
				if (xnbd->readonly)
					ret = nbd_negotiate_with_client_readonly(csockfd, xnbd->disksize);
				else
					ret = nbd_negotiate_with_client(csockfd, xnbd->disksize);
				if (ret < 0) {
					warn("negotiation with the client failed");
					continue;
				}

				info("csockfd %d", csockfd);
				invoke_new_session(xnbd, csockfd);

				/* for short cut */
				nready -= 1;
			}

			if (nready == 0)
				break;
		}
	}



	/* notify child processes */
	shutdown_all_sessions(xnbd);

	return 0;
}


static struct option longopts[] = {
	/* commands */
	{"target", no_argument, NULL, 't'},
	{"cow-target", no_argument, NULL, 'c'},
	{"proxy", no_argument, NULL, 'p'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	/* options */
	{"lport", required_argument, NULL, 'l'},
	{"gstatpath", required_argument, NULL, 'G'},
	{"daemonize", no_argument, NULL, 'd'},
	{"readonly", no_argument, NULL, 'r'},
	{"logpath", required_argument, NULL, 'L'},
	{"tos", no_argument, NULL, 'T'},
	{"connected-fd", required_argument, NULL, 'F'},
	{"inetd", no_argument, NULL, 'i'},
	{NULL, 0, NULL, 0},
};

static const char *opt_string = "tpchvl:G:drL:TF:i";


static const char *help_string = "\
Usage: \n\
  xnbd-server --target [options] disk_image\n\
  xnbd-server --cow-target [options] base_disk_image\n\
  xnbd-server --proxy [options] remote_host remort_port cache_disk_path cache_bitmap_path control_socket_path\n\
  xnbd-server --help\n\
  xnbd-server --version\n\
\n\
Options: \n\
  --lport	listen port (default 8520)\n\
  --daemonize	run as a daemon process\n\
  --readonly	export a disk as readonly\n\
  --logpath	logfile (default /tmp/xnbd.log)\n\
  --inetd	redirect stderr for running from inetd\n\
";



static const char *version = "xNBD (version 0.1.0-pre)";
static const char *copyright = "\
Copyright (C) 2008-2011 National Institute of Advanced Industrial Science\n\
and Technology\n\
\n\
This program is free software; you can redistribute it and/or modify it\n\
under the terms of the GNU General Public License as published by the Free\n\
Software Foundation; either version 2 of the License, or (at your option)\n\
any later version.\n\
\n\
Development of xNBD was partially sponsored by Wavecon GmbH <www.wavecon.de>.\n\
";



		


static void show_help_and_exit(const char *msg)
{
	if (msg)
		g_warning("%s", msg);

	fprintf(stderr, "%s", help_string);
	exit(EXIT_SUCCESS);
}

  

int main(int argc, char **argv) {
	struct xnbd_info xnbd;
	enum xnbd_cmd_type cmd = xnbd_cmd_unknown;
	int lport = XNBD_PORT;
	char *gstatpath = NULL;
	int daemonize = 0;
	int readonly = 0;
	int tos = 0;
	int connected_fd = -1;
	const char *logpath = NULL;
	int inetd = 0;

#ifdef NEED_GTHREAD_INIT
	if (g_thread_supported())
		err("glib thread not supported");
#endif

	bzero(&xnbd, sizeof(xnbd));

	g_log_set_default_handler(xutil_log_handler, (void *) &xnbd);

	PAGESIZE = (unsigned int) getpagesize();
	if (CBLOCKSIZE % PAGESIZE != 0)
		warn("CBLOCKSIZE %u PAGESIZE %u", CBLOCKSIZE, PAGESIZE);

	for (;;) {
		int c;
		int index = 0;

		c = getopt_long(argc, argv, opt_string, longopts, &index);
		if (c == -1)
			break;

		switch (c) {
			case 'L':
				logpath = optarg;
				break;
			case 'i':
				inetd = 1;
				connected_fd = 0;
				break;
		}
	}

	if (inetd)
		redirect_stderr(logpath);

	optind = 1;

	for (;;) {
		int c;
		int index = 0;

		c = getopt_long(argc, argv, opt_string, longopts, &index);
		if (c == -1)
			break;

		switch (c) {
			/* commands */
			case 't':
				if (cmd != xnbd_cmd_unknown)
					show_help_and_exit("specify one mode");
			
				cmd = xnbd_cmd_target;
				break;

			case 'p':
				if (cmd != xnbd_cmd_unknown)
					show_help_and_exit("specify one mode");

				cmd = xnbd_cmd_proxy;
				break;

			case 'c':
				if (cmd != xnbd_cmd_unknown)
					show_help_and_exit("specify one mode");

				cmd = xnbd_cmd_cow_target;
				break;

			case 'h':
				if (cmd != xnbd_cmd_unknown)
					show_help_and_exit("specify one mode");

				cmd = xnbd_cmd_help;
				break;

			case 'v':
				if (cmd != xnbd_cmd_unknown)
					show_help_and_exit("specify one mode");

				cmd = xnbd_cmd_version;
				break;

			/* options */
			case 'l':
				lport = atoi(optarg);
				info("listen port %d", lport);
				break;

			case 'G':
				gstatpath = optarg;
				info("ext2 group I/O status %s", optarg);
				err("not-yet-released feature");
				break;

			case 'd':
				if (inetd)
					err("daemonize option may not be specified with inetd option");
				daemonize = 1;
				info("daemonize enabled");
				break;

			case 'r':
				readonly = 1;
				info("readonly enabled");
				break;

			case 'T':
				tos = 1;
				info("ToS enabled");
				break;

			case 'F':
				/* use a file descriptor specified in a command line */
				if (inetd)
					err("connected_fd option may not be specified with inetd option");
				connected_fd = atoi(optarg);
				info("connected fd %d", connected_fd);
				break;

			case 'L':
			case 'i':
				/* previously processed options */
				break;

			case '?':
				cmd = xnbd_cmd_help;
				break;
			default:
				err("getopt");
		}
	}


	if (cmd != xnbd_cmd_unknown && cmd != xnbd_cmd_version)
		info("cmd %s mode", longopts[cmd].name);

	switch (cmd) {
		case xnbd_cmd_help:
			show_help_and_exit(NULL);

		case xnbd_cmd_version:
			printf("%s\n\n", version);
			printf("%s\n", copyright);
			exit(EXIT_SUCCESS);

		case xnbd_cmd_target:
		case xnbd_cmd_cow_target:
		case xnbd_cmd_proxy:
			break;

		case xnbd_cmd_unknown:
		default:
			show_help_and_exit("give one command");
	}


	switch (cmd) {
		case xnbd_cmd_target:
			if (argc - optind != 1)
				show_help_and_exit("argument error");

			xnbd.target_diskpath   = argv[optind];

			break;

		case xnbd_cmd_proxy:
			if (argc - optind != 5)
				show_help_and_exit("argument error");

			xnbd.proxy_rhost  = argv[optind];
			xnbd.proxy_rport  = argv[optind + 1];
			xnbd.proxy_diskpath = argv[optind + 2];
			xnbd.proxy_bmpath   = argv[optind + 3];
			xnbd.proxy_unixpath = argv[optind + 4];

			break;

		case xnbd_cmd_cow_target:
			if (argc - optind != 1)
				show_help_and_exit("argument error");

			xnbd.cow_diskpath = argv[optind];

			break;

		case xnbd_cmd_version:
		case xnbd_cmd_help:
		case xnbd_cmd_unknown:
		default:
			err("not reached");
	}

	xnbd.cmd = cmd;
	xnbd.readonly = readonly;
	xnbd.tos = tos;
	xnbd_initialize(&xnbd);

	if (xnbd.cmd == xnbd_cmd_proxy)
		cachestat_initialize(DEFAULT_CACHESTAT_PATH, xnbd.nblocks);

	if (!inetd && logpath) {
		info("logfile %s", logpath);
		redirect_stderr(logpath);
	}

	if (daemonize)
		detach(logpath);


	master_server(lport, (void *) &xnbd, connected_fd);

	xnbd_shutdown(&xnbd);
	cachestat_shutdown();

	info("the master server now exits");

	return 0;
}
