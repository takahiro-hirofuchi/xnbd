/* 
 * Copyright (C) 2008-2009 National Institute of Advanced Industrial Science and Technology
 */
#include "xnbd.h"



const int XNBD_PORT = 8520;



void setup_disk(char *diskpath, struct xnbd_info *xnbd)
{
	int diskfd;


	if (xnbd->readonly)
		diskfd = open(diskpath, O_RDONLY | O_NOATIME);
	else
		diskfd = open(diskpath, O_RDWR | O_NOATIME);
	if (diskfd < 0) {
		if (errno == EOVERFLOW)
			warn("enable large file support!");
		err("open, %s", strerror(errno));
	}


	off_t disksize = get_disksize(diskfd);

	check_disksize(diskpath, disksize);


	/* multi-connections call this */
	//if (posix_fallocate(diskfd, 0, disksize))
	//	warn("maybe no enough space in a local file system");
	



	xnbd->diskfd = diskfd;
	xnbd->disksize = disksize;
	xnbd->diskopened = 1;

}





void setup_cachedisk(struct xnbd_info *xnbd, off_t disksize, char *cachepath)
{
	int cachefd;

	cachefd = open(cachepath, O_RDWR | O_CREAT | O_NOATIME, S_IRUSR | S_IWUSR);
	if (cachefd < 0)
		err("open");
	

	off_t size = get_disksize(cachefd);
	if (size < disksize) {
		warn("cache disk size is smaller than the target disk size %ju < %ju", size, disksize);
		warn("now expand it");
		off_t ret = lseek(cachefd, disksize - 1, SEEK_SET);
		if (ret < 0)
			err("lseek");
		
		ret = write(cachefd, "\0", 1);
		if (ret < 0)
			err("write");
	}
	


	xnbd->cachefd = cachefd;
	xnbd->cacheopened = 1;
}






#if 0
void get_event_connecter(int *notifier, int *listener)
{
	int pipefds[2];
	int ret = pipe(pipefds);
	if (ret == -1)
		err("pipe, %m");

	*notifier = pipefds[1];
	*listener = pipefds[0];
}
#endif


void xnbd_session_initialize_connections(struct xnbd_info *xnbd, struct xnbd_session *ses)
{
	if (xnbd->proxymode) {
		off_t disksize = 0;

		ses->remotefd = net_tcp_connect(xnbd->remotehost, xnbd->remoteport);
		if (ses->remotefd < 0)
			err("connecting %s:%s failed", xnbd->remotehost, xnbd->remoteport);

		/* negotiate and get disksize from remote server */
		disksize = nbd_negotiate_with_server(ses->remotefd);
		if (disksize != xnbd->disksize)
			err("The remote host answered a different disksize.");
	}
}



/* called once in the master process */
void xnbd_initialize(struct xnbd_info *xnbd)
{
	if (xnbd->proxymode) {
		int remotefd;

		if (!(xnbd->remotehost && xnbd->remoteport
					&& xnbd->cachepath && xnbd->cbitmappath))
			err("insuffcient info");


		remotefd = net_tcp_connect(xnbd->remotehost, xnbd->remoteport);
		if (remotefd < 0)
			err("connecting %s:%s failed", xnbd->remotehost, xnbd->remoteport);

		/* check the remote server and get a disksize */
		xnbd->disksize = nbd_negotiate_with_server(remotefd);
		nbd_client_send_disc_request(remotefd);
		close(remotefd);

		xnbd->nblocks = get_disk_nblocks(xnbd->disksize);
		xnbd->cbitmap = bitmap_open_file(xnbd->cbitmappath, xnbd->nblocks, &xnbd->cbitmaplen, 0, 1);
		// xnbd->cbitmapopened = 1;

		/* setup cachefile */
		setup_cachedisk(xnbd, xnbd->disksize, xnbd->cachepath);


		info("proxymode mode %s %s cache %s cachebitmap %s",
				xnbd->remotehost, xnbd->remoteport,
				xnbd->cachepath, xnbd->cbitmappath);


	} else {
		if (!xnbd->diskpath)
			err("insuffcient info");

		if (xnbd->cow) {
			xnbd->ds = open_cow_disk(xnbd->diskpath, 1, 0);
			xnbd->disksize = xnbd->ds->disksize;
		} else
			setup_disk(xnbd->diskpath, xnbd);

		xnbd->nblocks = get_disk_nblocks(xnbd->disksize);
	}

	// monitor_init(xnbd->nblocks);


	info("xnbd master initialization done");
}



void xnbd_shutdown(struct xnbd_info *xnbd)
{
	info("xnbd_shutdowning ...");

	if (xnbd->diskopened)
		close(xnbd->diskfd);
	xnbd->diskopened = 0;


	if (xnbd->ds)
		close_cow_disk(xnbd->ds, 1);
	xnbd->ds = NULL;



	if (xnbd->cacheopened)
		close(xnbd->cachefd);
	xnbd->cacheopened = 0;


	if (xnbd->cbitmap)
		bitmap_close_file(xnbd->cbitmap, xnbd->cbitmaplen);
	xnbd->cbitmap = NULL;



	// monitor_shutdown();
}


void do_service(struct xnbd_session *ses)
{
	int ret;
	struct xnbd_info *xnbd = ses->xnbd;
	

	if (xnbd->proxymode) {
		dbg("proxy mode");
		ret = proxy_server(ses);
	} else {
		dbg("target mode");
		//xnbd->migrating_to_target = 0;
		if (xnbd->cow)
			ret = target_server_cow(ses);
		else
			ret = target_server(ses);
	}


	info("process got out from main loop, ret %d", ret);


//	if (xnbd->migrating_to_target) {
//		xnbd->proxymode = 0;
//		//xnbd->migrating_to_target = 0;
//		xnbd->diskpath = xnbd->cachepath;
//		goto serve_again;
//	}
//
	info("shutdown xnbd done");
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


void free_session(struct xnbd_info *xnbd, struct xnbd_session *ses)
{
	if (xnbd->proxymode) {
		nbd_client_send_disc_request(ses->remotefd);
		close(ses->remotefd);
	}

	close(ses->event_notifier_fd);

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
static volatile sig_atomic_t need_exit = 0;



static void signal_handler(int signum)
{
	dbg("sig: signal catched, code %d (%s)", signum, sys_siglist[signum]);

	if (signum == SIGCHLD)
		got_sigchld = 1;
	else if (signum == SIGHUP)
		got_sighup = 1;
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

	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);
}


static struct pollfd eventfds[MAXLISTENSOCK];
static nfds_t nlistened = 0;

void invoke_new_session(struct xnbd_info *xnbd, int csockfd)
{
	struct xnbd_session *ses = g_malloc0(sizeof(struct xnbd_session));
	ses->clientfd = csockfd;
	ses->xnbd = xnbd;

	/* used for sending msg to the session process */
	get_event_connecter(&ses->event_notifier_fd, &ses->event_listener_fd);
	xnbd_session_initialize_connections(xnbd, ses);

	info("negotiations done");

	pid_t pid = fork(); 
	if (pid == -1)
		err("fork failed");

	if (pid == 0) {
		/* child */
		close(ses->event_notifier_fd);

		for (GList *list = g_list_first(xnbd->sessions); list != NULL; list = g_list_next(list)) {
			struct xnbd_session *s = (struct xnbd_session *) list->data;
			info("cleanup pid %d", s->pid);
			if (xnbd->proxymode)
				close(s->remotefd);
			info(" clientfd %d", s->clientfd);
			close(s->clientfd);

			/* this must be commented out, closed alreay in the parent */
			//close(s->event_listener_fd);
			//info(" s->event_listener_fd %d", s->event_listener_fd);
			close(s->event_notifier_fd);
			info(" s->event_notifier_fd %d", s->event_notifier_fd);
		}


		for (nfds_t j = 0; j < nlistened; j++) 
			close(eventfds[j].fd);



		dbg("new connection");
		info("do service %d", getpid());
		//{
		//	pid_t mypid = getpid();
		//	char buf[100];
		//	sprintf(buf, "lsof -p %d", mypid);
		//	system(buf);
		//	sleep(10);
		//}

		do_service(ses);

		close(csockfd);

		info("process %d exit", getpid());
		exit(EXIT_SUCCESS);
	}


	close(ses->event_listener_fd);

	ses->pid = pid;
	xnbd->sessions = g_list_append(xnbd->sessions, ses);

	/* parent */
	//close(csockfd);
}


void shutdown_all_sessions(struct xnbd_info *xnbd)
{
	info("cleanup %d child process(es)", g_list_length(xnbd->sessions));

	for (GList *list = g_list_first(xnbd->sessions); list != NULL; list = g_list_next(list)) {
		struct xnbd_session *s = (struct xnbd_session *) list->data;
		/* TODO: notify gracefully, then send SIGKILL */

		info("notify %d of termination", s->pid);
		ssize_t ret = write(s->event_notifier_fd, "0", 1);
		if (ret < 0)
			warn("notifiy failed");

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
	}
}


int master_server(int port, void *data)
{
	int lsock[MAXLISTENSOCK];
	struct addrinfo *ai_head;

	struct xnbd_info *xnbd = (struct xnbd_info *) data;

	ai_head = net_getaddrinfo(NULL, port, PF_UNSPEC);
	if (!ai_head)
		return 0;

	nlistened = net_listen_all_addrinfo(ai_head, lsock);
	if (nlistened <= 0)
		err("no socket to listen to");

	freeaddrinfo(ai_head);


	for (nfds_t i = 0; i < nlistened; i++) {
		eventfds[i].fd     = lsock[i];
		eventfds[i].events = POLLRDNORM;
	}

	for (nfds_t i = nlistened; i < MAXLISTENSOCK; i++)
		eventfds[i].fd     = -1;


	set_sigactions();

	sigset_t sigs_blocked;
	sigset_t orig_sigmask;
	/*
	 * The master process does not want to get SIGCHLD anytime; when SIGCHLD received, some
	 * system calls may fail with errno == EINTR. Only this ppoll() can be intrrupted.
	 */
	sigemptyset(&sigs_blocked);
	/* do now allow SIG_CHLD except ppoll() */
	sigaddset(&sigs_blocked, SIGCHLD);
	sigaddset(&sigs_blocked, SIGINT);
	sigaddset(&sigs_blocked, SIGTERM);
	sigaddset(&sigs_blocked, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &sigs_blocked, &orig_sigmask);

	GList *socklist = NULL;
	int restarting = 0;

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

				struct xnbd_session *ses = find_session_with_pid(xnbd, pid);
				if (!ses)
					err("unknown session pid %d", pid);

				xnbd->sessions = g_list_remove(xnbd->sessions, ses);
				free_session(xnbd, ses);
				info("session (pid %d) exited", pid);

				if (WIFEXITED(status))
					info("   with exit status=%d", WEXITSTATUS(status));

				if (WIFSIGNALED(status))
					info("   killed by signal=%d(%s)", WTERMSIG(status), sys_siglist[WTERMSIG(status)]);
			}
		}

		if (restarting && g_list_length(xnbd->sessions) == 0) {
			/* All sessions are stopped. Now start new sessions with existing sockets. */

			info("All sessions are stopped. Now restart.");
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

			restarting = 0;
		}

		if (got_sighup) {
			info("got SIGHUP, restart %d process(es)", g_list_length(xnbd->sessions));
			got_sighup = 0;

			/* notify all sessions of termination */
			for (GList *list = g_list_first(xnbd->sessions); list != NULL; list = g_list_next(list)) {
				struct xnbd_session *s = (struct xnbd_session *) list->data;

				dbg("%p\n", s);
				/*
				 * If a new connection is accepted during
				 * restarting, send SIGHUP to the master server
				 * again.
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

				info("notify %d of termination", s->pid);
				ssize_t ret = write(s->event_notifier_fd, "0", 1);
				if (ret < 0)
					warn("notifiy failed");
			}

			restarting = 1;
		}

		/* SIGCHLD must be blocked here, so that only this ppoll() detects that */
		//raise(SIGCHLD);

		info("start polling");
		nready = ppoll(eventfds, nlistened, NULL, &orig_sigmask); 
		//printf("poll ready %d\n", nready);
		if (nready == -1) {
			/* signal catched */
			if (errno == EINTR) {
				info("polling signal catched");
				continue;
			} else
				err("poll, %s", strerror(errno));
		}


		for (nfds_t i = 0; i < nlistened; i++) {
			int sockfd = eventfds[i].fd;

			if (sockfd < 0)
				continue;

			if (eventfds[i].revents & (POLLHUP | POLLNVAL)) 
				err("unknown events, %x", eventfds[i].revents);

			if (eventfds[i].revents & (POLLRDNORM | POLLERR)) {
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
			}

			/* short cut */
			nready -= 1;
			if (nready == 0)
				break;
		}
	}



	/* notify child processes */
	shutdown_all_sessions(xnbd);

	return 0;
}





#include <getopt.h>

static struct option longopts[] = {
	{"target", no_argument, NULL, 't'},
	{"proxy", no_argument, NULL, 'p'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{"lport", required_argument, NULL, 'l'},
	{"bgctlprefix", required_argument, NULL, 'B'},
	{"gstatpath", required_argument, NULL, 'G'},
	{"daemonize", no_argument, NULL, 'd'},
	{"readonly", no_argument, NULL, 'r'},
	{"cow", no_argument, NULL, 'c'},
	{"logpath", required_argument, NULL, 'L'},
	{NULL, 0, NULL, 0},
};

enum {
	cmd_unknown = -1,
	cmd_target = 0,
	cmd_proxy,
	cmd_help,
	cmd_version
} cmd = cmd_unknown;



static const char *help_string = "\
Usage: \n\
  xnbd-server --target [options] disk_image \n\
  xnbd-server --proxy [options] target_host port cache_image cache_bitmap \n\
  xnbd-server --help \n\
  xnbd-server --version \n\
\n\
Options: \n\
  --lport	listen port (default 8520) \n\
  --bgctlprefix	FIFO file prefix used by a control program in proxy mode \n\
  		(default /tmp/xnbd-bg.ctl) \n\
  --daemonize	run as a daemon process \n\
  --readonly	export a disk as readonly in target mode \n\
  --cow		export a disk as copy-on-write in target mode \n\
  --logpath	logfile (default /tmp/xnbd.log) \n\
";


static const char *version = "$Id$";


		


static void show_help_and_exit(const char *msg)
{
	if (msg)
		g_warning("%s", msg);

	fprintf(stderr, "%s", help_string);
	exit(EXIT_SUCCESS);
}

  

int main(int argc, char **argv) {
	struct xnbd_info xnbd;
	int lport = XNBD_PORT;
	char *gstatpath = NULL;
	char *bgctlprefix = NULL;
	int daemonize = 0;
	int readonly = 0;
	int cow = 0;
	const char *logpath = NULL;
	int logfd = -1;

	if (g_thread_supported())
		err("glib thread not supported");

	bzero(&xnbd, sizeof(xnbd));

	//g_log_set_default_handler("xnbd_master", G_LOG_LEVEL_WARNING | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION, log_handler, NULL);
	g_log_set_default_handler(xutil_log_handler, (void *) &xnbd);

	PAGESIZE = (unsigned int) getpagesize();
	if (CBLOCKSIZE % PAGESIZE != 0)
		warn("CBLOCKSIZE %u PAGESIZE %u", CBLOCKSIZE, PAGESIZE);


	for (;;) {
		int c;
		int index = 0;

		c = getopt_long(argc, argv, "tphvl:B:G:drcL:", longopts, &index);
		if (c == -1)
			break;

		switch (c) {
			case 't':
				if (cmd != cmd_unknown)
					show_help_and_exit("specify one mode");
			
				cmd = cmd_target;
				break;

			case 'p':
				if (cmd != cmd_unknown)
					show_help_and_exit("specify one mode");

				cmd = cmd_proxy;
				break;

			case 'h':
				if (cmd != cmd_unknown)
					show_help_and_exit("specify one mode");

				cmd = cmd_help;
				break;

			case 'v':
				if (cmd != cmd_unknown)
					show_help_and_exit("specify one mode");

				cmd = cmd_version;
				break;

			case 'l':
				lport = atoi(optarg);
				info("listen port %d", lport);
				break;

			case 'B':
				bgctlprefix = optarg;
				info("background copy control %s", optarg);
				break;

			case 'G':
				gstatpath = optarg;
				info("ext2 group I/O status %s", optarg);
				err("not-yet-released feature");
				break;

			case 'd':
				daemonize = 1;
				info("daemonize enabled");
				break;

			case 'r':
				readonly = 1;
				info("readonly enabled");
				break;

			case 'c':
				cow = 1;
				info("copy-on-write enabled");
				break;

			case 'L':
				logpath = optarg;
				info("log file %s", logpath);
				break;

			case '?':
				cmd = cmd_help;
				break;
			default:
				err("getopt");
		}
	}

	info("cmd %s mode", longopts[cmd].name);

	switch (cmd) {
		case cmd_help:
			show_help_and_exit(NULL);

		case cmd_version:
			printf("%s\n", version);
			exit(EXIT_SUCCESS);

		case cmd_unknown:
			 err("bug");

		case cmd_target:
		case cmd_proxy:
			break;
		default:
			show_help_and_exit("give one command");
	}


	switch (cmd) {
		case cmd_target:
			if (argc - optind != 1)
				show_help_and_exit("argument error");


			xnbd.diskpath   = argv[optind];
			xnbd.proxymode  = 0;
			xnbd.cow        = cow;
			xnbd.readonly   = readonly;


			break;

		case cmd_proxy:
			if (argc - optind != 4)
				show_help_and_exit("argument error");

			xnbd.remotehost  = argv[optind];
			xnbd.remoteport  = argv[optind + 1];
			xnbd.cachepath   = argv[optind + 2];
			xnbd.cbitmappath = argv[optind + 3];
			xnbd.proxymode   = 1;


			if (bgctlprefix)
				xnbd.bgctlprefix = bgctlprefix;
			else {
				xnbd.bgctlprefix = "/tmp/xnbd-bg.ctl";
				info("use default bgctlprefix %s", xnbd.bgctlprefix);
			}

			break;

		case cmd_version:
		case cmd_help:
		case cmd_unknown:
		default:
			err("not reached");
	}


	xnbd_initialize(&xnbd);

	if (xnbd.proxymode)
		cachestat_initialize(DEFAULT_CACHESTAT_PATH, xnbd.nblocks);

	if (daemonize) {
		int ret = daemon(0, 0);
		if (ret < 0)
			err("daemon %m");
	}

	if (logpath || daemonize) {
		if (!logpath)
			logpath = "/tmp/xnbd.log";

		logfd = open(logpath, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
		if (logfd < 0)
			err("open %s, %m", logpath);

		int ret = dup2(logfd, 2);
		if (ret < 0)
			err("dup2 %m");

		close(logfd);
	}



	master_server(lport, (void *) &xnbd);

	xnbd_shutdown(&xnbd);
	cachestat_shutdown();


	close(2);

	return 0;
}
