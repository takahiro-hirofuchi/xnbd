/* 
 * xNBD - an enhanced Network Block Device program
 *
 * Copyright (C) 2008-2012 National Institute of Advanced Industrial Science
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
#include <libgen.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>


#define XNBD_IMAGE_ADDED  0
#define XNBD_IMAGE_ACCESS_ERROR  (-1)
#define XNBD_ENOMEN  (-3)
#define XNBD_NOT_ADDING_TWICE  (-4)


pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
GHashTable * p_disk_dict = NULL;
guint images_added_ever = 0;


typedef struct _t_disk_data {
	char * disk_file_name;  /* Used as key in the hash table, too. So no need to free keys. */
	guint index;
} t_disk_data;

typedef struct _t_listing_state {
	guint index_to_print;
	guint index_up_next;
	FILE * fp;
} t_listing_state;


static void destroy_value(t_disk_data * p_disk_data) {
	g_free(p_disk_data->disk_file_name);
	g_free(p_disk_data);
}

static gboolean find_by_index(const char * key, const t_disk_data * p_disk_data, gconstpointer user_data) {
	const int index_at_addition_time = GPOINTER_TO_INT(user_data);
	return p_disk_data->index == index_at_addition_time;
}

static int add_diskimg(char *dname)
{
	/* Check image access */
	int fd;
	if ((fd = open(dname, O_RDONLY)) < 0)
		return XNBD_IMAGE_ACCESS_ERROR;
	close(fd);

	/* Add to hash table */
	pthread_mutex_lock(&mutex);
	int res = XNBD_IMAGE_ADDED;
	if (g_hash_table_contains(p_disk_dict, dname))
	{
		res = XNBD_NOT_ADDING_TWICE;
	}
	else
	{
		t_disk_data * const p_disk_data = g_try_new(t_disk_data, 1);
		if (p_disk_data)
		{
			p_disk_data->disk_file_name = g_strdup(dname);
			if (p_disk_data->disk_file_name)
			{
				p_disk_data->index = images_added_ever++;
				g_hash_table_insert(p_disk_dict, p_disk_data->disk_file_name, p_disk_data);
			}
			else
			{
				g_free(p_disk_data);
				res = XNBD_ENOMEN;
			}
		}
		else
		{
			res = XNBD_ENOMEN;
		}
	}
	pthread_mutex_unlock(&mutex);
	return res;
}

static void del_diskimg(int num)
{
	num--;
	if (num >= 0) {
		pthread_mutex_lock(&mutex);
		g_hash_table_foreach_remove(p_disk_dict, (GHRFunc)find_by_index, num);
		pthread_mutex_unlock(&mutex);
	}
}

static int has_diskimg(char *dname)
{
	pthread_mutex_lock(&mutex);
	const int res = g_hash_table_contains(p_disk_dict, dname) ? 0 : -1;
	pthread_mutex_unlock(&mutex);
	return res;
}

static void find_smallest_index_iterator(gpointer key, const t_disk_data * p_disk_data, t_listing_state * p_listing_state) {
	if (p_disk_data->index < p_listing_state->index_to_print)
	{
		p_listing_state->index_to_print = p_disk_data->index;
	}
}

static void list_images_iterator(gpointer key, const t_disk_data * p_disk_data, t_listing_state * p_listing_state) {
	if (p_disk_data->index == p_listing_state->index_to_print)
	{
		fprintf(p_listing_state->fp, "%d : %s\n", p_disk_data->index + 1, p_disk_data->disk_file_name);
	}
	else if ((p_disk_data->index > p_listing_state->index_to_print) && (p_disk_data->index < p_listing_state->index_up_next))
	{
		p_listing_state->index_up_next = p_disk_data->index;
	}
}

static void list_diskimg(FILE *fp)
{
	pthread_mutex_lock(&mutex);
	if (g_hash_table_size(p_disk_dict) > 0)
	{
		t_listing_state listing_state;
		listing_state.index_to_print = (guint)-1;
		listing_state.index_up_next = (guint)-1;
		listing_state.fp = fp;

		/* Produce output sorted by index without actually sorting the data, O(n^2) approach */
		g_hash_table_foreach(p_disk_dict, (GHFunc)find_smallest_index_iterator, &listing_state);
		while (listing_state.index_to_print < (guint)-1) {
			listing_state.index_up_next = (guint)-1;
			g_hash_table_foreach(p_disk_dict, (GHFunc)list_images_iterator, &listing_state);
			listing_state.index_to_print = listing_state.index_up_next;
		}
	}
	else
	{
		fprintf(fp, "no item\n");
	}
	pthread_mutex_unlock(&mutex);
	fflush(fp);
}

static void perform_shutdown(FILE * fp)
{
	pthread_mutex_lock(&mutex);
	g_hash_table_destroy(p_disk_dict);
	pthread_mutex_unlock(&mutex);

	fprintf(fp, "All images terminated\n");
	kill(0, SIGTERM);
}

static int make_unix_sock(const char *uxsock_path)
{
	int uxsock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (uxsock == -1) {
		warn("socket(AF_UNIX): %m");
		return -1;
	}
	struct sockaddr_un ux_saddr;
	strcpy(ux_saddr.sun_path, uxsock_path);
	ux_saddr.sun_family = AF_UNIX;
	if (bind(uxsock, &ux_saddr, sizeof(ux_saddr))) {
		warn("bind(AF_UNIX): %m");
		return -2;
	}
	if (listen(uxsock, 8)) {
		warn("listen(AF_UNIX): %m");
		return -3;
	}
	return uxsock;
}

static const int MAX_CTL_CONNS = 8;
/* static pthread_once_t once_ctl = PTHREAD_ONCE_INIT; */
static int mgr_threads = 0;

static int count_mgr_threads(int val)
{
	int ret;
	pthread_mutex_lock(&mutex);
	ret = mgr_threads = mgr_threads + val;
	pthread_mutex_unlock(&mutex);
	return ret;
}

static void *start_filemgr_thread(void *uxsock)
{
	const int rbufsize = 128;
	
	char buf[rbufsize];
	char cmd[rbufsize];
	char arg[rbufsize];
	int ret;

	int conn_uxsock = accept(*(int *)uxsock, NULL, NULL);
	if (conn_uxsock == -1) {
		warn("accept(AF_UNIX): %m");
		pthread_exit(NULL);
	}
	FILE *fp = fdopen(conn_uxsock, "r+");
	if (count_mgr_threads(1) <= MAX_CTL_CONNS) {
		fprintf(fp, "\"help\" command displays help for other commands\n");
		for(;;) {
			if (fputs("(xnbd) ", fp) == EOF){
				warn("fputs : EOF");
				break;
			}
			fflush(fp);
			if (fgets(buf, rbufsize, fp) == NULL)
				break;
			if (sscanf(buf, "%s%s", cmd, arg) < 1) {
				/* perror("sscanf"); */
				continue;
			}
	
			if (strcmp(cmd, "list") == 0)
				list_diskimg(fp);
			else if (strcmp(cmd, "add") == 0) {
				ret = add_diskimg(arg);
				if (ret == XNBD_IMAGE_ACCESS_ERROR)
					fprintf(fp, "cannot open %s\n", arg);
				else if (ret == XNBD_ENOMEN)
					fprintf(fp, "out of memory\n");
				else if (ret == XNBD_NOT_ADDING_TWICE)
					fprintf(fp, "image cannot be added twice\n");
			}
			else if (strcmp(cmd, "del") == 0)
				del_diskimg(atoi(arg));
			else if (strcmp(cmd, "shutdown") == 0) {
				perform_shutdown(fp);
			}
			else if (strcmp(cmd, "help") == 0)
				fprintf(fp,
					"list     : show diskimage list\n"
					"add PATH : add diskimage\n"
					"del N    : delete diskimage (N = diskimage number on list)\n"
					"shutdown : terminate all images and shutdown xnbd-wrapper instance\n"
					"quit     : quit(disconnect)\n");
			else if (strcmp(cmd, "quit") == 0)
				break;
			else
				fprintf(fp, "unknown command\n");
		}
	} else {
		fprintf(fp, "too many connections\n");
		fflush(fp);
	}
	fclose(fp);
	close(conn_uxsock);
	count_mgr_threads(-1);

	/* just to avoid warning */
	return NULL;
}

static int make_tcp_sock(const char *addr_or_name, const char *port)
{
	int tcp_sock;
	struct addrinfo hints;
	struct addrinfo *res, *rp;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	int error = getaddrinfo(addr_or_name, port, &hints, &res);
	if (error) {
		warn("%s: %s", port, gai_strerror(error));
		return -1;
	}

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		tcp_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (tcp_sock != -1)
			break;
	}

	if (rp == NULL) {
		warn("rp is NULL\n");
		return -1;
	}

	int optval = 1;
	if (setsockopt(tcp_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))) {
		perror("setsockopt");
		return -1;
	}

	if (bind(tcp_sock, rp->ai_addr, rp->ai_addrlen)) {
		perror("bind");
		return -1;
	}

	freeaddrinfo(res);

	if (listen(tcp_sock, 64)) {
		perror("listen");
		return -1;
	}

	return tcp_sock;
}

struct exec_params {
	char *binpath;
	const char *target_mode;
	int readonly;
	int syslog;
};

static void exec_xnbd_server(struct exec_params *params, char *fd_num, char *requested_img)
{
	char *args[8];
	int i = 0;
	args[i] = params->binpath;
	args[++i] = (char *)params->target_mode;
	if (params->readonly)
		args[++i] = (char *)"--readonly";
	if (params->syslog)
		args[++i] = (char *)"--syslog";
	args[++i] = (char *)"--connected-fd";
	args[++i] = fd_num;
	args[++i] = requested_img;
	args[++i] = NULL;

#ifdef XNBD_DEBUG
	{
		info("About to execute...");
		char ** walker = args;
		while (*walker)
		{
			info("[%d] \"%s\"", walker - args, *walker);
			walker++;
		}
	}
#endif

	(void)execv(params->binpath, args);

	warn("exec failed");
	_exit(EXIT_FAILURE);
}

static const char help_string[] =
	"\n\n"
	"Usage: \n"
	"  %s [--port port] [--xnbd-binary path-to-xnbdserver] [--imgfile disk-image-file] [--laddr listen-addr] [--socket socket-path]\n"
	"\n"
	"Options: \n"
	"  --daemonize   run wrapper as a daemon process\n"
	"  --cow         run server instances as a cow target\n"
	"  --readonly    run server instances as a readonly target.\n"
	"  --port        Listen port (default: 8520).\n"
	"  --xnbd-binary Path to xnbd-server.\n"
	"  --imgfile     Path to disk image file. This options can be used multiple times.\n"
	"                You can also use xnbd-wrapper-ctl to (de)register disk images dynamically.\n"
	"  --logpath     logfile (default /tmp/xnbd.log)\n"
	"  --laddr       Listen address.\n"
	"  --socket      Unix socket path to listen on (default: /tmp/xnbd_wrapper.ctl).\n"
	"  --syslog      use syslog for logging\n"
	"\n"
	"Examples: \n"
	"  xnbd-wrapper --imgfile /data/disk1\n"
	"  xnbd-wrapper --imgfile /data/disk1 --imgfile /data/disk2 --xnbd-binary /usr/local/bin/xnbd-server --laddr 127.0.0.1 --port 18520 --socket /tmp/xnbd_wrapper_1.ctl\n";


int main(int argc, char **argv) {
	char *fd_num;
	pid_t pid;
	char *child_prog = NULL;
	char *laddr = NULL;
	char *port = NULL;
	int sockfd, conn_sockfd, ux_sockfd;
	int ch, ret;
	char *requested_img = NULL;
	struct stat sb;
	pthread_t thread;
	const char default_ctl_path[] = "/tmp/xnbd_wrapper.ctl";
	char *ctl_path = NULL;
	int forked_srvs = 0;
	const int MAX_NSRVS = 512;
	int cstatus;
	pid_t cpid;
	const char default_server_target[] = "--target";
	const char *server_target = NULL;
	int daemonize = 0;
	int syslog = 0;
	const char *logpath = NULL;
	struct exec_params exec_srv_params = { .readonly = 0 };

	p_disk_dict = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify)destroy_value);

	sigset_t sigset;
	int sigfd;
	struct signalfd_siginfo sfd_siginfo;
	ssize_t rbytes;

	const int MAX_EVENTS = 8;
	struct epoll_event sigfd_ev, uxfd_ev, tcpfd_ev, ep_events[MAX_EVENTS];
	int epoll_fd;


	struct option longopts[] = {
		{"imgfile",     required_argument, NULL, 'f'},
		{"laddr",       required_argument, NULL, 'l'},
		{"port",        required_argument, NULL, 'p'},
		{"socket",      required_argument, NULL, 's'},
		{"xnbd-binary", required_argument, NULL, 'b'},
		{"cow",         no_argument,       NULL, 'c'},
		{"readonly",    no_argument,       NULL, 'r'},
		{"daemonize",   no_argument,       NULL, 'd'},
		{"logpath",     required_argument, NULL, 'L'},
		{"syslog",      no_argument,       NULL, 'S'},
		{"help",        no_argument,       NULL, 'h'},
		{ NULL,         0,                 NULL,  0 }
	};


	struct custom_log_handler_params log_params = {
		.use_syslog = 0,
		.use_fd = 1,
		.fd = fileno(stderr),
	};
	g_log_set_default_handler(custom_log_handler, (void *)&log_params);

        // default            ...  stderr: on,   syslog: off,  logfile: off
        // logpath            ...  stderr: off,  syslog: off,  logfile: on
        // syslog             ...  stderr: off,  syslog: on,   logfile: off
        // syslog,logpath     ...  stderr: off,  syslog: on,   logfile on
        // daemonize          ...  stderr: off,  syslog: on,   logfile: off
        // daemonize, syslog  ...  stderr: off,  syslog: on,   logfile: off
        // daemonize, logpath ...  stderr: off,  syslog: off,  lofgile: on  // syslog off !
        // daemonize, logpath, syslog  ...  stderr: off,  syslog: on,   logfile: on

	while((ch = getopt_long(argc, argv, "b:f:hl:p:s:SdL:", longopts, NULL)) != -1) {
		switch (ch) {
			case 'L':
				logpath = optarg;
				log_params.use_fd = 1;
				log_params.fd = get_log_fd(logpath);
				info("LOGFILE: %s", logpath);
				g_log_set_default_handler(custom_log_handler, (void *)&log_params);
				break;
			case 'c':
				server_target = "--cow-target";
				break;
			case 'r':
				exec_srv_params.readonly = 1;
				break;
			case 'd':
				daemonize = 1;
				break;
			case 'l':
				laddr = optarg;
				break;
			case 'p':
				port = optarg;
				break;
			case 'f':
				if ((ret = add_diskimg(optarg)) < 0) {
					if (ret == XNBD_IMAGE_ACCESS_ERROR)
						warn("cannot open %s", optarg);
					else if (ret == XNBD_ENOMEN)
						warn("out of memory");
					else if (ret == XNBD_NOT_ADDING_TWICE)
						warn("image cannot be added twice");
				}
				break;
			case 'b':
				child_prog = optarg;
				break;
			case 's':
				ctl_path = optarg;
				break;
			case 'S':
				//log_params.use_syslog = 1;
				syslog = 1;
				break;
			case 'h':
				log_params.fd = fileno(stdout);
				g_log_set_default_handler(custom_log_handler, (void *)&log_params);
				// fall through
			default:
				info(help_string, argv[0]);

				if (ch == 'h')
					return EXIT_SUCCESS;

				return EXIT_FAILURE;
		}
	}

	if (syslog || (daemonize && (logpath == NULL))) {
		log_params.use_syslog = 1;
		exec_srv_params.syslog = 1;
		if (!daemonize)
			log_params.use_fd = 0;
	} else {
		exec_srv_params.syslog = 0;
	}


	if (child_prog == NULL) {
		char *wrapper_abspath = realpath(argv[0], NULL);
		if (asprintf(&child_prog, "%s/xnbd-server", dirname(wrapper_abspath)) == -1) {
			return EXIT_FAILURE;
		}
		free(wrapper_abspath);
	}

	if (access(child_prog, X_OK) != 0) {
		err("check xnbd-binary: %m");
	}

	info("xnbd-binary: %s", child_prog);
	exec_srv_params.binpath = child_prog;


	if (port == NULL) {
		if (asprintf(&port, "%d", XNBD_PORT) == -1) {
			return EXIT_FAILURE;
		}
	}
	info("port: %s", port);


	if (! ctl_path)
		ctl_path = (char *)default_ctl_path;


	if (! server_target)
		server_target = default_server_target;
		//server_target = (char *)default_server_target;

	exec_srv_params.target_mode = server_target;


        if (daemonize)
		if (daemon(0, 0) == -1)
			err("daemon %m");


	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGTERM);
	sigaddset(&sigset, SIGCHLD);
	sigaddset(&sigset, SIGPIPE);
	if (sigprocmask(SIG_BLOCK, &sigset, NULL) == -1)
		err("sigprocmask() : %m");  /* exit */

	sigfd = signalfd(-1, &sigset, 0);
	if (sigfd == -1)
		err("signalfd() : %m");  /* exit */

	epoll_fd = epoll_create1(0);
	if (epoll_fd == -1)
		err("epoll_create : %m");

	/* add signalfd */
	sigfd_ev.events = POLLIN;
	sigfd_ev.data.fd = sigfd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sigfd, &sigfd_ev) == -1) {
		err("epoll_ctl : %m");
	}

	/* add tcp socket */
	if ((sockfd = make_tcp_sock(laddr, port)) == -1)
		err("make_tcp_sock() returned %d", sockfd);
	tcpfd_ev.events = POLLIN;
	tcpfd_ev.data.fd = sockfd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockfd, &tcpfd_ev) == -1) {
		err("epoll_ctl : %m");
	}

	/* add unix socket */
	if ((ux_sockfd = make_unix_sock(ctl_path)) < 0)
		err("make_unix_sock() returned %d", ux_sockfd);
	uxfd_ev.events = POLLIN;
	uxfd_ev.data.fd = ux_sockfd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ux_sockfd, &uxfd_ev) == -1) {
		err("epoll_ctl : %m");
	}

	for (;;) {
		int num_of_fds = epoll_wait(epoll_fd, ep_events, MAX_EVENTS, -1);
			if (num_of_fds == -1)
				err("epoll_wait : %m");
		for (int c_ev = 0; c_ev < num_of_fds; c_ev++) {
			if (ep_events[c_ev].data.fd == sigfd) {
				/* signalfd */
				rbytes = read(sigfd, &sfd_siginfo, sizeof(sfd_siginfo));
				if (rbytes != sizeof(sfd_siginfo))
					err("read sigfd : %m");
				if (sfd_siginfo.ssi_signo == SIGTERM || sfd_siginfo.ssi_signo == SIGINT) {
					close(epoll_fd);
					close(sockfd);
					close(ux_sockfd);
					close(sigfd);
					unlink(ctl_path);
					exit(EXIT_SUCCESS);
				} else if (sfd_siginfo.ssi_signo == SIGCHLD) {
					if ((cpid = waitpid(-1, &cstatus, WNOHANG)) == -1)
						warn("waitpid : %m");
					if (WIFEXITED(cstatus)) 
						warn("pid %ld : exit status %d", (long)cpid, WEXITSTATUS(cstatus));
					forked_srvs--;
					info("forked_srvs : %d", forked_srvs);
				}
			} else if (ep_events[c_ev].data.fd == ux_sockfd) {
				/* unix socket */
				if (pthread_create(&thread, NULL, start_filemgr_thread, (void *)&ux_sockfd))
					warn("pthread_create : %m");
				if (pthread_detach(thread))
					warn("pthread_detach : %m");
				pthread_detach(thread);
			} else if (ep_events[c_ev].data.fd == sockfd) {
				/* tcp socket */
				conn_sockfd = accept(sockfd, NULL, NULL);
				if (conn_sockfd == -1) {
					warn("accept : %m");
					break;
				}

				/* asprintf() is GNU extention */
				if (asprintf(&fd_num, "%d", conn_sockfd) == -1) {
					break;
				}
				info("conn_sockfd: %d", conn_sockfd);

				if (forked_srvs == MAX_NSRVS) {
					close(conn_sockfd);
					warn("fork : reached the limit");
					break;
				}


				pid = fork();
				if (pid == 0) {
					/* child */

					if (sigprocmask(SIG_UNBLOCK, &sigset, NULL) == -1) {
						warn("sigprocmask() : %m");
						_exit(EXIT_FAILURE);
					}

					close(sockfd);
					close(epoll_fd);
					close(ux_sockfd);
					close(sigfd);

					if ((requested_img = nbd_negotiate_with_client_new_phase_0(conn_sockfd)) == NULL) {
						warn("requested_img: NULL");
						close(conn_sockfd);
						_exit(EXIT_FAILURE);
					}
					info("requested_img: %s\n", requested_img);

					if (has_diskimg(requested_img) < 0) {
						if(close(conn_sockfd))
							warn("close(p0)");
						_exit(EXIT_FAILURE);
					}

					stat(requested_img, &sb);
					if (nbd_negotiate_with_client_new_phase_1(conn_sockfd, sb.st_size, 0)) {
						if(close(conn_sockfd))
							warn("close(p1)");
						_exit(EXIT_FAILURE);
					}

					exec_xnbd_server(&exec_srv_params, fd_num, requested_img);

				} else if (pid > 0) {
					/* parent */
					free(fd_num);
					forked_srvs++;
					info("forked_srvs : %d", forked_srvs);
					info("fork: pid %ld", (long)pid);
					close(conn_sockfd);
				} else {
					err("fork: %m");
					break;
				}
			}
		}
	}

	return EXIT_FAILURE;
}
