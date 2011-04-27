#include "xnbd.h"
#include <libgen.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>

/* static const int MAX_DISKIMG_NUM = 32; */
#define MAX_DISKIMG_NUM 32

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

struct diskimg_list {
	int num_of_diskimgs;
	char *diskimgs[MAX_DISKIMG_NUM];
};

static struct diskimg_list dsklist = { .num_of_diskimgs = 0 };

static int add_diskimg(struct diskimg_list *list, char *dname)
{
	int fd;
	if ((fd = open(dname, O_RDONLY)) < 0)
		return -1;
	close(fd);
	if (list->num_of_diskimgs < MAX_DISKIMG_NUM) {
		pthread_mutex_lock(&mutex);
		for (int i = 0; i < list->num_of_diskimgs; i++) {
			if (list->diskimgs[i] == NULL) {
	 			if (asprintf(&list->diskimgs[i], "%s", dname) < 0) {
					pthread_mutex_unlock(&mutex);
					return -3;
				}
				list->num_of_diskimgs++;
				pthread_mutex_unlock(&mutex);
				return 0;
			}
		}
		if (asprintf(&list->diskimgs[list->num_of_diskimgs], "%s", dname) < 0) {
			pthread_mutex_unlock(&mutex);
			return -3;
		}
		list->num_of_diskimgs++;
		pthread_mutex_unlock(&mutex);
		/* return list->num_of_diskimgs; */
		return 0;
	}
	return -2;
}

static int del_diskimg(struct diskimg_list *list, int num)
{
	num--;
	if (num < MAX_DISKIMG_NUM && num >= 0) {
		pthread_mutex_lock(&mutex);
		free(list->diskimgs[num]);
		list->diskimgs[num] = NULL;
		list->num_of_diskimgs--;
		pthread_mutex_unlock(&mutex);
		return 0;
	}
	return -1;
}

static int has_diskimg(struct diskimg_list *list, char *dname)
{
	int range = list->num_of_diskimgs;
	for (int i = 0; i < range; i++) {
		if (list->diskimgs[i] == NULL)
			range++;
		else
			if (strcmp(list->diskimgs[i], dname) == 0)
				return 0;
	}
	return -1;
}

static void list_diskimg(struct diskimg_list *list, FILE *fp)
{
	int range = list->num_of_diskimgs;
	for (int i = 0; i < range; i++) {
		if (list->diskimgs[i] == NULL)
			range++;
		else
			fprintf(fp, "%d : %s\n", i+1, list->diskimgs[i]);
	}
	if (range == 0)
		fprintf(fp, "no item\n");
	fflush(fp);
}

static int make_unix_sock(const char *uxsock_path)
{
	int uxsock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (uxsock == -1) {
		perror("socket(AF_UNIX)");
		return -1;
	}
	struct sockaddr_un ux_saddr;
	strcpy(ux_saddr.sun_path, uxsock_path);
	ux_saddr.sun_family = AF_UNIX;
	if (bind(uxsock, &ux_saddr, sizeof(ux_saddr))) {
		perror("bind(AF_UNIX)");
		pthread_exit(NULL);
	}
	if (listen(uxsock, 8)) {
		perror("listen(AF_UNIX)");
		pthread_exit(NULL);
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
		perror("accept(AF_UNIX)");
		pthread_exit(NULL);
	}
	FILE *fp = fdopen(conn_uxsock, "r+");
	if (count_mgr_threads(1) <= MAX_CTL_CONNS) {
		fprintf(fp, "help command displays help for another command\n");
		for(;;) {
			if (fputs("(xnbd) ", fp) == EOF){
				g_warning("fputs : EOF");
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
				list_diskimg(&dsklist, fp);
			else if (strcmp(cmd, "add") == 0) {
				ret = add_diskimg(&dsklist, arg);
				if (ret == -1)
					fprintf(fp, "cannot open %s\n", arg);
				else if (ret == -2)
					fprintf(fp, "list is full\n");
			}
			else if (strcmp(cmd, "del") == 0)
				del_diskimg(&dsklist, atoi(arg));
			else if (strcmp(cmd, "help") == 0)
				fprintf(fp,
					"list     : show diskimage list\n"
					"add PATH : add diskimage\n"
					"del N    : delete diskimage (N = diskimage number on list)\n"
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
		fprintf(stderr, "%s: %s\n", port, gai_strerror(error));
		return -1;
	}

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		tcp_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (tcp_sock != -1)
			break;
	}

	if (rp == NULL) {
		fprintf(stderr, "rp is NULL\n");
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
		return EXIT_FAILURE;
	}

	return tcp_sock;
}


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
	char ctl_path[] = "/tmp/xnbd_wrapper.ctl";
	int forked_srvs = 0;
	const int MAX_NSRVS = 512;
	
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
		{"xnbd-binary", required_argument, NULL, 'b'},
		{"help",        no_argument,       NULL, 'h'},
		{ NULL,         0,                 NULL,  0 }
	};


	while((ch = getopt_long(argc, argv, "b:f:hl:p:", longopts, NULL)) != -1) {
		switch (ch) {
			case 'l':
				laddr = optarg;
				break;
			case 'p':
				port = optarg;
				break;
			case 'f':
				if ((ret = add_diskimg(&dsklist, optarg)) < 0) {
					if (ret == -1)
						fprintf(stderr, "cannot open %s\n", optarg);
					else if (ret == -2)
						fprintf(stderr, "list is full\n");
					return EXIT_FAILURE;
				}
				break;
			case 'b':
				if (asprintf(&child_prog, "%s", optarg) == -1) {
					return EXIT_FAILURE;
				}
				break;
			case 'h':
			default:
				printf("Usage: \n"
				       "  %s [-p port | --port=port] [-b path-to-xnbdserver | --xnbd-binary=path-to-xnbdserver] [-f disk-image-file --imgfile disk-image-file] [-l listen-addr | --laddr listen-addr ]\n", *argv);
				if (ch == 'h')
					return EXIT_SUCCESS;
				return EXIT_FAILURE;
		}
	}

	if (child_prog == NULL) {
		if (asprintf(&child_prog, "%s/xnbd-server", dirname(*argv)) == -1) {
			return EXIT_FAILURE;
		}
	}

	if (port == NULL) {
		if (asprintf(&port, "%d", XNBD_PORT) == -1) {
			return EXIT_FAILURE;
		}
	}

	g_message("port: %s", port);
	g_message("xnbd-binary: %s", child_prog);
	list_diskimg(&dsklist, stdout);

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGTERM);
	sigaddset(&sigset, SIGCHLD);
	sigaddset(&sigset, SIGPIPE);
	if (sigprocmask(SIG_BLOCK, &sigset, NULL) == -1)
		g_error("sigprocmask() : %s", g_strerror(errno));  /* exit */

	sigfd = signalfd(-1, &sigset, 0);
	if (sigfd == -1)
		g_error("signalfd() : %s", g_strerror(errno));  /* exit */

	epoll_fd = epoll_create1(0);
	if (epoll_fd == -1)
		g_error("epoll_create : %s", g_strerror(errno));

	/* add signalfd */
	sigfd_ev.events = POLLIN;
	sigfd_ev.data.fd = sigfd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sigfd, &sigfd_ev) == -1) {
		g_error("epoll_ctl : %s", g_strerror(errno));
	}

	/* add unix socket */
	ux_sockfd = make_unix_sock(ctl_path);
	uxfd_ev.events = POLLIN;
	uxfd_ev.data.fd = ux_sockfd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ux_sockfd, &uxfd_ev) == -1) {
		g_error("epoll_ctl : %s", g_strerror(errno));
	}

	/* add tcp socket */
	sockfd = make_tcp_sock(laddr, port);
	tcpfd_ev.events = POLLIN;
	tcpfd_ev.data.fd = sockfd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockfd, &tcpfd_ev) == -1) {
		g_error("epoll_ctl : %s", g_strerror(errno));
	}

	for (;;) {
		int num_of_fds = epoll_wait(epoll_fd, ep_events, MAX_EVENTS, -1);
			if (num_of_fds == -1)
				g_error("epoll_wait : %s", g_strerror(errno));
		for (int c_ev = 0; c_ev < num_of_fds; c_ev++) {
			if (ep_events[c_ev].data.fd == sigfd) {
				/* signalfd */
				rbytes = read(sigfd, &sfd_siginfo, sizeof(sfd_siginfo));
				if (rbytes != sizeof(sfd_siginfo))
					g_error("read sigfd : %s", strerror(errno));
				if (sfd_siginfo.ssi_signo == SIGTERM || sfd_siginfo.ssi_signo == SIGINT) {
					close(epoll_fd);
					close(sockfd);
					close(ux_sockfd);
					close(sigfd);
					unlink(ctl_path);
					exit(EXIT_SUCCESS);
				} else if (sfd_siginfo.ssi_signo == SIGCHLD) {
					g_warning("Got SIGCHLD");
					forked_srvs--;
					g_message("forked_srvs : %d", forked_srvs);
				}
			} else if (ep_events[c_ev].data.fd == ux_sockfd) {
				/* unix socket */
				if (pthread_create(&thread, NULL, start_filemgr_thread, (void *)&ux_sockfd))
					g_warning("pthread_create : %s", g_strerror(errno));
				if (pthread_detach(thread))
					g_warning("pthread_detach : %s", g_strerror(errno));
				pthread_detach(thread);
			} else if (ep_events[c_ev].data.fd == sockfd) {
				/* tcp socket */
				conn_sockfd = accept(sockfd, NULL, NULL);
				if (conn_sockfd == -1) {
					perror("accept");
					break;
				}

				/* asprintf() is GNU extention */
				if (asprintf(&fd_num, "%d", conn_sockfd) == -1) {
					break;
				}
				printf("conn_sockfd: %d\n", conn_sockfd);

				if (forked_srvs == MAX_NSRVS) {
					close(conn_sockfd);
					g_warning("fork : reached the limit");
					break;
				}


				pid = fork();
				if (pid == 0) {
					/* child */

					if (sigprocmask(SIG_UNBLOCK, &sigset, NULL) == -1)
						g_error("sigprocmask() : %s", g_strerror(errno));  /* exit */

					close(sockfd);
					close(epoll_fd);
					close(ux_sockfd);
					close(sigfd);

					requested_img = nbd_negotiate_with_client_new_phase_0(conn_sockfd);
					printf("requested_img: %s\n", requested_img);

					if (has_diskimg(&dsklist, requested_img) < 0) {
						if(close(conn_sockfd))
							perror("close(p0)");
						_exit(EXIT_FAILURE);
					}

					stat(requested_img, &sb);
					if (nbd_negotiate_with_client_new_phase_1(conn_sockfd, sb.st_size, 0)) {
						if(close(conn_sockfd))
							perror("close(p1)");
						_exit(EXIT_FAILURE);
					}

					(void)execl(child_prog, child_prog, "--target", "--connected-fd", fd_num, requested_img, (char *)NULL);
					perror("exec");
					_exit(EXIT_FAILURE);
				} else if (pid > 0) {
					/* parent */
					free(fd_num);
					forked_srvs++;
					g_message("forked_srvs : %d", forked_srvs);
					printf("fork: pid %ld\n", (long)pid);
					close(conn_sockfd);
				} else {
					perror("fork");
					break;
				}
			}
		}
	}

	return EXIT_FAILURE;
}
