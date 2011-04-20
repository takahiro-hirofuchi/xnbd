#include "xnbd.h"
#include <libgen.h>

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

static void *start_filemgr()
{
	const int rbufsize = 128;

	int mgt_uxsock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (mgt_uxsock == -1) {
		perror("socket(AF_UNIX)");
		pthread_exit(NULL);
	}
	struct sockaddr_un mgt_saddr;
	char uxsock_path[] = "/tmp/xnbd_wrapper.sock";
	strcpy(mgt_saddr.sun_path, uxsock_path);
	mgt_saddr.sun_family = AF_UNIX;
	if (bind(mgt_uxsock, &mgt_saddr, sizeof(mgt_saddr))) {
		perror("bind(AF_UNIX)");
		pthread_exit(NULL);
	}
	if (listen(mgt_uxsock, 8)) {
		perror("listen(AF_UNIX)");
		pthread_exit(NULL);
	}
	
	char buf[rbufsize];
	char cmd[rbufsize];
	char arg[rbufsize];
	int ret;
	for(;;) {
		int conn_uxsock = accept(mgt_uxsock, NULL, NULL);
                if (conn_uxsock == -1) {
                        perror("accept(AF_UNIX)");
                        break;
			pthread_exit(NULL);
		}
		FILE *fp = fdopen(conn_uxsock, "r+");
		fprintf(fp, "help command displays help for another command\n");
		for(;;) {
			fputs("(xnbd) ", fp);
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
		close(conn_uxsock);
		free(fp);
	}
	close(mgt_uxsock);
	remove(uxsock_path);
	/* just to avoid warning */
	return NULL;
}


int main(int argc, char **argv) {
	char *fd_num;
	pid_t pid;
	int error;
	int optval;
	char *child_prog = NULL;
	char *laddr = NULL;
	char *port = NULL;
	int sockfd, conn_sockfd;
	int ch, ret;
	struct addrinfo hints;
	struct addrinfo *res, *rp;
	char *requested_img = NULL;
	struct stat sb;
	pthread_t thread;
	

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

	printf("port: %s\n", port);
	printf("xnbd-binary: %s\n", child_prog);
	list_diskimg(&dsklist, stdout);

	pthread_create(&thread, NULL, start_filemgr, NULL);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	error = getaddrinfo(laddr, port, &hints, &res);
	if (error) {
		fprintf(stderr, "%s: %s\n", port, gai_strerror(error));
		return EXIT_FAILURE;
	}

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sockfd != -1)
			break;
	}

	if (rp == NULL) {
		fprintf(stderr, "rp is NULL\n");
		return EXIT_FAILURE;
	}

	optval = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))) {
		perror("setsockopt");
		return EXIT_FAILURE;
	}

	if (bind(sockfd, rp->ai_addr, rp->ai_addrlen)) {
		perror("bind");
		return EXIT_FAILURE;
	}

	freeaddrinfo(res);

	if (listen(sockfd, 64)) {
		perror("listen");
		return EXIT_FAILURE;
	}

	for (;;) {
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


		pid = fork();
		if (pid == 0) {
			/* child */
			close(sockfd);

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
			printf("fork: pid %ld\n", (long)pid);
			close(conn_sockfd);
		} else {
			perror("fork");
			break;
		}
	}

	return EXIT_FAILURE;
}
