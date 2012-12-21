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
#include <assert.h>


#define XNBD_IMAGE_ADDED  0
#define XNBD_IMAGE_ACCESS_ERROR  (-1)
#define XNBD_NOT_ADDING_TWICE  (-4)

#define NOT_PROXIED  NULL


pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
GHashTable * p_disk_dict = NULL;
guint images_added_ever = 0;


typedef struct _t_disk_data {
	char * local_exportname;  /* Used as key in the hash table, too. So no need to free keys. */
	char * disk_file_name;
	guint index;
	struct {
		char * target_host;
		char * target_port;
		/* for cache_image see disk_file_name above */
		char * bitmap_image;
		char * control_socket_path;
		char * target_exportname;
	} proxy;

	/* NOTE: Upon extension update destroy_value, copy_disk_data and create_disk_data below, too! */
} t_disk_data;

typedef struct _t_listing_state {
	guint index_to_print;
	guint index_up_next;
	FILE * fp;
} t_listing_state;


static void destroy_value(t_disk_data * p_disk_data) {
	g_free(p_disk_data->local_exportname);
	g_free(p_disk_data->disk_file_name);
	g_free(p_disk_data->proxy.target_host);
	g_free(p_disk_data->proxy.target_port);
	g_free(p_disk_data->proxy.bitmap_image);
	g_free(p_disk_data->proxy.control_socket_path);
	g_free(p_disk_data->proxy.target_exportname);
	g_free(p_disk_data);
}

#define COPY_STRING_MEMBER(FINE, MEMBER, SOURCE, TARGET)  \
	do { \
		if (FINE && SOURCE->MEMBER) { \
			TARGET->MEMBER = g_strdup(SOURCE->MEMBER); \
			if (! TARGET->MEMBER) \
				FINE = 0; \
		} \
	} while (0)

static t_disk_data * copy_disk_data(const t_disk_data * source) {
	int fine = 1;
	t_disk_data * const res = g_try_new(t_disk_data, 1);
	if (! res)
		fine = 0;

	if (fine)
	{
		memset(res, 0, sizeof(t_disk_data));
		res->index = source->index;
	}

	COPY_STRING_MEMBER(fine, local_exportname, source, res);
	COPY_STRING_MEMBER(fine, disk_file_name, source, res);
	COPY_STRING_MEMBER(fine, proxy.target_host, source, res);
	COPY_STRING_MEMBER(fine, proxy.target_port, source, res);
	COPY_STRING_MEMBER(fine, proxy.bitmap_image, source, res);
	COPY_STRING_MEMBER(fine, proxy.control_socket_path, source, res);
	COPY_STRING_MEMBER(fine, proxy.target_exportname, source, res);

	if (fine)
		return res;

	g_free(res->local_exportname);
	g_free(res->disk_file_name);
	g_free(res->proxy.target_host);
	g_free(res->proxy.target_port);
	g_free(res->proxy.bitmap_image);
	g_free(res->proxy.control_socket_path);
	g_free(res->proxy.target_exportname);
	g_free(res);
	return NULL;
}

static t_disk_data * create_disk_data(const char * local_exportname,
		const char * target_host, const char * target_port,
		const char * cache_image, const char * bitmap_image,
		const char * control_socket_path, const char * target_exportname)
{
	assert(cache_image);

	t_disk_data source;
	memset(&source, 0, sizeof(source));

	source.local_exportname = (char *)local_exportname;
	source.disk_file_name = (char *)cache_image;
	/* .index set later */
	source.proxy.target_host = (char *)target_host;
	source.proxy.target_port = (char *)target_port;
	source.proxy.bitmap_image = (char *)bitmap_image;
	source.proxy.control_socket_path = (char *)control_socket_path;
	source.proxy.target_exportname = (char *)target_exportname;

	return copy_disk_data(&source);
}

static gboolean find_by_index(const char * key, const t_disk_data * p_disk_data, gconstpointer user_data) {
	(void)key;

	const guint index_at_addition_time = GPOINTER_TO_UINT(user_data);
	return p_disk_data->index == index_at_addition_time;
}

static gboolean find_by_file(const char * key, const t_disk_data * p_disk_data, const char * filename) {
	(void)key;

	return strcmp(p_disk_data->disk_file_name, filename) == 0;
}

static gboolean find_by_exportname(const char * key, const t_disk_data * p_disk_data, const char * local_exportname) {
	(void)key;

	return strcmp(p_disk_data->local_exportname, local_exportname) == 0;
}

static int add_diskimg(t_disk_data * p_disk_data)
{
	/* Check image access */
	int fd;
	if ((fd = open(p_disk_data->disk_file_name, O_RDONLY)) < 0)
		return XNBD_IMAGE_ACCESS_ERROR;
	close(fd);

	/* Add to hash table */
	pthread_mutex_lock(&mutex);
	int res = XNBD_IMAGE_ADDED;
	/* NOTE: Avoiding g_hash_table_contains since that is glib 2.32+ */
	if (g_hash_table_lookup(p_disk_dict, p_disk_data->local_exportname))
	{
		res = XNBD_NOT_ADDING_TWICE;
	}
	else
	{
		p_disk_data->index = images_added_ever++;
		g_hash_table_insert(p_disk_dict, p_disk_data->local_exportname, p_disk_data);
	}
	pthread_mutex_unlock(&mutex);
	return res;
}

static void del_diskimg_by_index(int num)
{
	num--;
	if (num >= 0) {
		pthread_mutex_lock(&mutex);
		g_hash_table_foreach_remove(p_disk_dict, (GHRFunc)find_by_index, GUINT_TO_POINTER((guint)num));
		pthread_mutex_unlock(&mutex);
	}
}

static void del_diskimg_by_file(const char * filename)
{
	pthread_mutex_lock(&mutex);
	g_hash_table_foreach_remove(p_disk_dict, (GHRFunc)find_by_file, (gpointer)filename);
	pthread_mutex_unlock(&mutex);
}

static void del_diskimg_by_exportname(const char * local_exportname)
{
	pthread_mutex_lock(&mutex);
	g_hash_table_foreach_remove(p_disk_dict, (GHRFunc)find_by_exportname, (gpointer)local_exportname);
	pthread_mutex_unlock(&mutex);
}

static t_disk_data * get_disk_data_for(const char *local_exportname)
{
	t_disk_data * res = NULL;

	pthread_mutex_lock(&mutex);
	const t_disk_data * const source = (t_disk_data *)g_hash_table_lookup(p_disk_dict, local_exportname);
	if (source)
		/* NOTE: We need a deep copy here so that we do not access data that another thread has freed */
		res = copy_disk_data(source);

	pthread_mutex_unlock(&mutex);
	return res;
}

static void find_smallest_index_iterator(gpointer key, const t_disk_data * p_disk_data, t_listing_state * p_listing_state) {
	(void)key;

	if (p_disk_data->index < p_listing_state->index_to_print)
	{
		p_listing_state->index_to_print = p_disk_data->index;
	}
}

static void list_images_iterator(gpointer key, const t_disk_data * p_disk_data, t_listing_state * p_listing_state) {
	(void)key;

	if (p_disk_data->index == p_listing_state->index_to_print)
	{
		guint one_based_index = p_disk_data->index + 1;
		if (p_disk_data->proxy.target_host)
			fprintf(p_listing_state->fp, "%d : %s  (%s:%s%s%s, %s, %s, %s)\n", one_based_index, p_disk_data->local_exportname,
					p_disk_data->proxy.target_host, p_disk_data->proxy.target_port,
					p_disk_data->proxy.target_exportname ? ":" : "",
					p_disk_data->proxy.target_exportname ? p_disk_data->proxy.target_exportname : "",
					p_disk_data->disk_file_name, p_disk_data->proxy.bitmap_image,
					p_disk_data->proxy.control_socket_path);
		else
			fprintf(p_listing_state->fp, "%d : %s  (%s)\n", one_based_index, p_disk_data->local_exportname,
					p_disk_data->disk_file_name);
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

static int hexdig_char_to_int(char c)
{
	switch (c) {
		case '0': return 0;
		case '1': return 1;
		case '2': return 2;
		case '3': return 3;
		case '4': return 4;
		case '5': return 5;
		case '6': return 6;
		case '7': return 7;
		case '8': return 8;
		case '9': return 9;
		case 'a': case 'A': return 10;
		case 'b': case 'B': return 11;
		case 'c': case 'C': return 12;
		case 'd': case 'D': return 13;
		case 'e': case 'E': return 14;
		case 'f': case 'F': return 15;
		default: return -1;
	}
}

#define ADVANCE_COPY_ONE_CHAR(READ_HEAD, WRITE_HEAD)  \
	do { \
		if (READ_HEAD > WRITE_HEAD) { \
			WRITE_HEAD[0] = READ_HEAD[0]; \
		} \
		READ_HEAD += 1; \
		WRITE_HEAD += 1; \
	} while(0)

#define ADVANCE_COPY_TWO_CHARS(READ_HEAD, WRITE_HEAD)  \
	do { \
		if (READ_HEAD > WRITE_HEAD) { \
			WRITE_HEAD[0] = READ_HEAD[0]; \
			WRITE_HEAD[1] = READ_HEAD[1]; \
		} \
		READ_HEAD += 2; \
		WRITE_HEAD += 2; \
	} while(0)

/*
 * Decodes percent-encoded text in-place.
 *
 * We avoid g_uri_unescape_segment because:
 * - it returns NULL on the malformed cases below (rather than skipping the troublemakers)
 * - it does not work in-place which means
 *   - it requires more memory and
 *   - requires out-of-memory handling
 *
 * Handling of well-formed data:
 * "%5a"    -> "Z"
 * "%5A"    -> "Z"
 *
 * Handling of malformed data:
 * "%%5A"   -> "%Z"
 * "%3%5A"  -> "%3Z"
 * "%3g%5A" -> "%3gZ"
 * "%"      -> "%"
 *  "%%"    -> "%%"
 * (similar to Python's urllib.unquote)
 */
static void decode_percent_encoding(char * text)
{
	if (! text)
		return;

	const char * read_head = text;
	char * write_head = text;
	while (read_head[0]) {
		if ((read_head[0] != '%') || ! read_head[1]) {
			ADVANCE_COPY_ONE_CHAR(read_head, write_head);
			continue;
		}

		const int higher = hexdig_char_to_int(read_head[1]);
		if (higher == -1) {
			/* Could still be a new '%', so re-inspect it next round */
			ADVANCE_COPY_ONE_CHAR(read_head, write_head);
			continue;
		}

		if (! read_head[2]) {
			/* Copy two character unmodified */
			ADVANCE_COPY_TWO_CHARS(read_head, write_head);
			continue;
		}

		const int lower = hexdig_char_to_int(read_head[2]);
		if (lower == -1) {
			/* Could still be a new '%', so re-inspect it next round */
			ADVANCE_COPY_TWO_CHARS(read_head, write_head);
			continue;
		}

		assert((0 <= higher) && (higher < 16));
		assert((0 <= lower) && (lower < 16));

		/* Copy "%.." in decoded form */
		write_head[0] = 16 * higher + lower;
		read_head += 3;
		write_head += 1;
	}

	if (read_head > write_head) {
		write_head[0] = '\0';
	}
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
	const int rbufsize = 128 * 8;
	
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
				/* Remove trailing newline so it does not end up in the last argument */
				const size_t buf_len = strlen(buf);
				if ((buf_len > 0) && (buf[buf_len - 1] == '\n'))
					buf[buf_len - 1] = '\0';

				const unsigned int EXPECTED_ARGC_MIN = 1 + 1;
				const unsigned int EXPECTED_ARGC_MAX = 1 + 1 + 1;
				const unsigned int MAX_ARGC = EXPECTED_ARGC_MAX + 1;  /* +1 or we do not notice g_strsplit's internal merging */
				gchar ** argv = g_strsplit(buf, " ", MAX_ARGC);
				if (argv)
				{
					/* Calculate argc from argv */
					unsigned int argc = 0;
					while (argv[argc])
						argc++;

					if ((argc < EXPECTED_ARGC_MIN) || (argc > EXPECTED_ARGC_MAX)) {
						fprintf(fp, "usage: add [<EXPORTNAME>] FILE\n");
					} else {
						int i = 1;
						for (; i < argc; i++)
							decode_percent_encoding(argv[i]);

						const char * const file = (argc == 3) ? argv[2] : argv[1];
						const char * const exportname = (argc == 3) ? argv[1] : file;

						t_disk_data * const p_disk_data = create_disk_data(exportname, NOT_PROXIED, NOT_PROXIED, file, NOT_PROXIED, NOT_PROXIED, NOT_PROXIED);
						if (p_disk_data)
						{
							ret = add_diskimg(p_disk_data);
							if (ret == XNBD_IMAGE_ACCESS_ERROR)
								fprintf(fp, "cannot open %s\n", file);
							else if (ret == XNBD_NOT_ADDING_TWICE)
								fprintf(fp, "image cannot be added twice\n");
						}
						else
						{
							fprintf(fp, "out of memory\n");
						}
					}
					g_strfreev(argv);
				}
				else
				{
					fprintf(fp, "out of memory\n");
				}
			}
			else if (strcmp(cmd, "add-proxy") == 0) {
				/* Remove trailing newline so it does not end up in the last argument */
				const size_t buf_len = strlen(buf);
				if ((buf_len > 0) && (buf[buf_len - 1] == '\n'))
					buf[buf_len - 1] = '\0';

				const unsigned int EXPECTED_ARGC_MIN = 1 + 6;
				const unsigned int EXPECTED_ARGC_MAX = 1 + 6 + 1;
				const unsigned int MAX_ARGC = EXPECTED_ARGC_MAX + 1;  /* +1 or we do not notice g_strsplit's internal merging */
				gchar ** argv = g_strsplit(buf, " ", MAX_ARGC);
				if (argv)
				{
					/* Calculate argc from argv */
					unsigned int argc = 0;
					while (argv[argc])
						argc++;

					if ((argc < EXPECTED_ARGC_MIN) || (argc > EXPECTED_ARGC_MAX)) {
						fprintf(fp, "usage: add-proxy <LOCAL_EXPORTNAME> <TARGET_HOST> <TARGET_PORT> <CACHE_IMAGE> <BITMAP_IMAGE> <CONTROL_SOCKET_PATH> [<TARGET_EXPORTNAME>]\n");
					} else {
						int i = 1;
						for (; i < argc; i++)
							decode_percent_encoding(argv[i]);

						const char * const local_exportname = argv[1];
						const char * const target_host = argv[2];
						const char * const target_port = argv[3];
						const char * const cache_image = argv[4];
						const char * const bitmap_image = argv[5];
						const char * const control_socket_path = argv[6];
						const char * const target_exportname = (argc > 7) ? argv[7] : NULL;

						t_disk_data * const p_disk_data = create_disk_data(local_exportname, target_host, target_port, cache_image, bitmap_image, control_socket_path, target_exportname);
						if (! p_disk_data)
						{
							fprintf(fp, "out of memory\n");
						}
						else
						{
							ret = add_diskimg(p_disk_data);
							if (ret == XNBD_IMAGE_ACCESS_ERROR)
								fprintf(fp, "cannot open %s\n", cache_image);
							else if (ret == XNBD_NOT_ADDING_TWICE)
								fprintf(fp, "image cannot be added twice\n");
						}
					}
					g_strfreev(argv);
				}
				else
				{
					fprintf(fp, "out of memory\n");
				}
			}
			else if (strcmp(cmd, "del") == 0)
				del_diskimg_by_index(atoi(arg));
			else if (strcmp(cmd, "del-file") == 0) {
				decode_percent_encoding(arg);
				del_diskimg_by_file(arg);
			} else if (strcmp(cmd, "del-exportname") == 0) {
				decode_percent_encoding(arg);
				del_diskimg_by_exportname(arg);
			} else if (strcmp(cmd, "shutdown") == 0) {
				perform_shutdown(fp);
			}
			else if (strcmp(cmd, "help") == 0)
				fprintf(fp,
					"  list                 : show list of disk images\n"
					"\n"
					"  add [NAME] PATH      : add disk image in target mode\n"
					"  add-proxy ...        : add disk image in proxy mode\n"
					"\n"
					"  del INDEX            : delete disk image by index\n"
					"  del-file FILE        : delete disk image by file name\n"
					"  del-exportname NAME  : delete disk image by export name\n"
					"\n"
					"  shutdown             : terminate all images and shutdown xnbd-wrapper instance\n"
					"  quit                 : quit (disconnect)\n");
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

static void exec_xnbd_server(struct exec_params *params, char *fd_num, const t_disk_data * disk_data)
{
	char *args[8 + 4 + 2];
	int i = 0;
	args[i] = params->binpath;

	if (disk_data->proxy.target_host) {
		args[++i] = (char *)"--proxy";
	} else {
		args[++i] = (char *)params->target_mode;
	}

	if (params->readonly)
		args[++i] = (char *)"--readonly";
	if (params->syslog)
		args[++i] = (char *)"--syslog";
	args[++i] = (char *)"--connected-fd";
	args[++i] = fd_num;

	if (disk_data->proxy.target_host)
	{
		if (disk_data->proxy.target_exportname) {
			args[++i] = (char *)"--target-exportname";
			args[++i] = disk_data->proxy.target_exportname;
		}
		args[++i] = disk_data->proxy.target_host;
		args[++i] = disk_data->proxy.target_port;
		args[++i] = disk_data->disk_file_name;
		args[++i] = disk_data->proxy.bitmap_image;
		args[++i] = disk_data->proxy.control_socket_path;
	}
	else
	{
		args[++i] = disk_data->disk_file_name;
	}

	args[++i] = NULL;

#ifdef XNBD_DEBUG
	{
		info("About to execute...");
		char ** walker = args;
		while (*walker)
		{
			info("[%ld] \"%s\"", walker - args, *walker);
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
	"  %s [--lport port] [--xnbd-binary path-to-xnbdserver] [--imgfile disk-image-file] [--laddr listen-addr] [--socket socket-path]\n"
	"\n"
	"Options: \n"
	"  --daemonize   run wrapper as a daemon process\n"
	"  --cow         run server instances as a cow target\n"
	"  --readonly    run server instances as a readonly target.\n"
	"  --lport       Listen port (default: 8520).\n"
	" (--port)       Deprecated, please use --lport instead.\n"
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
	"  xnbd-wrapper --imgfile /data/disk1 --imgfile /data/disk2 --xnbd-binary /usr/local/bin/xnbd-server --laddr 127.0.0.1 --lport 18520 --socket /tmp/xnbd_wrapper_1.ctl\n";


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
		{"lport",       required_argument, NULL, 'p'},
		{"port",        required_argument, NULL, 'p'}, /* DEPRECATED */
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
			{
				const char * const local_exportname = optarg;
				const char * const filename = optarg;
				t_disk_data * const p_disk_data = create_disk_data(local_exportname, NOT_PROXIED, NOT_PROXIED, filename, NOT_PROXIED, NOT_PROXIED, NOT_PROXIED);
				if (p_disk_data)
				{
					if ((ret = add_diskimg(p_disk_data)) < 0) {
						if (ret == XNBD_IMAGE_ACCESS_ERROR)
							warn("cannot open %s", filename);
						else if (ret == XNBD_NOT_ADDING_TWICE)
							warn("image cannot be added twice");
					}
				}
				else
				{
					warn("out of memory");
				}
				break;
			}
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

					const t_disk_data * const disk_data = get_disk_data_for(requested_img);
					if (! disk_data) {
						if(close(conn_sockfd))
							warn("close(p0)");
						_exit(EXIT_FAILURE);
					}

					if (stat(disk_data->disk_file_name, &sb) == -1) {
						warn("stat failed: %s", disk_data->disk_file_name);
						if(close(conn_sockfd))
							warn("close(p1)");
						_exit(EXIT_FAILURE);
					}

					if (nbd_negotiate_with_client_new_phase_1(conn_sockfd, sb.st_size, 0)) {
						if(close(conn_sockfd))
							warn("close(p2)");
						_exit(EXIT_FAILURE);
					}

					exec_xnbd_server(&exec_srv_params, fd_num, disk_data);

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
