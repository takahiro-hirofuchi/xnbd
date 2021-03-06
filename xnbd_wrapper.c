/*
 * xNBD - an enhanced Network Block Device program
 *
 * Copyright (C) 2008-2014 National Institute of Advanced Industrial Science
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
#include <stdbool.h>

#include <jansson.h>


#define XNBD_IMAGE_ADDED  0
#define XNBD_IMAGE_ACCESS_ERROR  (-1)
#define XNBD_NOT_ADDING_TWICE  (-4)

#define NOT_PROXIED  NULL

#define ARGC_RANGE(min, max)  (min), (max)

#define ARGV_SUCCESS  0
#define ARGV_ENOMEM  1
#define ARGV_ERROR_USAGE  2

#define MESSAGE_ENOMEM  "out of memory"

#define TRYLOCK_SUCCEEDED  0

#define REMOVE_FROM_SET  TRUE
#define KEEP_IN_SET  FALSE


pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
GHashTable * p_disk_dict = NULL;
GHashTable * p_server_pid_set = NULL;
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

	/* NOTE: Upon extension update destroy_value, copy_disk_data, mark_proxy_mode_ended and create_disk_data below, too! */
} t_disk_data;

typedef struct _t_thread_data {
	int conn_uxsock;
	const char * xnbd_bgctl_command;
	const char * database_file_name;
	int * p_child_process_count;
} t_thread_data;

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

static void inform_xnbd_server_termination(pid_t pid, int status) {
	if (WIFEXITED(status)) {
		warn("pid %ld : exit status %d", (long)pid, WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		warn("pid %ld : terminated by signal %d", (long)pid, WTERMSIG(status));
	}
}

static void about_to_execute(const char * const * argv) {
#ifdef XNBD_DEBUG
	{
		info("About to execute...");
		const char * const * walker = argv;
		while (*walker)
		{
			info("[%td] \"%s\"", walker - argv, *walker);
			walker++;
		}
	}
#else
	(void)argv;
#endif
}

static void execvp_or_abort(const char * const * argv)
{
	(void)execvp(argv[0], (char **)argv);

	warn("exec failed");
	_exit(EXIT_FAILURE);
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

static int del_diskimg_by_index(int num)
{
	guint removed_count = 0;

	num--;
	if (num >= 0) {
		pthread_mutex_lock(&mutex);
		removed_count = g_hash_table_foreach_remove(p_disk_dict, (GHRFunc)find_by_index, GUINT_TO_POINTER((guint)num));
		pthread_mutex_unlock(&mutex);
	}

	return (removed_count > 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int del_diskimg_by_file(const char * filename)
{
	pthread_mutex_lock(&mutex);
	const guint removed_count = g_hash_table_foreach_remove(p_disk_dict, (GHRFunc)find_by_file, (gpointer)filename);
	pthread_mutex_unlock(&mutex);

	return (removed_count > 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int del_diskimg_by_exportname(const char * local_exportname)
{
	pthread_mutex_lock(&mutex);
	const guint removed_count = g_hash_table_foreach_remove(p_disk_dict, (GHRFunc)find_by_exportname, (gpointer)local_exportname);
	pthread_mutex_unlock(&mutex);

	return (removed_count > 0) ? EXIT_SUCCESS : EXIT_FAILURE;
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

#define G_FREE_SET_NULL(p)  \
	do { \
		g_free(p); \
		p = NULL; \
	} while(0)

static void mark_proxy_mode_ended(const char * local_exportname)
{
	pthread_mutex_lock(&mutex);
	t_disk_data * const p_disk_data = (t_disk_data *)g_hash_table_lookup(p_disk_dict, local_exportname);
	if (p_disk_data) {
		G_FREE_SET_NULL(p_disk_data->proxy.target_host);
		G_FREE_SET_NULL(p_disk_data->proxy.target_port);
		G_FREE_SET_NULL(p_disk_data->proxy.bitmap_image);
		G_FREE_SET_NULL(p_disk_data->proxy.control_socket_path);
		G_FREE_SET_NULL(p_disk_data->proxy.target_exportname);
	}
	pthread_mutex_unlock(&mutex);
}

#define G_FREE_SET_DUPED(target, source)  \
	do { \
		g_free(target); \
		target = g_strdup(source); \
	} while(0)

static void update_proxy_settings(const char * local_exportname, const char * host, const char * port, const char * target_exportname) {
	pthread_mutex_lock(&mutex);
	t_disk_data * const p_disk_data = (t_disk_data *)g_hash_table_lookup(p_disk_dict, local_exportname);
	if (p_disk_data) {
		G_FREE_SET_DUPED(p_disk_data->proxy.target_host, host);
		G_FREE_SET_DUPED(p_disk_data->proxy.target_port, port);
		G_FREE_SET_DUPED(p_disk_data->proxy.target_exportname, target_exportname);
	}
	pthread_mutex_unlock(&mutex);
}

static gboolean waitpid_nohang_ghrfunc(gpointer key, gpointer value, gpointer user_data) {
	(void)value;
	const pid_t server_pid = (pid_t)GPOINTER_TO_INT(key);
	int * const p_child_process_count = (int *)user_data;

	int status;
	const pid_t waitpid_res = waitpid(server_pid, &status, WNOHANG);
	if (waitpid_res != server_pid) {
		return KEEP_IN_SET;
	}

	inform_xnbd_server_termination(server_pid, status);

	pthread_mutex_lock(&mutex);
	(*p_child_process_count)--;
	info("child_process_count-- : %d  (xnbd-server terminated)", (*p_child_process_count));
	pthread_mutex_unlock(&mutex);

	return REMOVE_FROM_SET;
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

static void report_return_code(FILE * fp, int code)
{
	if (code < 0) {
		code = EXIT_FAILURE;
	}

	fprintf(fp, "return code %d\n", code);
	fflush(fp);
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
}

static void add_disk_to_json_ghfunc(gpointer key, const t_disk_data * p_disk_data, json_t * json_root) {
	(void)key;
	json_t * const disk_property_dict = json_object();
	json_object_set_new(json_root, p_disk_data->local_exportname, disk_property_dict);

	const char * mode = (p_disk_data->proxy.target_host) ? "proxy" : "target";
	json_object_set_new(disk_property_dict, "mode", json_string(mode));
	json_object_set_new(disk_property_dict, "image_path", json_string(p_disk_data->disk_file_name));
	if (p_disk_data->proxy.target_host) {
		json_object_set_new(disk_property_dict, "remote_host", json_string(p_disk_data->proxy.target_host));
		json_object_set_new(disk_property_dict, "remote_port", json_string(p_disk_data->proxy.target_port));
		json_object_set_new(disk_property_dict, "bitmap_path", json_string(p_disk_data->proxy.bitmap_image));
		json_object_set_new(disk_property_dict, "control_socket_path", json_string(p_disk_data->proxy.control_socket_path));
		json_t * const target_exportname = (p_disk_data->proxy.target_exportname)
				? json_string(p_disk_data->proxy.target_exportname)
				: json_null();
		json_object_set_new(disk_property_dict, "remote_export_name", target_exportname);
	}
}

static bool ensure_directory_of_file_exists(FILE * fp, const char * filename) {
	g_assert(filename);
	char * const dup = strdup(filename);
	if (! dup) {
		return false;
	}

	const char * const dir = dirname(dup);
	g_assert(dir);

	if (strcmp(dir, "") && strcmp(dir, ".") && strcmp(dir, "/")) {
		const int mkdir_res = mkdir(dir, 0700);
		if (mkdir_res == -1) {
			if (errno != EEXIST) {
				fprintf(fp, "Directory \"%s\": Could not create, error %d: %s\n", dir, errno, strerror(errno));
				free(dup);
				return false;
			}
		} else {
			fprintf(fp, "Directory \"%s\" created.\n", dir);
		}
	}

	free(dup);
	return true;
}

static ssize_t io_all(int fd, char *buf, size_t bytes_total, int reading)
{
	size_t bytes_done = 0;
	while (bytes_done < bytes_total) {
		ssize_t res;
		if (reading)
			res = read(fd, buf + bytes_done, bytes_total - bytes_done);
		else
			res = write(fd, buf + bytes_done, bytes_total - bytes_done);

		if (res == -1)
			return -1;
		else
			bytes_done += res;
	}

	return bytes_done;
}

static bool dump_registered_images_UNLOCKED(FILE * fp, const char * json_filename) {
	if (! ensure_directory_of_file_exists(fp, json_filename)) {
		return false;
	}

	const int fd = open(json_filename, O_WRONLY | O_CREAT | O_NOFOLLOW, 0600);
	if (fd == -1) {
		fprintf(fp, "File \"%s\": Could not open/create, error %d: %s\n", json_filename, errno, strerror(errno));
		return false;
	}

	struct stat props;
	const int fstat_res = fstat(fd, &props);
	if (fstat_res == -1) {
		fprintf(fp, "File \"%s\": Could not fstat, error %d: %s\n", json_filename, errno, strerror(errno));
		close(fd);
		return false;
	}

	if (! S_ISREG(props.st_mode)) {
		fprintf(fp, "File \"%s\": Not a regular file, refusing to write to it\n", json_filename);
		close(fd);
		return false;
	}

	if (props.st_nlink > 1) {
		fprintf(fp, "File \"%s\": Detected hard-link, refusing to write to it\n", json_filename);
		close(fd);
		return false;
	}

	const int ftruncate_res = ftruncate(fd, 0);
	if (ftruncate_res == -1) {
		fprintf(fp, "File \"%s\": Could not truncate, error %d: %s\n", json_filename, errno, strerror(errno));
		close(fd);
		return false;
	}

	/* Aggregate JSON */
	json_t * const json_root = json_object();
	json_t * const images_dict = json_object();
	json_object_set_new(json_root, "version", json_integer(2));
	json_object_set_new(json_root, "images", images_dict);
	g_hash_table_foreach(p_disk_dict, (GHFunc)add_disk_to_json_ghfunc, images_dict);
	char * const json_content = json_dumps(json_root, JSON_INDENT(4) | JSON_SORT_KEYS);
	json_decref(json_root);

	/* Write data to the dbpath */
	const ssize_t bytes_total = strlen(json_content);
	const ssize_t write_res = io_all(fd, json_content, bytes_total, 0);
	if (write_res == -1) {
		fprintf(fp, "File \"%s\": Could not write, error %d: %s\n", json_filename, errno, strerror(errno));

		free(json_content);
		close(fd);
		return false;
	}

	free(json_content);
	close(fd);

	fprintf(fp, "Database written to file \"%s\".\n", json_filename);
	return true;
}

static bool perform_save(FILE * fp, const char * json_filename) {
	pthread_mutex_lock(&mutex);
	const bool success = dump_registered_images_UNLOCKED(fp, json_filename);
	pthread_mutex_unlock(&mutex);
	return success;
}

static void perform_shutdown(FILE * fp, bool kill_child_processes)
{
	if (kill_child_processes) {
		fprintf(fp, "All images terminated\n");
		kill(0, SIGTERM);  /* includes ourselves */
	} else {
		kill(getpid(), SIGTERM);  /* just ourselves */
	}
}

static void auto_save(const char * json_filename) {
	FILE * const dev_null = fopen("/dev/null", "w");
	const bool success = perform_save(dev_null, json_filename);
	fclose(dev_null);

	if (success)
		info("Database saved");
	else
		warn("Failed to write database to \"%s\"", json_filename);
}

static bool load_database_json(json_t * root,
		int * p_count_added, int * p_count_skipped) {
	g_assert(root);
	g_assert(p_count_added);
	g_assert(p_count_skipped);

	if (! json_is_object(root)) {
		info("Root must be an object/dictionary");
		return false;
	}

	json_t * const version = json_object_get(root, "version");
	if (version) {
		const json_int_t version_int = json_integer_value(version);
		if (version_int != 2) {
			info("File format version %" JSON_INTEGER_FORMAT " is not supported", version_int);
			return false;
		}
	} else {
		info("File format version must be an integer");
		return false;
	}

	json_t * const images = json_object_get(root, "images");
	if (! images) {
		return true;
	}

	if (! json_is_object(images)) {
		info("Images must be an object/dictionary");
		return false;
	}

	void * iter = json_object_iter(images);
	while (iter) {
		const char * local_export_name = json_object_iter_key(iter);
		json_t * const properties_json = json_object_iter_value(iter);
		if (! properties_json) {
			info("Image \"%s\": Properties missing", local_export_name);
			return false;
		}
		if (! json_is_object(properties_json)) {
			info("Image \"%s\": Properties must be an object/dictionary", local_export_name);
			return false;
		}
		json_t * const mode_json = json_object_get(properties_json, "mode");
		if (! mode_json) {
			info("Image \"%s\": Attribute \"mode\" must be set", local_export_name);
			return false;
		}
		if (! json_is_string(mode_json)) {
			info("Image \"%s\": Attribute \"mode\" must be a string", local_export_name);
			return false;
		}

		const char * const mode = json_string_value(mode_json);
		if (! strcmp(mode, "target")) {
			json_t * const image_path_json = json_object_get(properties_json, "image_path");
			if (! image_path_json) {
				info("Image \"%s\": Attribute \"image_path\" must be set", local_export_name);
				return false;
			}
			if (! json_is_string(image_path_json)) {
				info("Image \"%s\": Attribute \"image_path\" must be a string", local_export_name);
				return false;
			}
			const char * const image_path = json_string_value(image_path_json);

			t_disk_data * const p_disk_data = create_disk_data(
					local_export_name, NOT_PROXIED, NOT_PROXIED, image_path,
					NOT_PROXIED, NOT_PROXIED, NOT_PROXIED);
			if (! p_disk_data)
				err("%s", MESSAGE_ENOMEM);

			const int ret = add_diskimg(p_disk_data);
			if (ret == XNBD_IMAGE_ACCESS_ERROR) {
				warn("Image \"%s\": Adding failed, failed to open", image_path);
			} else if (ret == XNBD_NOT_ADDING_TWICE) {
				warn("Image \"%s\": Adding failed, cannot add twice", image_path);
			} else if (ret == XNBD_IMAGE_ADDED) {
				info("Image \"%s\" added (%s)", local_export_name, image_path);
			} else {
				warn("Image \"%s\": Adding failed, unknown error %d", local_export_name, ret);
			}

			int * const p_count = (ret == XNBD_IMAGE_ADDED) ? p_count_added : p_count_skipped;
			(*p_count)++;
		} else if (! strcmp(mode, "proxy")) {
			json_t * const image_path_json = json_object_get(properties_json, "image_path");
			if (! image_path_json) {
				info("Image \"%s\": Attribute \"image_path\" must be set", local_export_name);
				return false;
			}
			if (! json_is_string(image_path_json)) {
				info("Image \"%s\": Attribute \"image_path\" must be a string", local_export_name);
				return false;
			}
			const char * const image_path = json_string_value(image_path_json);

			json_t * const bitmap_path_json = json_object_get(properties_json, "bitmap_path");
			if (! bitmap_path_json) {
				info("Image \"%s\": Attribute \"bitmap_path\" must be set", local_export_name);
				return false;
			}
			if (! json_is_string(bitmap_path_json)) {
				info("Image \"%s\": Attribute \"bitmap_path\" must be a string", local_export_name);
				return false;
			}
			const char * const bitmap_path = json_string_value(bitmap_path_json);

			json_t * const control_socket_path_json = json_object_get(properties_json, "control_socket_path");
			if (! control_socket_path_json) {
				info("Image \"%s\": Attribute \"control_socket_path\" must be set", local_export_name);
				return false;
			}
			if (! json_is_string(control_socket_path_json)) {
				info("Image \"%s\": Attribute \"control_socket_path\" must be a string", local_export_name);
				return false;
			}
			const char * const control_socket_path = json_string_value(control_socket_path_json);

			json_t * const remote_export_name_json = json_object_get(properties_json, "remote_export_name");
			if (remote_export_name_json) {
				if (! json_is_string(remote_export_name_json) && ! json_is_null(remote_export_name_json)) {
					info("Image \"%s\": Attribute \"remote_export_name\" must be null or a string", local_export_name);
					return false;
				}
			}
			const char * const remote_export_name = remote_export_name_json
					? (json_is_null(remote_export_name_json)
						? NULL
						: json_string_value(remote_export_name_json))
					: NULL;

			json_t * const remote_host_json = json_object_get(properties_json, "remote_host");
			if (! remote_host_json) {
				info("Image \"%s\": Attribute \"remote_host\" must be set", local_export_name);
				return false;
			}
			if (! json_is_string(remote_host_json)) {
				info("Image \"%s\": Attribute \"remote_host\" must be a string", local_export_name);
				return false;
			}
			const char * const remote_host = json_string_value(remote_host_json);

			json_t * const remote_port_json = json_object_get(properties_json, "remote_port");
			if (! remote_port_json) {
				info("Image \"%s\": Attribute \"remote_port\" must be set", local_export_name);
				return false;
			}
			if (! json_is_string(remote_port_json)) {
				info("Image \"%s\": Attribute \"remote_port\" must be a string", local_export_name);
				return false;
			}
			const char * const remote_port = json_string_value(remote_port_json);

			t_disk_data * const p_disk_data = create_disk_data(
						local_export_name, remote_host, remote_port, image_path,
						bitmap_path, control_socket_path, remote_export_name);
			if (! p_disk_data)
				err("%s", MESSAGE_ENOMEM);

			const int ret = add_diskimg(p_disk_data);
			if (ret == XNBD_IMAGE_ACCESS_ERROR) {
				warn("Image \"%s\": Adding failed, failed to open", image_path);
			} else if (ret == XNBD_NOT_ADDING_TWICE) {
				warn("Image \"%s\": Adding failed, cannot add twice", image_path);
			} else if (ret == XNBD_IMAGE_ADDED) {
				info("Image \"%s\" added (%s:%s%s%s, %s, %s, %s)", local_export_name,
						remote_host, remote_port,
						remote_export_name ? ":" : "",
						remote_export_name ? remote_export_name : "",
						image_path, bitmap_path, control_socket_path);
			} else {
				warn("Image \"%s\": Adding failed, unknown error %d", local_export_name, ret);
			}

			int * const p_count = (ret == XNBD_IMAGE_ADDED) ? p_count_added : p_count_skipped;
			(*p_count)++;
		} else {
			info("Image \"%s\": mode \"%s\" not supported", local_export_name, mode);
			return false;
		}

		iter = json_object_iter_next(images, iter);
	}
	return true;
}

static void load_database_file_or_abort(const char * json_filename) {
	const int fd = open(json_filename, O_RDONLY | O_NOFOLLOW);
	if (fd == -1) {
		if (errno == ENOENT) {
			info("No previous state to restore, file %s not found.", json_filename);
			return;
		} else {
			err("File \"%s\": Could not open, error %d: %s", json_filename, errno, strerror(errno));
		}
	}

	struct stat props;
	const int fstat_res = fstat(fd, &props);
	if (fstat_res == -1) {
		err("File \"%s\": Could not fstat, error %d: %s", json_filename, errno, strerror(errno));
	}

	if (! S_ISREG(props.st_mode)) {
		err("File \"%s\": Not a regular file, refusing to read from it", json_filename);
	}

	if (props.st_nlink > 1) {
		err("File \"%s\": Detected hard-link, refusing to read from it", json_filename);
	}

	/* Read data from the dbpath */
	const ssize_t bytes_total = props.st_size;
	char * const json_buffer = g_malloc(bytes_total);
	const ssize_t read_res = io_all(fd, json_buffer, bytes_total, 1);
	if (read_res == -1) {
		err("File \"%s\": Could not read, error %d: %s", json_filename, errno, strerror(errno));
	}
	close(fd);

	json_error_t json_error;
	json_t * const root = json_loadb(json_buffer, bytes_total, 0, &json_error);
	free(json_buffer);
	if (! root) {
		err("File \"%s\" (line %d, column %d): Invalid JSON: %s", json_filename, json_error.line, json_error.column, json_error.text);
	}

	int count_added = 0;
	int count_skipped = 0;

	if (! load_database_json(root, &count_added, &count_skipped))
		err("Loading datebase state from %s failed.", json_filename);

	json_decref(root);

	info("Database loaded (%d of %d images skipped)", count_skipped, count_skipped + count_added);

	if (count_skipped) {
		/* Rename current file to .prev for human inspection since
		 * on exit the original location is re-written with the skipped volumes removed */
		char * backup_filename = NULL;
		const int res = asprintf(&backup_filename, "%s.prev", json_filename);
		if (res == -1)
			err("%s", MESSAGE_ENOMEM);

		const int unlink_res = unlink(backup_filename);
		if (unlink_res == -1) {
			if (errno != ENOENT) {
				warn("File \"%s\": Could not remove, error %d: %s", backup_filename, errno, strerror(errno));
			}
		} else {
			info("File \"%s\" removed", backup_filename);
		}

		const int rename_res = rename(json_filename, backup_filename);
		if (rename_res == -1) {
			warn("File \"%s\": Could not rename to \"%s\", error %d: %s", json_filename, backup_filename, errno, strerror(errno));
		} else {
			info("File \"%s\" renamed to \"%s\".", json_filename, backup_filename);
		}

		free(backup_filename);

		auto_save(json_filename);
	}
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

static int extract_decode_check_usage(char * buf, gchar *** p_argv, guint * p_argc, guint argc_min, guint argc_max)
{
	/* Remove trailing newline so it does not end up in the last argument */
	const size_t buf_len = strlen(buf);
	if ((buf_len > 0) && (buf[buf_len - 1] == '\n'))
		buf[buf_len - 1] = '\0';

	gchar ** const argv = g_strsplit(buf, " ", argc_max + 1);  /* +1 or we do not notice g_strsplit's internal merging */
	if (! argv)
	{
		*p_argv = NULL;
		*p_argc = 0;
		return ARGV_ENOMEM;
	}

	/* Calculate argc from argv */
	guint argc = 0;
	while (argv[argc])
		argc++;

	/* Check usage */
	if ((argc < argc_min) || (argc > argc_max)) {
		g_strfreev(argv);

		*p_argv = NULL;
		*p_argc = 0;
		return ARGV_ERROR_USAGE;
	}

	/* Decode percent encoded arguments */
	guint i = 1;
	for (; i < argc; i++)
		decode_percent_encoding(argv[i]);

	*p_argv = argv;
	*p_argc = argc;
	return ARGV_SUCCESS;
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
		warn("bind(AF_UNIX), socket \"%s\": %m", uxsock_path);
		return -2;
	}
	if (listen(uxsock, 8)) {
		warn("listen(AF_UNIX), socket \"%s\": %m", uxsock_path);
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

static pid_t invoke_bgctl(FILE * fp, const char ** argv)
{
	const pid_t pid = fork();
	if (pid != 0) {
		/* Inside parent process */
		return pid;
	}

	about_to_execute(argv);  /* before output redirection! */

	/* Redirect stdout/stderr to <fp> */
	close(0);
	const int output_fd = fileno(fp);
	if (output_fd != -1) {
		dup2(output_fd, 1);
		dup2(output_fd, 2);
	}

	execvp_or_abort(argv);

	err("should never get here");
	return 0;
}

static int handle_bgctl_command(const char * usage, const char * mode, unsigned int expected_argc_min, unsigned int expected_argc_max,
		char * buf, FILE * fp, const char * xnbd_bgctl_command, guint * p_argc, gchar *** p_argv, int * p_child_process_count)
{
	int return_code = -1;

	gchar ** argv = NULL;
	guint argc = 0;
	const int res = extract_decode_check_usage(buf, &argv, &argc, ARGC_RANGE(expected_argc_min, expected_argc_max));
	if (res == ARGV_ERROR_USAGE) {
		fprintf(fp, "usage: %s\n", usage);
	} else if (res == ARGV_ENOMEM) {
		fprintf(fp, "%s\n", MESSAGE_ENOMEM);
	} else if (res == ARGV_SUCCESS) {
		if (p_argc && p_argv) {
			*p_argc = argc;
			*p_argv = argv;
		}

		{
			const char * const local_exportname = argv[1];
			t_disk_data * const p_disk_data = get_disk_data_for(local_exportname);
			if (! p_disk_data) {
				fprintf(fp, "There is no export named \"%s\".\n", local_exportname);
			} else {
				if (! p_disk_data->proxy.target_host) {
					fprintf(fp, "Export \"%s\" not configured for proxy mode.\n", local_exportname);
				} else if (access(p_disk_data->proxy.control_socket_path, R_OK) == -1) {
					fprintf(fp, "Export \"%s\" not being served to any client at the moment.\n", local_exportname);
				} else {
					/* <input> = <command> <local_exportname> [<arg> .. [<target_exportname>]] */
					/* <output> = <xnbd-bgctl> [<--exportname> <NAME>] <mode> <control_socket> <arg>*positional_args_to_append <NULL> */
					const bool target_exportname_present = (argc == expected_argc_max);
					const int positional_args_to_append = argc - 1 - 1 - (target_exportname_present ? 1 : 0);
					const char * bgctl_argv[1 + (target_exportname_present ? 2 : 0) + 1 + 1 + positional_args_to_append + 1];
					int bgctl_argc = 0;
					bgctl_argv[bgctl_argc++] = xnbd_bgctl_command;
					if (target_exportname_present) {
						bgctl_argv[bgctl_argc++] = "--exportname";
						bgctl_argv[bgctl_argc++] = argv[expected_argc_max - 1];  /* i.e. the last argument */
					}

					bgctl_argv[bgctl_argc++] = mode;
					bgctl_argv[bgctl_argc++] = p_disk_data->proxy.control_socket_path;

					for (int i = 0; i < positional_args_to_append; i++) {
						bgctl_argv[bgctl_argc++] = argv[1 + 1 + i];  /* <input> = <command> <local_exportname> [<arg> ..] */
					}
					bgctl_argv[bgctl_argc++] = NULL;

					const pid_t bgctl_pid = invoke_bgctl(fp, bgctl_argv);
					if (bgctl_pid != -1) {
						pthread_mutex_lock(&mutex);
						(*p_child_process_count)++;
						info("child_process_count++ : %d  (forked to execute xnbd-bgctl)", (*p_child_process_count));
						pthread_mutex_unlock(&mutex);
					}

					/* Wait for child process termination */
					if (bgctl_pid == -1) {
						fprintf(fp, "xnbd-bgctl could not be executed.\n");
					} else {
						int status = -1;
						const pid_t waitpid_res = waitpid(bgctl_pid, &status, 0);
						if (waitpid_res != bgctl_pid) {
							warn("waiting for xnbd-bgctl(%d), waitpid : %m", bgctl_pid);
						}

						pthread_mutex_lock(&mutex);
						(*p_child_process_count)--;
						info("child_process_count-- : %d  (xnbd-bgctl terminated)", (*p_child_process_count));
						pthread_mutex_unlock(&mutex);

						if (WIFEXITED(status)) {
							return_code = (unsigned char)(WEXITSTATUS(status));
						} else {
							assert(WIFSIGNALED(status));
							return_code = (unsigned char)(128 + WTERMSIG(status));
						}

						if (return_code != 0) {
							fprintf(fp, "Execution of xnbd-bgctl failed with code %d.\n", return_code);
						}
					}
				}
				destroy_value(p_disk_data);
			}
		}
	}

	if (! (p_argc && p_argv)) {
		g_strfreev(argv);
	}

	return return_code;
}

static void *start_filemgr_thread(void * pointer)
{
	t_thread_data * const p_thread_data = (t_thread_data *)pointer;
	const int rbufsize = 128 * 8;

	char buf[rbufsize];
	char cmd[rbufsize];
	char arg[rbufsize];
	int ret;

	FILE *fp = fdopen(p_thread_data->conn_uxsock, "r+");
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

			int return_code = EXIT_SUCCESS;

			if (strcmp(cmd, "list") == 0)
				list_diskimg(fp);
			else if ((strcmp(cmd, "add") == 0) || (strcmp(cmd, "add-target") == 0)) {
				gchar ** argv = NULL;
				guint argc = 0;
				const int res = extract_decode_check_usage(buf, &argv, &argc, ARGC_RANGE(2, 3));
				if (res == ARGV_ENOMEM) {
					fprintf(fp, "%s\n", MESSAGE_ENOMEM);
					return_code = EXIT_FAILURE;
				} else if (res == ARGV_ERROR_USAGE) {
					fprintf(fp, "usage: %s\n", "add-target <LOCAL_EXPORTNAME> <FILE>");
					return_code = EXIT_FAILURE;
				} else if (res == ARGV_SUCCESS) {
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

						if (ret == XNBD_IMAGE_ADDED)
							auto_save(p_thread_data->database_file_name);

						return_code = (ret == XNBD_IMAGE_ADDED) ? EXIT_SUCCESS : EXIT_FAILURE;
					}
					else
					{
						fprintf(fp, "%s\n", MESSAGE_ENOMEM);
						return_code = EXIT_FAILURE;
					}
					g_strfreev(argv);
				}
			}
			else if (strcmp(cmd, "add-proxy") == 0) {
				gchar ** argv = NULL;
				guint argc = 0;
				const int res = extract_decode_check_usage(buf, &argv, &argc, ARGC_RANGE(7, 8));
				if (res == ARGV_ENOMEM) {
					fprintf(fp, "%s\n", MESSAGE_ENOMEM);
					return_code = EXIT_FAILURE;
				} else if (res == ARGV_ERROR_USAGE) {
					fprintf(fp, "usage: %s\n", "add-proxy <LOCAL_EXPORTNAME> <TARGET_HOST> <TARGET_PORT> <CACHE_IMAGE> <BITMAP_IMAGE> <CONTROL_SOCKET_PATH> [<TARGET_EXPORTNAME>]");
					return_code = EXIT_FAILURE;
				} else if (res == ARGV_SUCCESS) {
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
						fprintf(fp, "%s\n", MESSAGE_ENOMEM);
						return_code = EXIT_FAILURE;
					}
					else
					{
						ret = add_diskimg(p_disk_data);
						if (ret == XNBD_IMAGE_ACCESS_ERROR)
							fprintf(fp, "cannot open %s\n", cache_image);
						else if (ret == XNBD_NOT_ADDING_TWICE)
							fprintf(fp, "image cannot be added twice\n");

						if (ret == XNBD_IMAGE_ADDED)
							auto_save(p_thread_data->database_file_name);

						return_code = (ret == XNBD_IMAGE_ADDED) ? EXIT_SUCCESS : EXIT_FAILURE;
					}
					g_strfreev(argv);
				}
			}
			else if (strcmp(cmd, "del") == 0) {
				const int number = atoi(arg);
				return_code = del_diskimg_by_index(number);

				if (return_code == EXIT_SUCCESS) {
					auto_save(p_thread_data->database_file_name);
				} else {
					fprintf(fp, "Image number %d could not be deleted.\n", number);
				}
			} else if (strcmp(cmd, "del-file") == 0) {
				decode_percent_encoding(arg);
				return_code = del_diskimg_by_file(arg);

				if (return_code == EXIT_SUCCESS) {
					auto_save(p_thread_data->database_file_name);
				} else {
					fprintf(fp, "Image with filename \"%s\" could not be deleted.\n", arg);
				}
			} else if (strcmp(cmd, "del-exportname") == 0) {
				decode_percent_encoding(arg);
				return_code = del_diskimg_by_exportname(arg);

				if (return_code == EXIT_SUCCESS) {
					auto_save(p_thread_data->database_file_name);
				} else {
					fprintf(fp, "Image with exportname \"%s\" could not be deleted.\n", arg);
				}
			} else if (strcmp(cmd, "shutdown") == 0) {
				perform_shutdown(fp, true);
			} else if (strcmp(cmd, "orphan") == 0) {
				perform_shutdown(fp, false);
			} else if (strcmp(cmd, "bgctl-query") == 0) {
				return_code = handle_bgctl_command("bgctl-query EXPORTNAME", "--query", ARGC_RANGE(2, 2), buf, fp, p_thread_data->xnbd_bgctl_command, NULL, NULL, p_thread_data->p_child_process_count);
			} else if (strcmp(cmd, "bgctl-switch") == 0) {
				guint argc = 0;
				gchar ** argv = NULL;

				return_code = handle_bgctl_command("bgctl-switch EXPORTNAME", "--switch", ARGC_RANGE(2, 2), buf, fp, p_thread_data->xnbd_bgctl_command, &argc, &argv, p_thread_data->p_child_process_count);
				if (return_code == EXIT_SUCCESS) {
					const char * const local_exportname = argv[1];
					mark_proxy_mode_ended(local_exportname);

					auto_save(p_thread_data->database_file_name);
				}

				g_strfreev(argv);
			} else if (strcmp(cmd, "bgctl-cache-all") == 0) {
				return_code = handle_bgctl_command("bgctl-cache-all EXPORTNAME", "--cache-all", ARGC_RANGE(2, 2), buf, fp, p_thread_data->xnbd_bgctl_command, NULL, NULL, p_thread_data->p_child_process_count);
			} else if (strcmp(cmd, "bgctl-reconnect") == 0) {
				guint argc = 0;
				gchar ** argv = NULL;

				return_code = handle_bgctl_command("bgctl-reconnect LOCAL_EXPORTNAME HOST PORT [TARGET_EXPORTNAME]", "--reconnect", ARGC_RANGE(4, 5), buf, fp, p_thread_data->xnbd_bgctl_command, &argc, &argv, p_thread_data->p_child_process_count);
				if (return_code == EXIT_SUCCESS) {
					const char * const local_exportname = argv[1];
					const char * const host = argv[2];
					const char * const port = argv[3];
					const char * const target_exportname = (argc >= 5) ? argv[4] : NULL;

					update_proxy_settings(local_exportname, host, port, target_exportname);

					auto_save(p_thread_data->database_file_name);
				}

				g_strfreev(argv);
			} else if (strcmp(cmd, "save") == 0) {
				perform_save(fp, p_thread_data->database_file_name);
			}
			else if (strcmp(cmd, "help") == 0)
				fprintf(fp,
					"  list                 : show list of disk images\n"
					"\n"
					"  add-target NAME PATH : add disk image in target mode\n"
					"  add-proxy ...        : add disk image in proxy mode\n"
					" (add [NAME] PATH)     : add disk image in target mode, deprecated\n"
					"\n"
					"  del-file FILE        : delete disk image by file name\n"
					"  del-exportname NAME  : delete disk image by export name\n"
					" (del INDEX)           : delete disk image by index, deprecated\n"
					"\n"
					"  bgctl-query NAME     : Query status of proxy\n"
					"  bgctl-switch NAME    : Switch from proxy to target mode\n"
					"  bgctl-cache-all NAME : Instruct proxy to cache all blocks\n"
					"  bgctl-reconnect ...  : Reconnect proxy to a given location\n"
					"\n"
					"  save                 : make xnbd-wrapper re-write its image database file\n"
					"  shutdown             : terminate all images and shutdown xnbd-wrapper instance\n"
					"  orphan               : shutdown xnbd-wrapper instance, keep xnbd-server processes alive\n"
					"  quit                 : quit (disconnect)\n");
			else if (strcmp(cmd, "quit") == 0)
				break;
			else {
				fprintf(fp, "unknown command\n");
				return_code = EXIT_FAILURE;
			}

			report_return_code(fp, return_code);
		}
	} else {
		fprintf(fp, "too many connections\n");
		fflush(fp);
	}
	fclose(fp);
	close(p_thread_data->conn_uxsock);
	count_mgr_threads(-1);

	g_free(p_thread_data);

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
	const char *binpath;
	const char *target_mode;
	int readonly;
	int syslog;
	const char *proxy_max_que_size_str;
	const char *proxy_max_buf_size_str;
};

static void exec_xnbd_server(struct exec_params *params, char *fd_num, const t_disk_data * disk_data)
{
	char *args[8 + 4 + 2 + 4];
	int i = 0;
	args[i] = (char *)params->binpath;

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
		if (params->proxy_max_que_size_str) {
			args[++i] = (char *)"--max-queue-size";
			args[++i] = (char *)params->proxy_max_que_size_str;
		}
		if (params->proxy_max_buf_size_str) {
			args[++i] = (char *)"--max-buf-size";
			args[++i] = (char *)params->proxy_max_buf_size_str;
		}

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

	about_to_execute((const char * const *)args);
	execvp_or_abort((const char * const *)args);
}

static bool command_available(const char * command) {
	const pid_t pid = fork();
	if (pid == 0) {
		/* Inside child process */
		const char * const argv[] = {
			"/usr/bin/which",
			command,
			NULL,
		};

		about_to_execute(argv);  /* before output redirection! */

		/* Redirect stdout/stderr to /dev/null */
		close(0);
#ifndef XNBD_DEBUG
		const int output_fd = open("/dev/null", O_WRONLY);
		if (output_fd != -1) {
			dup2(output_fd, 1);
			dup2(output_fd, 2);
		}
#endif

		execvp_or_abort(argv);

		err("should never get here");
		return false;
	}

	/* Inside parent process */
	int status;
	const pid_t waitpid_res = waitpid(pid, &status, 0);
	if (waitpid_res != pid) {
		err("waitpid failed: %m");
	}

	assert(WIFEXITED(status));
	return (WEXITSTATUS(status) == 0) ? true : false;
}

static void ensure_command_available(const char * command) {
	assert(command);
	if (! command_available(command)) {
		if (strchr(command, '/')) {
			/* File on disk */
			struct stat buf;
			const int statt_res = stat(command, &buf);
			if (statt_res == 1) {
				err("Cannot access file \"%s\": %m", command);
			}

			if (access(command, X_OK) != 0) {
				err("Will not be able to execute file \"%s\" later: %m", command);
			}
		} else {
			/* Command name to be complete from ${PATH} */
			err("Command \"%s\" not found", command);
		}
	}
}

static void query_remote_disk_size(off_t * p_disk_size_bytes, const char * host,
		const char * port, const char * exportname)
{
	assert(p_disk_size_bytes && host && port);

	const int sockfd = net_connect(host, port, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd < 0) {
		warn("cannot connect to %s(%s)", host, port);
		return;
	}

	int ret;
	if (exportname)
		ret = nbd_negotiate_v2_client_side(sockfd, p_disk_size_bytes, NULL, strlen(exportname), exportname);
	else
		ret = nbd_negotiate_v1_client_side(sockfd, p_disk_size_bytes, NULL);

	close(sockfd);

	if (ret < 0) {
		warn("negotiation with %s:%s failed", host, port);
		return;
	}
}


static const char help_string[] =
	"\n\n"
	"Usage: \n"
	"  %s [options]\n"
	"\n"
	"Options: \n"
	"  --daemonize    run wrapper as a daemon process\n"
	"  --cow          run server instances as a cow target\n"
	"  --readonly     run server instances as a readonly target\n"
	"  --laddr        listening address\n"
	"  --lport        listening port (default: 8520)\n"
	" (--port)        deprecated, use --lport instead\n"
	"  --xnbd-bgctl   path to the xnbd-bgctl executable\n"
	"  --xnbd-server  path to the xnbd-server executable\n"
	"  --imgfile      path to a disk image file. This options can be used multiple times.\n"
	"                 Use also xnbd-wrapper-ctl to (de)register disk images dynamically.\n"
	"  --logpath PATH use the given path for logging (default: stderr/syslog)\n"
	"  --dbpath PATH  use the given path for persisting database state (default: /var/lib/xnbd/xnbd.state)\n"
	"  --socket       unix socket path to listen on (default: /var/run/xnbd-wrapper.ctl).\n"
	"  --syslog       use syslog for logging\n"
	"  --max-queue-size SIZE\n"
	"                 set the limit of the request queue size per xnbd-server process (default: 0, no limit)\n"
	"  --max-buf-size SIZE (bytes)\n"
	"                 set the limit of internal buffer usage per xnbd-server process (default: 0, no limit)\n"
	"\n"
	"Examples: \n"
	"  xnbd-wrapper --imgfile /data/disk1\n"
	"  xnbd-wrapper --imgfile /data/disk1 --imgfile /data/disk2 --xnbd-server /usr/local/bin/xnbd-server --xnbd-bgctl /usr/local/bin/xnbd-bgctl --laddr 127.0.0.1 --lport 18520 --socket /tmp/xnbd-wrapper.ctl\n";


int main(int argc, char **argv) {
	char *fd_num;
	pid_t pid;
	const char *xnbd_server_command = "xnbd-server";
	char *laddr = NULL;
	char *port = NULL;
	int sockfd, conn_sockfd, ux_sockfd;
	int ch, ret;
	char *requested_img = NULL;
	pthread_t thread;
	const char default_ctl_path[] = "/var/run/xnbd-wrapper.ctl";
	char *ctl_path = NULL;
	int child_process_count = 0;
	const int MAX_NSRVS = 512;
	const char default_server_target[] = "--target";
	const char *server_target = NULL;
	int daemonize = 0;
	int syslog = 0;
	const char *logpath = NULL;
	const char *dbpath = "/var/lib/xnbd/xnbd.state";
	struct exec_params exec_srv_params = { .readonly = 0 };
	const char * xnbd_bgctl_command = "xnbd-bgctl";

	p_disk_dict = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify)destroy_value);
	p_server_pid_set = g_hash_table_new(g_direct_hash, g_direct_equal);


	sigset_t sigset;
	int sigfd;
	struct signalfd_siginfo sfd_siginfo;
	ssize_t rbytes;

	const int MAX_EVENTS = 8;
	struct epoll_event sigfd_ev, uxfd_ev, tcpfd_ev, ep_events[MAX_EVENTS];
	int epoll_fd;

	set_process_name("xnbd-wrapper");

	struct option longopts[] = {
		{"imgfile",     required_argument, NULL, 'f'},
		{"laddr",       required_argument, NULL, 'l'},
		{"lport",       required_argument, NULL, 'p'},
		{"port",        required_argument, NULL, 'p'}, /* DEPRECATED */
		{"socket",      required_argument, NULL, 's'},
		{"xnbd-bgctl",  required_argument, NULL, 't'},
		{"xnbd-server", required_argument, NULL, 'b'},
		{"xnbd-binary", required_argument, NULL, 'b'}, /* DEPRECATED */
		{"cow",         no_argument,       NULL, 'c'},
		{"readonly",    no_argument,       NULL, 'r'},
		{"daemonize",   no_argument,       NULL, 'd'},
		{"logpath",     required_argument, NULL, 'L'},
		{"dbpath",      required_argument, NULL, 'j'},
		{"syslog",      no_argument,       NULL, 'S'},
		{"help",        no_argument,       NULL, 'h'},
		{"max-queue-size", required_argument, NULL, 'Q'},
		{"max-buf-size",   required_argument, NULL, 'B'},
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

	while((ch = getopt_long(argc, argv, "b:f:hl:p:s:SdL:Q:B:", longopts, NULL)) != -1) {
		switch (ch) {
			case 'L':
				logpath = optarg;
				log_params.use_fd = 1;
				log_params.fd = get_log_fd(logpath);
				info("LOGFILE: %s", logpath);
				g_log_set_default_handler(custom_log_handler, (void *)&log_params);
				break;
			case 'j':
				dbpath = optarg;
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
					warn(MESSAGE_ENOMEM);
				}
				break;
			}
			case 'b':
				xnbd_server_command = optarg;
				break;
			case 't':
				xnbd_bgctl_command = optarg;
				break;
			case 's':
				ctl_path = optarg;
				break;
			case 'S':
				//log_params.use_syslog = 1;
				syslog = 1;
				break;
			case 'Q':
			{
				/* passing 0 is acceptable */
				const size_t proxy_max_que_size = strtoul(optarg, NULL, 0);
				info("max_queue_size %zu", proxy_max_que_size);
				exec_srv_params.proxy_max_que_size_str = optarg;
				break;
			}
			case 'B':
			{
				const size_t proxy_max_buf_size = strtoul(optarg, NULL, 0);
				info("max_buf_size %zu", proxy_max_buf_size);
				exec_srv_params.proxy_max_buf_size_str = optarg;
				break;
			}
			case 'h':
				log_params.fd = fileno(stdout);
				g_log_set_default_handler(custom_log_handler, (void *)&log_params);
				// fall through
			default:
				{
					FILE * const target = (ch == 'h') ? stdout : stderr;
					fprintf(target, help_string, argv[0]);
				}

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

	ensure_command_available("which");  /* self test */
	ensure_command_available(xnbd_bgctl_command);
	ensure_command_available(xnbd_server_command);

	info("xnbd-bgctl executable: %s", xnbd_bgctl_command);
	info("xnbd-server executable: %s", xnbd_server_command);
	exec_srv_params.binpath = xnbd_server_command;

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

	load_database_file_or_abort(dbpath);

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
	memset(&sigfd_ev, 0, sizeof(sigfd_ev));
	sigfd_ev.events = POLLIN;
	sigfd_ev.data.fd = sigfd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sigfd, &sigfd_ev) == -1) {
		err("epoll_ctl : %m");
	}

	/* add tcp socket */
	if ((sockfd = make_tcp_sock(laddr, port)) == -1)
		err("make_tcp_sock() returned %d", sockfd);

	memset(&tcpfd_ev, 0, sizeof(tcpfd_ev));
	tcpfd_ev.events = POLLIN;
	tcpfd_ev.data.fd = sockfd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockfd, &tcpfd_ev) == -1) {
		err("epoll_ctl : %m");
	}

	/* add unix socket */
	if ((ux_sockfd = make_unix_sock(ctl_path)) < 0)
		err("make_unix_sock() returned %d", ux_sockfd);

	memset(&uxfd_ev, 0, sizeof(uxfd_ev));
	uxfd_ev.events = POLLIN;
	uxfd_ev.data.fd = ux_sockfd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ux_sockfd, &uxfd_ev) == -1) {
		err("epoll_ctl : %m");
	}

	for (;;) {
		int num_of_fds = epoll_wait(epoll_fd, ep_events, MAX_EVENTS, -1);
		if (num_of_fds == -1) {
			if (errno == EINTR)
				continue;
			err("epoll_wait : %m");
		}
		for (int c_ev = 0; c_ev < num_of_fds; c_ev++) {
			if (ep_events[c_ev].data.fd == sigfd) {
				/* signalfd */
				rbytes = read(sigfd, &sfd_siginfo, sizeof(sfd_siginfo));
				if (rbytes != sizeof(sfd_siginfo))
					err("read sigfd : %m");
				if (sfd_siginfo.ssi_signo == SIGTERM || sfd_siginfo.ssi_signo == SIGINT) {
					auto_save(dbpath);

					pthread_mutex_lock(&mutex);
					g_hash_table_destroy(p_disk_dict);
					pthread_mutex_unlock(&mutex);

					close(epoll_fd);
					close(sockfd);
					close(ux_sockfd);
					close(sigfd);
					unlink(ctl_path);
					exit(EXIT_SUCCESS);
				} else if (sfd_siginfo.ssi_signo == SIGCHLD) {
					g_hash_table_foreach_remove(p_server_pid_set, waitpid_nohang_ghrfunc, &child_process_count);
				}
			} else if (ep_events[c_ev].data.fd == ux_sockfd) {
				/* unix socket */
				const int conn_uxsock = accept(ux_sockfd, NULL, NULL);
				if (conn_uxsock == -1) {
					warn("accept(AF_UNIX): %m");
					continue;
				}

				t_thread_data * const p_thread_data = g_try_new(t_thread_data, 1);
				if (! p_thread_data) {
					warn("Could not start thread: %s", MESSAGE_ENOMEM);
				} else {
					p_thread_data->conn_uxsock = conn_uxsock;
					p_thread_data->xnbd_bgctl_command = xnbd_bgctl_command;
					p_thread_data->database_file_name = dbpath;
					p_thread_data->p_child_process_count = &child_process_count;
					if (pthread_create(&thread, NULL, start_filemgr_thread, (void *)p_thread_data))
						warn("pthread_create : %m");
					if (pthread_detach(thread))
						warn("pthread_detach : %m");
				}
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

				pthread_mutex_lock(&mutex);
				const gboolean child_process_limit_reached = (child_process_count >= MAX_NSRVS);
				pthread_mutex_unlock(&mutex);

				if (child_process_limit_reached) {
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

					if ((requested_img = nbd_negotiate_v2_server_phase0(conn_sockfd)) == NULL) {
						warn("requested_img: NULL");
						close(conn_sockfd);
						_exit(EXIT_FAILURE);
					}
					info("requested_img: %s", requested_img);

					const t_disk_data * const disk_data = get_disk_data_for(requested_img);
					if (! disk_data) {
						if(close(conn_sockfd))
							warn("close(p0)");
						_exit(EXIT_FAILURE);
					}

					off_t disk_size_bytes = -1;

					if (disk_data->proxy.target_host) {
						/* proxy mode, forward original remote disk size */
						query_remote_disk_size(&disk_size_bytes,
								disk_data->proxy.target_host,
								disk_data->proxy.target_port,
								disk_data->proxy.target_exportname);

						if (disk_size_bytes < 0) {
							warn("could query remote disk size for image: %s", disk_data->disk_file_name);
							if(close(conn_sockfd))
								warn("close(p1.1)");
							_exit(EXIT_FAILURE);
						}
					} else {
						/* target mode, stat local file */
						const int fd = open(disk_data->disk_file_name, O_RDONLY);
						if (fd == -1) {
							warn("stat failed: %s", disk_data->disk_file_name);
							if(close(conn_sockfd))
								warn("close(p1.2)");
							_exit(EXIT_FAILURE);
						}
						disk_size_bytes = get_disksize(fd);
						close(fd);
					}

					info("disk_size_bytes: %jd", disk_size_bytes);

					if (nbd_negotiate_v2_server_phase1(conn_sockfd, disk_size_bytes, 0)) {
						if(close(conn_sockfd))
							warn("close(p2)");
						_exit(EXIT_FAILURE);
					}

					exec_xnbd_server(&exec_srv_params, fd_num, disk_data);

				} else if (pid > 0) {
					/* parent */
					free(fd_num);

					g_hash_table_insert(p_server_pid_set, GINT_TO_POINTER(pid), NULL);

					pthread_mutex_lock(&mutex);
					child_process_count++;
					info("child_process_count++ : %d  (forked to execute xnbd-server)", child_process_count);
					pthread_mutex_unlock(&mutex);

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
