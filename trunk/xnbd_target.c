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


#include <sys/ioctl.h>
/* clone_file() is a snippet from coreutils. modified. */
/* Perform the O(1) btrfs clone operation, if possible.
 * Upon success, return 0.  Otherwise, return -1 and set errno.  */
static int clone_file_by_reflink(int dstfd, int srcfd)
{
#ifdef __linux__
#undef BTRFS_IOCTL_MAGIC
#define BTRFS_IOCTL_MAGIC 0x94
#undef BTRFS_IOC_CLONE
#define BTRFS_IOC_CLONE _IOW (BTRFS_IOCTL_MAGIC, 9, int)
	return ioctl(dstfd, BTRFS_IOC_CLONE, srcfd);
#else
	(void) dstfd;
	(void) srcfd;
	errno = ENOTSUP;
	return -1;
#endif
}

static void clone_file_by_copy(int dstfd, int srcfd)
{
	off_t total = 0;
	char buf[1024];
	ssize_t ret;

	for (;;) {
		ret = pread(srcfd, buf, sizeof(buf), total);
		if (ret < 0)
			err("read, %m");
		else if (ret == 0) {
			/* eof */
			break;
		}

		write_all(dstfd, buf, (size_t) ret);
		total += ret;
	}

	struct stat st;
	ret = fstat(srcfd, &st);
	if (ret < 0)
		err("fstat, %m");

	if (st.st_size != total)
		err("size mismatch");

}

void xnbd_target_make_snapshot(struct xnbd_info *xnbd)
{
	time_t now = time(NULL);
	/* clone_file_by_copy() is not atomic. so use hardlink */
	char *dstpath = g_strdup_printf("%s.snapshot.%08lu", xnbd->target_diskpath, now);
	char *tmpdstpath = g_strdup_printf("%s.snapshot.%08lu.tmp", xnbd->target_diskpath, now);

	int dstfd = open(tmpdstpath, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (dstfd < 0) {
		warn("snapshot: opening %s failed, %m", tmpdstpath);
		goto err;
	}

	int ret = clone_file_by_reflink(dstfd, xnbd->target_diskfd);
	if (ret) {
		warn("snapshot: cloning %s to %s by reflink failed, %m", xnbd->target_diskpath, tmpdstpath);
		warn("snapshot: fall back to normal copy ...");
		clone_file_by_copy(dstfd, xnbd->target_diskfd);
	}

	close(dstfd);


	ret = link(tmpdstpath, dstpath);
	if (ret < 0)
		err("hardlink, %m");

	ret = unlink(tmpdstpath);
	if (ret < 0)
		err("unlink, %m");

	info("snapshot: %s", dstpath);
err:
	g_free(dstpath);
	g_free(tmpdstpath);
}


void xnbd_target_open_disk(char *diskpath, struct xnbd_info *xnbd)
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

	/* multiple connections call this */
	//if (posix_fallocate(diskfd, 0, disksize))
	//	warn("maybe no enough space in a local file system");

	xnbd->target_diskfd = diskfd;
	xnbd->disksize = disksize;
}


int target_mode_main_mmap(struct xnbd_session *ses)
{
	struct xnbd_info *xnbd = ses->xnbd;

	struct nbd_reply reply;
	int csock = ses->clientfd;
	uint32_t iotype = 0;
	off_t iofrom = 0;
	size_t iolen  = 0;
	int ret;

	memset(&reply, 0, sizeof(reply));
	reply.magic = htonl(NBD_REPLY_MAGIC);
	reply.error = 0;


	ret = poll_request_arrival(ses);
	if (ret < 0)
		return -1;

	ret = nbd_server_recv_request(csock, xnbd->disksize, &iotype, &iofrom, &iolen, &reply);
	if (ret == NBD_SERVER_RECV__BAD_REQUEST) {
		net_send_all_or_abort(csock, &reply, sizeof(reply));
		return 0;
	} else if (ret == NBD_SERVER_RECV__MAGIC_MISMATCH)
		err("client bug: invalid header");
	else if (ret == NBD_SERVER_RECV__TERMINATE)
		return ret;

	if (xnbd->readonly) {
		if (iotype == NBD_CMD_WRITE || iotype == NBD_CMD_TRIM) {
			/* do not read following write data */
			err("%s to a readonly disk. disconnect.", nbd_get_iotype_string(iotype));
		}
	}

	dbg("direct mode");

	switch (iotype) {
		case NBD_CMD_WRITE:
			dbg("disk write iofrom %ju iolen %zu", iofrom, iolen);

			{
				struct mmap_region *mpinfo = mmap_region_create(xnbd->target_diskfd, iofrom, iolen, xnbd->readonly);

				int ret = net_recv_all_or_error(csock, mpinfo->iobuf, iolen);
				if (ret < 0) {
					if (errno == EIO)
						reply.error = htonl(EIO);
					else
						err("CMD_WRITE: fatal error %m");
				}

				net_send_all_or_abort(csock, &reply, sizeof(reply));

				/* call mmap_region_msync(mpinfo) if writeout is necessary now */
				mmap_region_free(mpinfo);
			}
			break;

		case NBD_CMD_READ:
			dbg("disk read iofrom %ju iolen %zu", iofrom, iolen);

			{
				struct iovec iov[2];
				memset(&iov, 0, sizeof(iov));
				iov[0].iov_base = &reply;
				iov[0].iov_len  = sizeof(reply);


				off_t ret = lseek(xnbd->target_diskfd, iofrom, SEEK_SET);
				if (ret < 0) {
					/* We already confirmed the request
					 * never exceeds the end of the file.
					 * This lseek should never return an
					 * error. */
					err("CMD_READ: lseek (fd %d, iofrom %jd), %jd %m", xnbd->target_diskfd, iofrom, ret);
				}

				/* We expect a client never sends insane iolen.
				 * In such case, the server exits (i.e., disconnect). */
				char *buf = g_malloc(iolen);

				ret = net_recv_all_or_error(xnbd->target_diskfd, buf, iolen);
				if (ret < 0) {
					if (errno == EIO)
						reply.error = htonl(EIO);
					else
						err("CMD_READ: fatal error %m");
				}

				if (reply.error == 0) {
					iov[1].iov_base = buf;
					iov[1].iov_len  = iolen;
					net_writev_all_or_abort(csock, iov, 2);
				} else
					net_writev_all_or_abort(csock, iov, 1);

				g_free(buf);
			}
			break;

		case NBD_CMD_FLUSH:
			dbg("disk flush");

			{
				ret = fsync(xnbd->target_diskfd);
				if (ret < 0) {
					warn("CMD_FLUSH: fsync failed, %m");
					if (errno == EIO) {
						/* underlying disk might be broken */
						reply.error = htonl(EIO);
					} else
						err("CMD_FLUSH: fatal error %m");
				}

				net_send_all_or_abort(csock, &reply, sizeof(reply));
			}
			break;

		case NBD_CMD_TRIM:
			dbg("disk trim iofrom %ju iolen %zu", iofrom, iolen);

			punch_hole(xnbd->target_diskfd, iofrom, iolen);

		default:
			err("unknown command in the target mode, %u (%s)", iotype, nbd_get_iotype_string(iotype));
	}

	return 0;
}



int xnbd_target_session_server(struct xnbd_session *ses)
{
	set_process_name("target_wrk");
	for (;;) {
		int ret = 0;

		ret = target_mode_main_mmap(ses);
		if (ret < 0)
			return ret;
	}

	return 0;
}
