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

	check_disksize(diskpath, disksize, false);

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
	if (ret == -1) {
		net_send_all_or_abort(csock, &reply, sizeof(reply));
		return 0;
	} else if (ret == -2)
		err("client bug: invalid header");
	else if (ret == -3)
		return ret;

	if (xnbd->readonly && iotype == NBD_CMD_WRITE) {
		/* do not read following write data */
		err("NBD_CMD_WRITE to a readonly disk. disconnect.");
	}

	dbg("direct mode");

	char *mmaped_buf = NULL;
	size_t mmaped_len = 0;
	off_t mmaped_offset = 0;
	char *iobuf = NULL;


	iobuf = mmap_iorange(xnbd->disksize, xnbd->readonly, xnbd->target_diskfd, iofrom, iolen, &mmaped_buf, &mmaped_len, &mmaped_offset);
	dbg("mmaped_buf %p iobuf %p mmaped_len %zu iolen %zu", mmaped_buf, iobuf, mmaped_len, iolen);



	struct iovec iov[2];

	switch (iotype) {
		case NBD_CMD_WRITE:
			dbg("disk write iofrom %ju iolen %zu", iofrom, iolen);

			net_recv_all_or_abort(csock, iobuf, iolen);

			net_send_all_or_abort(csock, &reply, sizeof(reply));

			break;

		case NBD_CMD_READ:
			dbg("disk read iofrom %ju iolen %zu", iofrom, iolen);

			memset(&iov, 0, sizeof(iov));
			iov[0].iov_base = &reply;
			iov[0].iov_len  = sizeof(reply);
			iov[1].iov_base = iobuf;
			iov[1].iov_len  = iolen;

			net_writev_all_or_abort(csock, iov, 2);

			break;

		default:
			err("unknown command %u", iotype);
	}


	//ret = msync(mmaped_buf, mmaped_len, MS_SYNC);
	//if (ret < 0)
	//	warn("msync failed");
	munmap_or_abort(mmaped_buf, mmaped_len);


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
