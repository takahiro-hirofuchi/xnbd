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


int main(int argc, char **argv)
{
	if (argc != 3) {
		printf("%s --cache-all-blocks bgctlpath\n", argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "--cache-all-blocks") == 0) {
		char *bgctlpath = argv[2];

		int fd = open(bgctlpath, O_WRONLY);
		if (fd < 0)
			err("open %s, %m", bgctlpath);

		unsigned long bindex = XNBD_BGCTL_MAGIC_CACHE_ALL;
		write_all(fd, &bindex, sizeof(bindex));

		close(fd);
	} else
		err("unknown options");

	return 0;
}
