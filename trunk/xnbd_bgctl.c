/* 
 * Copyright (C) 2008-2009 National Institute of Advanced Industrial Science and Technology
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

		char buf[100];
		sprintf(buf, "%u", UINT32_MAX);
		write_all(fd, buf, strlen(buf));

		close(fd);
	} else
		err("unknown options");

	return 0;
}
