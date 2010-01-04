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

		unsigned long bindex = ~(0UL) - 1;
		write_all(fd, &bindex, sizeof(bindex));

		close(fd);
	} else
		err("unknown options");

	return 0;
}
