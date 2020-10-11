#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#include "lbbp.h"

int main(int argc, char **argv)
{
    int fd, i;
    struct lbbp_cfg_params params;
	struct sockaddr_in sa;
	char *token, *saveptr;


	if (argc != 4) {
		printf("Usage: ./cfg_crab_server <vip> <port> <mask>\n");
		return -1;
	}

	/* Parse vip for match and store in be */
	inet_pton(AF_INET, argv[1], &(sa.sin_addr));
	params.lb_ip = ntohl(sa.sin_addr.s_addr);

	/* Parse port for match and store in be */
	params.port = atoi(argv[2]);

	params.mask = strtol(argv[3], NULL, 16);

    fd = open("/dev/lbbp", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Error opening device file\n");
		return -1;
	}

    ioctl(fd, LBBP_CFG, &params);

    return 0;
}
