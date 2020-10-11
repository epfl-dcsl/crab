#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>

#include "lbbp.h"

int main(int argc, char **argv)
{
    int fd, i;
    struct lbbpl_cfg_params params;
	struct sockaddr_in sa;
	char *token, *saveptr;


	if (argc != 6) {
		printf("Usage: ./cfg_lbblp <vip> <port> <taget_count> <comma separated target IPs> <LB_RR|LB_RAND>\n");
		return -1;
	}

	/* Parse vip for match and store in be */
	inet_pton(AF_INET, argv[1], &(sa.sin_addr));
	params.vip = sa.sin_addr.s_addr;

	/* Parse port for match and store in be */
	params.port = htons(atoi(argv[2]));

	params.target_count = atoi(argv[3]);
	saveptr = argv[4];
	for (i=0;i<params.target_count;i++) {
		token = strtok_r(saveptr, ",", &saveptr);
		inet_pton(AF_INET, token, &(sa.sin_addr));
		params.targets[i] = sa.sin_addr.s_addr;
	}

	if (strncmp(argv[5], "LB_RR", 5) == 0)
		params.lbt = LB_RR;
	else if (strncmp(argv[5], "LB_RAND", 7) == 0)
		params.lbt = LB_RAND;
	else {
		fprintf(stderr, "Wrong LB type\n");
		return -1;
	}

    fd = open("/dev/lbbp", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Error opening device file\n");
		return -1;
	}

    ioctl(fd, LBBPL_CFG, &params);

    return 0;
}
