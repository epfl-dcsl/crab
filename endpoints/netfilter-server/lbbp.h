#pragma once

struct lbbp_cfg_params {
	unsigned int lb_ip;
	unsigned int mask;
	unsigned int port;
};

#define LBBP_CFG _IOR('a', 0x01, struct lbbp_cfg_params)
