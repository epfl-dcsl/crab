#pragma once

enum lb_type {
	LB_RR = 0,
	LB_RAND,
};

struct lbbpl_cfg_params {
	unsigned int vip;
	unsigned int port;
	enum lb_type lbt;
	unsigned int target_count;
	unsigned int targets[64];
};

#define LBBPL_CFG _IOR('a', 0x01, struct lbbpl_cfg_params)
