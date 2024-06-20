#pragma once

#include "defines.h"
#include "vmlinux.h"

// struct definition for packet processing
struct event {
	u32 pid;
	u64 addr_pair;
	u32 port_pair;
	u8 buff[BUFF_SIZE];
	u32 len;
    u8 type;
    u8 direction;
};

const struct event *unused __attribute__((unused));