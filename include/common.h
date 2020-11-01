#ifndef _COMMON_H
#define _COMMON_H

#include <cstdint>

struct eth_addr{
    uint8_t addr[6];
};

typedef eth_addr eth_addr_t;

const eth_addr_t ETH_BROADCAST_ADDR = {
    .addr = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
};

struct ipv4_addr{
    uint8_t addr[4];
};

typedef ipv4_addr ipv4_addr_t;

#define DEBUG_MODE

#endif