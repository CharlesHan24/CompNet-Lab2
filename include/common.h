#ifndef _COMMON_H
#define _COMMON_H

#include <cstdint>

/**
 * Ethernet address type
 */
struct eth_addr{
    uint8_t addr[6];
};

typedef eth_addr eth_addr_t;


/**
 * Ethernet header type.
 * Never do struct aligning.
 */
struct __attribute__((__packed__)) eth_hdr{
    eth_addr_t dst_mac;
    eth_addr_t src_mac;
    uint16_t eth_type;
};
typedef eth_hdr eth_hdr_t;

const eth_addr_t ETH_BROADCAST_ADDR = {
    .addr = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
};


/**
 * IPV4 address 
 */
struct ipv4_addr{
    uint8_t addr[4];
};

typedef ipv4_addr ipv4_addr_t;


/**
 * Generate a hex mac address string for debugging.
 * @param mac_addr
 *     6-byte MAC address array to be converted
 * @param display_mac_str
 *     MAC address string in hexadecimal format, e.g, ff:ff:ff:ff:ff:ff
 */
void gen_mac_str(const unsigned char* mac_addr, char* display_mac_str);


#define ENDIAN_REV16(X) (((((uint16_t)X) >> 8) & 0x00ff) | (((uint16_t)X & 0x00ff) << 8))

#define DEBUG_MODE

#endif