#ifndef _COMMON_H
#define _COMMON_H

#include <cstdint>
#include <map>
#include <vector>
#include <mutex>

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
 * ARP header type 
 */
struct arp_hdr{
    ipv4_addr_t src;
    ipv4_addr_t dst;
    uint32_t arp_id;    // ARP id in order to correspond the stored payload the this ARP packet.
    uint8_t arp_type;   // Send or Reply
    uint8_t arp_cast;   // Single ARP query/response or broadcast ARP query/response. 
};
typedef arp_hdr arp_hdr_t;

/**
 * RFC 791 standard IPV4 header type. 
 */
struct __attribute__((packed)) ipv4_hdr{
    uint8_t version : 4;
    uint8_t ihl : 4;
    uint8_t tos;
    uint16_t len;
    uint16_t ident;
    uint16_t flags;
    uint8_t ttl;
    uint8_t proto;
    uint16_t hdr_csum;
    ipv4_addr_t src;
    ipv4_addr_t dst;
};
typedef ipv4_hdr ipv4_hdr_t;


/**
 * Generate a hex mac address string for debugging.
 * @param mac_addr
 *     6-byte MAC address array to be converted
 * @param display_mac_str
 *     MAC address string in hexadecimal format, e.g, ff:ff:ff:ff:ff:ff
 */
void gen_mac_str(const unsigned char* mac_addr, char* display_mac_str);

/**
 * Generate a "dot format" ipv4 address string for debugging.
 * @param ipv4_addr
 *     4-byte IPV4 address array to be converted
 * @param display_ipv4_str
 *     IPv4 address string in dot format, e.g, 10.20.30.40
 */
void gen_ipv4_str(const unsigned char* ipv4_addr, char* display_ipv4_addr);

/**
 * Get the current time
 */
uint64_t get_time();

// Big / Little endian reversion on uint16_t and uint32_t.
#define ENDIAN_REV16(X) (((((uint16_t)X) >> 8) & 0x00ff) | (((uint16_t)X & 0x00ff) << 8))
#define ENDIAN_REV32(X) ((ENDIAN_REV16(X & 0xffff) << 16) | (ENDIAN_REV16((X ^ 0xffff) >> 16)))

// Debug mode or not
#define DEBUG_MODE

#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_ARP 0x0806

#define ARP_TYPE_SD 0x1
#define ARP_TYPE_RCV 0x2

#define ARP_BROADCAST 0x1
#define ARP_E2E 0x2

/**
 * Wrapping a map data structure to make it thread-safe, by adding a lock.
 */
template<class key, class val>
struct multi_th_map{
    std::map<key, val> mp;
    std::mutex lock;

    multi_th_map (){
        lock.unlock();
    }
    ~multi_th_map (){}
};

/**
 * Wrapping a vector data structure to make it thread-safe, by adding a lock.
 */
template<class key>
struct multi_th_vector{
    std::vector<key> vec;
    std::mutex lock;

    multi_th_vector (){
        lock.unlock();
    }
    ~multi_th_vector (){}
};

template<class T>
struct multi_th_uint{
    T integ;
    std::mutex lock;
    multi_th_uint (){
        integ = 0;
        lock.unlock();
    }
    ~multi_th_uint (){}
};

#endif