#ifndef _IP_H
#define _IP_H

#include <netinet/ip.h>
#include "common.h"
#include <vector>

#define IP_FLOOD_TIMEOUT 300 // 300ms
#define IP_FLAG_DF 0x2
#define IP_DEFAULT_TTL 64

namespace IP_lyr{
    using std::vector;

    /**
     * An entry of the manually configured route table; 
     */
    struct route_entry{
        ipv4_addr_t dst;
        ipv4_addr_t mask;
        eth_addr_t next_hop_mac;
        int dev_id;
    };

    /**
     * Intializing the IP layer. It initializes the global data structures and launchs 
     * the "ip_flood_cleaner" thread for cleaning outdated IP packet record.
     */
    void init();

    /**
     * Exiting the process and releasing all the resources in the IP layer.
     */
    void exiting();

    /**
     * Cleaning all the outdated IP packet recorded in "ip_flood_visited" every 1 second.
     */
    void ip_flood_cleaner();

    /**
     *  Flood the ip packet to all the neighbor devices, if the routing table is not
     *  manually configured, or forward the ip packet to the next hop recorded in the 
     *  routing table. Longest prefix match is used to determine the next hop.
     * 
     *  @buf:
     *      Pointer to the Layer 4 buffer.
     *  @len:
     *      Length of the Layer 4 buffer.
     *  @ip_header:
     *      Pointer to the IP header.
     *  @return:
     *      0 on successfully forwarding and -1 on error.
     */
    int ip_forwarding(const void* buf, int len, const ipv4_hdr_t* ip_header);

    /**
     * @brief Send an IP packet to specified host. 
     *
     * @param src Source IP address.
     * @param dest Destination IP address.
     * @param proto Value of `protocol` field in IP header.
     * @param buf pointer to IP payload
     * @param len Length of IP payload
     * @return 0 on success, -1 on error.
     */
    int sendIPPacket(const ipv4_addr_t src, const ipv4_addr_t dst, 
        int proto, const void *buf, int len);

    /** 
     * @brief Process an IP packet upon receiving it.
     *
     * @param buf Pointer to the packet.
     * @param len Length of the packet.
     * @return 0 on success, -1 on error.
     * @see addDevice
     */
    typedef void (*IPPacketReceiveCallback)(const void* buf, int len, const eth_hdr_t* eth_header, int dev_id);

    /**
     * @brief Register a callback function to be called each time an IP packet
     * was received.
     *
     * @param callback The callback function.
     * @return 0 on success, -1 on error.
     * @see IPPacketReceiveCallback
     */
    int setIPPacketReceiveCallback(IPPacketReceiveCallback callback);

    /**
     * A default callback function upon receiving an IP packet.
     * 
     * If the packet does not reach the destination address, it will call ip_forwarding to
     * flood to all the neighbor devices.
     * Else, it calls the TCP receive callback function to pass the packet to the TCP layer.
     * 
     * @param
     *     See setIPPacketReceiveCallback
     */
    void default_ip_rcv_callback(const void* buf, int len, const eth_hdr_t* eth_header, int dev_id);

    /**
     * @brief Manully add an item to routing table. Useful when talking with real 
     * Linux machines.
     * 
     * @param dst The destination IP prefix.
     * @param mask The subnet mask of the destination IP prefix.
     * @param nextHopMAC MAC address of the next hop.
     * @param device Name of device to send packets on.
     * @return 0 on success, -1 on error
     */
    int setRoutingTable(const ipv4_addr_t dst, const ipv4_addr_t mask, 
        const void* nextHopMAC, const char *device);
}
#endif