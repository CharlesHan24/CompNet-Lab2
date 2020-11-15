#ifndef _ARP_H
#define _ARP_H

#include "common.h"
#include <cstdint>

#define ARP_NEIGHBOR_TIMEOUT 20 // 20s
#define ARP_IN_FLIGHT_TIMEOUT 1000 // 1000ms
namespace ARP_lyr{
    /**
     * Data structure of stored IP payload of in-flight ARP request.
     */
    struct in_flight_arp_item{
        void* payload;
        int len;
        uint32_t arp_id;     // ID of the stored item. Useful for checking which IP payload the ARP response packet corresponds to.
        uint64_t timestamp;
    };

    /**
     * Data structure of remembered neighborhood information. 
     */
    struct arp_neighbor_info{
        uint64_t timestamp;
        int dev_id;
        eth_addr_t mac_addr;
    };

    /**
     * Initializing the ARP layer.
     */
    void init();
   
    /**
     * Exiting the process and releasing all the resources in the ARP layer.
     */
    void exiting();

    /**
     * Send an broadcast ARP request in order to get the mac address of `all` the neighbor devices.
     * Since we apply IP flooding algorithm as our routing algorithm, we broadcast the 
     * IP packet to all the neighbor devices. We assume that the following behaviour is not 
     * allowed (or at least not a good practice): filling ethernet destination address 
     * with ETHERNET_BROADCAST_ADDRESS to send an IP packet. Therefore, we first use ARP to find
     * the mac address of all the neighbor devices, and then send the packet to each neighbor devices.
     * All the corresponding IP payload will be temporarily stored in a vector.
     * 
     * @payload:
     *     Pointer to the Layer 4 payload.
     * @len:
     *     Length of the Layer 4 payload.
     * @ip_header:
     *     Pointer to the Ipv4 header.
     * @return:
     *     0 on success and -1 on error.
     */
    int send_arp_request_broadcast(const void* payload, int len, const ipv4_hdr_t* ip_header);

    /**
     * Process an ARP packet upon receiving it.
     * 
     * @arp_buf:
     *      Pointer to the buffer of the ARP packet.
     * @len:
     *      length of the ARP packet.
     * @eth_header:
     *      Pointer to the ethernet header of that ARP packet.
     * @dev_id:
     *      ID of the device at which the ARP packet was received.
     * @return:
     *      Void since its caller (ethernet callback) splits and detach a single thread for 
     *      running it.
     */
    typedef void (*arp_receive_callback)(const void* arp_buf, int len, const eth_hdr_t* eth_header, int dev_id);

    /**
     * A default ARP receive callback function for processing an ARP packet upon receiving it.
     * If the packet is of type (ARP_TYPE_SD), the receiver will provide the ethernet source
     * address for answering the request.
     * Else if the packet is of type (ARP_TYPE_RCV), the receiver will use the received 
     * destinaion mac address and send the previously stored IP packet.
     * 
     * @param:
     *     See arp_receive_callback.
     */
    void default_arp_rcv_callback(const void* arp_buf, int len, const eth_hdr_t* eth_header, int dev_id);

    /**
     * Register a callback function to be called each time when an ARP packet was received.
     * 
     * @see: arp_receive_callback.
     */
    int set_arp_callback(arp_receive_callback arp_cb);
}

#endif