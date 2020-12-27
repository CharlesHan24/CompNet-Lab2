#ifndef _ARP_H
#define _ARP_H

namespace ARP{
    void init();

    int send_arp_request(const void* payload, int len, const ipv4_hdr_t* ip_header);

    typedef void (*arp_receive_callback)(const void* arp_buf, int len, const eth_hdr_t* eth_header, int dev_id);
}

#endif