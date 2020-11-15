#ifndef _TCP_H
#define _TCP_H

#include "common.h"

namespace TCP_lyr{
    typedef int (*TCP_packet_receive_callback)(const void* buf, int len, const ipv4_hdr_t* ip_header);

    int default_tcp_rcv_callback(const void* buf, int len, const ipv4_hdr_t* ip_header);
}

#endif