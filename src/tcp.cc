#include "tcp.h"
#include "common.h"
#include "kernel.h"

extern FILE* log_stream;
extern Kernel::kernel_t core;

namespace TCP_lyr{
    int default_tcp_rcv_callback(const void* buf, int len, const ipv4_hdr_t* ip_header){
        char src_str[100], dst_str[100];
        gen_ipv4_str((u_char*)&ip_header->dst, dst_str);
        gen_ipv4_str((u_char*)&ip_header->src, src_str);
        fprintf(log_stream, "[TCP]: Receiving a packet: %s -> %s\n", src_str, dst_str);
        fprintf(log_stream, "[TCP]: Payload: %s\n", (char*)buf);
        return 0;
    }
}