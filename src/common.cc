#include "common.h"
#include <cstdio>

void gen_mac_str(const unsigned char* mac_addr, char* display_mac_addr){
    sprintf(
        display_mac_addr,
        "%02x:%02x:%02x:%02x:%02x:%02x",
        mac_addr[0], mac_addr[1], mac_addr[2],
        mac_addr[3], mac_addr[4], mac_addr[5]
    );
}

/**
 *  ipv4_addr: Big endian
 */
void gen_ipv4_str(const unsigned char* ipv4_addr, char* display_ipv4_addr){
    sprintf(
        display_ipv4_addr,
        "%d.%d.%d.%d",
        ipv4_addr[0], ipv4_addr[1], ipv4_addr[2],
        ipv4_addr[3]
    );
}

uint64_t get_time(){
    timespec cur_time;
    //clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cur_time);
    clock_gettime(CLOCK_REALTIME, &cur_time);
    return cur_time.tv_nsec + 1000000000ul * cur_time.tv_sec;
}