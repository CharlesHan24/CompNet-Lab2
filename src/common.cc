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