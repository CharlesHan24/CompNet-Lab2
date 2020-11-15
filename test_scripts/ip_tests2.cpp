#include <cstdio>
#include <cstdlib>
#include "arp.h"
#include "ip.h"
#include "kernel.h"
#include "tcp.h"
#include "device.h"
#include "packetio.h"
#include <unistd.h>
using namespace std;

Kernel::kernel_t core;
FILE* log_stream;

int main(int argc, char* argv[]){
    if (argc <= 3){
        printf("Usage: ./ip_tests LOG_FILE_NAME ROLE (IP_DST) DEV1 DEV2 DEV3 ...\n");
        return 0;
    }

    log_stream = fopen(argv[1], "w");

    Packet_IO::setFrameReceiveCallback(Packet_IO::default_eth_rcv_callback);
    ARP_lyr::set_arp_callback(ARP_lyr::default_arp_rcv_callback);
    IP_lyr::setIPPacketReceiveCallback(IP_lyr::default_ip_rcv_callback);
    core.tcp_cb = TCP_lyr::default_tcp_rcv_callback;

    int role = atoi(argv[2]);
    if (role >= 2){
        printf("Error: ROLE must be 0 or 1\n");
        return 0;
    }
    if (role == 0){
        sleep(1);
    }

    int i = 3;
    ipv4_addr_t ip_dst;
    if (role == 0){
        sscanf(argv[3], "%d.%d.%d.%d", &ip_dst.addr[0], &ip_dst.addr[1], &ip_dst.addr[2], &ip_dst.addr[3]);
        i++;
    }

    for (; i < argc; i++){
        Device::addDevice(argv[i]);
    }

    if (role == 0){
        eth_addr_t eth_device_fwd;
        eth_device_fwd = {
            .addr = {0x4e, 0x2e, 0x15, 0xc7, 0x71, 0x34}
        };
        ipv4_addr_t mask = {
            .addr = {0xff, 0xff, 0xff, 0xff}
        };
        IP_lyr::setRoutingTable(ip_dst, mask, &eth_device_fwd, "veth1-2");

        char buf[100] = "01234567890123456789012345678901234567890123456789";
        IP_lyr::sendIPPacket(core.devices[0]->ipv4_addr[0], ip_dst, 6, buf, 50);
        sleep(10);
        buf[0] = 'a';
        buf[50] = 0;
        IP_lyr::sendIPPacket(core.devices[0]->ipv4_addr[0], ip_dst, 6, buf, 50);
    }
    else{
        for (i = 0; i < 1000; i++){
            sleep(1);
            fflush(log_stream);
        }
    }
    return 0;
}