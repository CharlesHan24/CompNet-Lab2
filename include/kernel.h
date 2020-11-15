#ifndef _SIM_KERNEL_H
#define _SIM_KERNEL_H

#include "device.h"
#include "packetio.h"
#include "arp.h"
#include "ip.h"
#include "tcp.h"
#include <vector>

namespace Kernel{
    using std::vector;
    using Device::device_t;
    using Packet_IO::frameReceiveCallback;
    using ARP_lyr::arp_receive_callback;
    using IP_lyr::IPPacketReceiveCallback;
    using TCP_lyr::TCP_packet_receive_callback;

    /**
     * Definition of a "simulated" kernel type. 
     * The "simulated" kernel performs the layer 2 & 3 & 4 tasks.
     */
    struct kernel_t{
        vector<device_t*> devices;
        volatile int quit_flag;
        
        int allo_device_id;
        frameReceiveCallback ether_cb;
        arp_receive_callback arp_cb;
        IPPacketReceiveCallback ip_cb;
        TCP_packet_receive_callback tcp_cb;
        
        kernel_t ();
        ~kernel_t ();
    };

    /**
     *  Redirect log info output stream to another FILE*.
     * 
     *  @param redirect
     *      The target output file stream.
     */
    void set_log_stream(FILE* redirect);
}

#endif