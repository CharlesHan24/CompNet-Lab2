/** 
 * @file device.h
 * @brief Library supporting network device management.
 */

#ifndef _DEVICE_H
#define _DEVICE_H

#include "pcap.h"
#include "common.h"
#include <cstdlib>
#include <string>

#define PCAP_TIMEOUT 10 // 10ms
#define PCAP_BUF_SIZE 102400 // 100KB

namespace Device{
    using std::string;
    struct device_t{
        pcap_if_t* dev_info;
        string dev_name;
        eth_addr_t ethernet_addr;
        ipv4_addr_t ipv4_addr;
        pcap_t* pcap_itfc;
        volatile int quit_flag;

        int dev_id;

        device_t ();

        ~device_t ();

        void sniffing();
        int launch();

    };


    /**
     * Add a device to the library for sending/receiving packets. 
     *
     * @param device Name of network device to send/receive packet on.
     * @return A non-negative _device-ID_ on success, -1 on error.
     */
    int addDevice(const char* device);

    /**
     * Find a device added by `addDevice`.
     *
     * @param device Name of the network device.
     * @return A non-negative _device-ID_ on success, -1 if no such device 
     * was found.
     */
    int findDevice(const char* device);

    device_t* find_device_inst(int dev_id);

    int del_device(int dev_id);
}

#endif