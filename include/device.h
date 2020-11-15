#ifndef _DEVICE_H
#define _DEVICE_H

#include "pcap.h"
#include "common.h"
#include "arp.h"
#include <cstdlib>
#include <string>
#include <vector>

#define PCAP_TIMEOUT 10 // 10ms
#define PCAP_BUF_SIZE 102400 // 100KB

namespace Device{
    using std::string;
    using std::vector;
    using ARP_lyr::arp_neighbor_info;

    /**
     * Definition of a device type.
     */
    struct device_t{
        pcap_if_t* dev_info;
        string dev_name;
        eth_addr_t ethernet_addr;
        vector<ipv4_addr_t> ipv4_addr;
        pcap_t* pcap_itfc;   // pointer to the pcap interface

        multi_th_vector<arp_neighbor_info> neighbor_info;
        volatile int quit_flag;

        int dev_id;

        device_t ();

        ~device_t ();

        /**
         * Start sniffing packets from pcap_itfc on the device.
         * This function should loop forever unless the device_t instance has been deleted.
         */
        void sniffing();

        /**
         * Launch the device and start sniffing packets from the device.
         * This function will try opening the device and if successful, launch 
         * another thread to sniff packets. The main thread should exit without blocking.
         * 
         * @return
         *     -1 on any launching error and 0 on success.
         */
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

    /**
     * Find a device according to device id, and return a device_t instance corresponding to the device id
     *
     * @param dev_id
     *     ID of the network device.
     * @return
     *     NULL if the device has not been added, and a device_t* if the corresponding device has been found.
     */
    device_t* find_device_inst(int dev_id);

    /**
     * Delete a device and terminate the capture process on the device
     * 
     * @param dev_id
     *     ID of the network device to be deleted.
     * @return
     *     -1 on error deleting the device or no corresponding device is found.
     *     0 on success.
     */
    int del_device(int dev_id);
}

#endif