#include "device.h"
#include "kernel.h"
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <netinet/ether.h> 
#include <linux/if_packet.h>
#include <netinet/ip.h>


namespace Device{
    using Kernel::core;
    using std::string;

    int device_t::launch(){
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_itfc = pcap_open_live(dev_name.c_str(), PCAP_BUF_SIZE, 0, PCAP_TIMEOUT, errbuf);
        if (pcap_itfc == NULL){
            fprintf(stderr, "[Error]: Cannot capture on device %s\n", dev_name.c_str());
            return -1;
        }

        /*Reference: https://www.tcpdump.org/pcap.html*/
        if (pcap_datalink(pcap_itfc) != DLT_EN10MB) {
            fprintf(stderr, "[Error]: Device %s doesn't provide Ethernet headers - not supported\n", dev_name.c_str());
            return -1;
        }

        // launch asynchronously
        
    }

    int addDevice(const char* device){
        char errbuf[PCAP_ERRBUF_SIZE];
        int ret = -1;
        pcap_if_t* all_devs;

        int res = pcap_findalldevs(&all_devs, errbuf);
        if (res != 0){
            fprintf(stderr, "[Error]: No device found\n");
            return -1;
        }

        if (device == NULL){
            fprintf(stderr, "[Error]: Invalid device name\n");
            return -1;
        }


        for (pcap_if_t* cur_dev = all_devs; cur_dev != NULL; cur_dev = cur_dev->next){
            char* dev_name = cur_dev->name;
            if (strcmp(dev_name, device) == 0){
                device_t* new_device = NULL;
                new_device = new device_t();
                new_device->dev_info = cur_dev;
                new_device->dev_name = string(cur_dev->name);
                new_device->dev_id = core.allo_device_id + 1;

                bool flag_ether = 0, flag_ipv4 = 0;
                for (pcap_addr_t* cur_addr = cur_dev->addresses; cur_addr != NULL; cur_addr = cur_addr->next){
                    if (cur_addr->addr->sa_family == AF_PACKET){ // ethernet address
                        if (flag_ether == 1){
                            fprintf(stderr, "[Error]: Multiple MAC addresses on a single device\n");
                            return -1;
                        }
                        
                        sockaddr_ll* phy_addr = (sockaddr_ll*)cur_addr->addr;

                        if (phy_addr->sll_halen != 6){
                            fprintf(stderr, "[Error]: Unexpected MAC address length\n");
                            return -1;
                        }

                        memcpy(&new_device->ethernet_addr, phy_addr->sll_addr, sizeof(eth_addr_t));

                        flag_ether = 1;
                    }


                    else if (cur_addr->addr->sa_family == AF_INET){ // ipv4
                        if (flag_ipv4 == 1){
                            fprintf(stderr, "[Error]: Multiple ipv4 addresses on a single device\n");
                            return -1;
                        }

                        sockaddr_in* ip_addr = (sockaddr_in*)cur_addr->addr;
                        memcpy((void*)&new_device->ipv4_addr, (void*)&ip_addr->sin_addr, sizeof(ipv4_addr_t));

                        flag_ipv4 = 1;
                    }
                }

                #ifdef DEBUG_MODE
                    printf("Found a new device: (%s, %d)\n", new_device->dev_name, new_device->dev_id);
                #endif
                
                if (!flag_ether){
                    fprintf(stderr, "Cannot found the MAC address\n");
                    return -1;
                }

                if (new_device->launch() == 0){ // start capturing successfully
                    ret = new_device->dev_id;
                    core.allo_device_id++;
                    core.devices.push_back(new_device);
                }
                else{
                    delete(new_device);
                    fprintf(stderr, "[Error]: Failed to launch this device\n");
                    return -1;
                }
            }
        }
        return ret;
    }

    int findDevice(const char* device){
        int tot_device = core.devices.size();
        for (int i = 0; i < tot_device; i++){
            device_t* cur_dev = core.devices[i];
            if (cur_dev->dev_name == string(device)){
                return cur_dev->dev_id;
            }
        }
        return -1;
    }
}