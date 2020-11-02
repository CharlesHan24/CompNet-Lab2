#include "device.h"
#include "kernel.h"
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <netinet/ether.h> 
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <thread>

extern Kernel::kernel_t core;
extern FILE* log_stream;

namespace Device{
    using std::string;
    using std::thread;

    device_t::device_t(){
        quit_flag = 0;
    }

    device_t::~device_t(){
        quit_flag = 1;
        if (pcap_itfc != NULL){
            pcap_close(pcap_itfc);
        }
        delete(dev_info);
    }

    void device_t::sniffing(){
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_pkthdr* pkt_hdr;
        char* pkt_data;
        int res;

        // loop indefinitely
        while (!quit_flag){
            res = pcap_next_ex(pcap_itfc, &pkt_hdr, (const u_char**)&pkt_data);
            if (res == 1){ // success
                #ifdef DEBUG_MODE
                    fprintf(log_stream, "Successfully read a packet on device %s\n", dev_name.c_str());
                #endif

                if (core.ether_cb == NULL){
                    #ifdef DEBUG_MODE
                        fprintf(log_stream, "[Warning]: No ethernet callback function is registered, and the packet will be simply dropped");
                    #endif
                }
                else{
                    if (core.ether_cb(pkt_data, pkt_hdr->len, dev_id) != 0){
                        fprintf(log_stream, "[Error]: Error executing ethernet callback function at device %s\n", dev_name.c_str());
                        return;
                    }
                }
            }
            else if (res == 0){ // timeout
                #ifdef DEBUG_MODE
                    fprintf(log_stream, "[Warning]: Timeout on device %s\n", dev_name.c_str());
                #endif
                continue;
            }
            
            else{
                fprintf(log_stream, "[Error]: Error occurs when reading the packet on device %s\n", dev_name.c_str());
                return;
            }
        }
    }

    int device_t::launch(){ // no blocking
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_itfc = pcap_open_live(dev_name.c_str(), PCAP_BUF_SIZE, 0, PCAP_TIMEOUT, errbuf);
        if (pcap_itfc == NULL){
            fprintf(log_stream, "[Error]: Cannot capture on device %s\n", dev_name.c_str());
            return -1;
        }

        /*Reference: https://www.tcpdump.org/pcap.html*/
        if (pcap_datalink(pcap_itfc) != DLT_EN10MB) {
            fprintf(log_stream, "[Error]: Device %s doesn't provide Ethernet headers - not supported\n", dev_name.c_str());
            return -1;
        }

        // launch asynchronously
        thread sniff_th(&device_t::sniffing, this);
        sniff_th.detach();
        return 0;
    }

    int addDevice(const char* device){
        char errbuf[PCAP_ERRBUF_SIZE];
        char mac_addr_display[100];
        int ret = -1;
        pcap_if_t* all_devs;

        int res = pcap_findalldevs(&all_devs, errbuf);
        if (res != 0){
            fprintf(log_stream, "[Error]: No device found\n");
            return -1;
        }

        if (device == NULL){
            fprintf(log_stream, "[Error]: Invalid device name\n");
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
                            fprintf(log_stream, "[Error]: Multiple MAC addresses on a single device\n");
                            return -1;
                        }
                        
                        sockaddr_ll* phy_addr = (sockaddr_ll*)cur_addr->addr;

                        if (phy_addr->sll_halen != 6){
                            fprintf(log_stream, "[Error]: Unexpected MAC address length\n");
                            return -1;
                        }

                        memcpy(&new_device->ethernet_addr, phy_addr->sll_addr, sizeof(eth_addr_t));
                        gen_mac_str((unsigned char*)&new_device->ethernet_addr, mac_addr_display);
                        fprintf(log_stream, "The target device's MAC address is %s\n", mac_addr_display);

                        flag_ether = 1;
                    }


                    else if (cur_addr->addr->sa_family == AF_INET){ // ipv4
                        if (flag_ipv4 == 1){
                            fprintf(log_stream, "[Error]: Multiple ipv4 addresses on a single device\n");
                            return -1;
                        }

                        sockaddr_in* ip_addr = (sockaddr_in*)cur_addr->addr;
                        memcpy((void*)&new_device->ipv4_addr, (void*)&ip_addr->sin_addr, sizeof(ipv4_addr_t));

                        flag_ipv4 = 1;
                    }
                }

                #ifdef DEBUG_MODE
                    fprintf(log_stream, "Found a new device: (%s, %d)\n", new_device->dev_name.c_str(), new_device->dev_id);
                #endif
                
                if (!flag_ether){
                    fprintf(log_stream, "Cannot found the MAC address\n");
                    return -1;
                }

                if (new_device->launch() == 0){ // start capturing successfully
                    ret = new_device->dev_id;
                    core.allo_device_id++;
                    core.devices.push_back(new_device);
                }
                else{
                    delete(new_device);
                    fprintf(log_stream, "[Error]: Failed to launch this device\n");
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

    device_t* find_device_inst(int dev_id){
        int dev_cnt = core.devices.size();
        for (int i = 0; i < dev_cnt; i++){
            if (core.devices[i]->dev_id == dev_id){
                return core.devices[i];
            }
        }
        return NULL;
    }

    int del_device(int dev_id){
        int dev_cnt = core.devices.size();
        int ret = -1;

        for (int i = 0; i < dev_cnt; i++){
            if (core.devices[i]->dev_id == dev_id){
                delete(core.devices[i]);
                for (int j = i; j < dev_cnt - 1; j++){
                    core.devices[j] = core.devices[j + 1];
                }
                core.devices.pop_back();
                ret = 0;
                break;
            }
        }
        return ret;
    }
}