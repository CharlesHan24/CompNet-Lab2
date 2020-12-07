#include "device.h"
#include "kernel.h"
#include "packetio.h"
#include "common.h"
#include <cstring>
#include <thread>

extern FILE* log_stream;
extern Kernel::kernel_t core;

namespace Packet_IO{
    using Kernel::kernel_t;
    using Device::device_t;
    using Device::find_device_inst;
    using std::thread;

    int sendFrame(const void* buf, int len, int ethtype, const void* destmac, int id){
        char mac_addr_display[100];
        char errbuf[PCAP_ERRBUF_SIZE];


        if ((buf == NULL) || (destmac == NULL)){
            fprintf(log_stream, "[Error]: [ETH]: No buf or destmac specified\n");
            return -1;
        }

        #ifdef DEBUG_MODE
            gen_mac_str((unsigned char*)destmac, mac_addr_display);
            fprintf(log_stream, "[ETH]: Sending frame to %s\n", mac_addr_display);
        #endif

        
        device_t* cur_device = find_device_inst(id);
        
        if (cur_device == NULL){
            fprintf(log_stream, "[Error]: [ETH]: Could not find device #%d\n", id);
            return -1;
        }
        
        char* frame_buf = new char[len + sizeof(eth_hdr_t) + 4];
        eth_hdr_t ethernet_header;
        ethernet_header.dst_mac = *(eth_addr_t*)destmac;
        ethernet_header.src_mac = cur_device->ethernet_addr;
        ethernet_header.eth_type = ENDIAN_REV16(ethtype);
        
        memcpy(frame_buf, &ethernet_header, sizeof(eth_hdr_t)
        );
        memcpy(frame_buf + sizeof(eth_hdr_t), buf, len);
        // last 4 bits are random: do not compute the checksum


        // send_frame
        if (pcap_sendpacket(cur_device->pcap_itfc, (u_char*)frame_buf, len + sizeof(eth_hdr_t) + 4) != 0){
            delete(frame_buf);
            fprintf(log_stream, "[Error]: [ETH]: Failed to send this packet\n");
            return -1;
        }
        delete(frame_buf);
        return 0;
    }

    int setFrameReceiveCallback(frameReceiveCallback callback){
        core.ether_cb = callback;
        return 0;
    }

    int eth_debug_callback(const void* buf, int len, int dev_id){
        char src_addr[100];
        char dst_addr[100];

        eth_hdr_t* header = (eth_hdr_t*)buf;
        gen_mac_str((unsigned char*)&header->src_mac, src_addr);
        gen_mac_str((unsigned char*)&header->dst_mac, dst_addr);

        device_t* cur_device = find_device_inst(dev_id);

        if ((header == NULL) || (cur_device == NULL)){
            printf("Error\n");
            return -1;
        }

        fprintf(log_stream, "[ETH]: Address: %s -> %s\n[ETH]: Device: %s\n[ETH]: Payload length: %d\n", src_addr, dst_addr, cur_device->dev_name.c_str(), len);
        return 0;
    }

    int default_eth_rcv_callback(const void* buf, int len, int dev_id){
        if (buf == NULL){
            return -1;
        }
        if (len <= sizeof(eth_hdr_t) + 4){
            fprintf(log_stream, "[Error]: [ETH]: Received a malformed ethernet frame. Dropping\n");
            return -1;
        }

        #ifdef DEBUG_MODE
            eth_debug_callback(buf, len, dev_id);
        #endif

        eth_hdr_t* header = (eth_hdr_t*)buf;
        void* ip_buf = (void*)((uint64_t)buf + sizeof(eth_hdr_t));

        if ((memcmp(&header->dst_mac, &ETH_BROADCAST_ADDR, 6) != 0) && (memcmp(&header->dst_mac, &find_device_inst(dev_id)->ethernet_addr, 6) != 0)){
            fprintf(log_stream, "[ETH]: The target mac destination is incorrect; drop it.\n");
            return -1;
        }
        
        if (header->eth_type == ENDIAN_REV16(ETH_TYPE_ARP)){
            core.arp_cb(ip_buf, len - sizeof(eth_hdr_t) - 4, header, dev_id);
        }
        else if (header->eth_type == ENDIAN_REV16(ETH_TYPE_IPV4)){
            if (memcmp(&header->dst_mac, &ETH_BROADCAST_ADDR, 6) == 0){
                fprintf(log_stream, "[Error]: [ETH]: Ethernet broadcast is not allowed when sending IP packets\n");
                return -1;
            }
            core.ip_cb(ip_buf, len - sizeof(eth_hdr_t) - 4, header, dev_id);

        }
        else{
            fprintf(log_stream, "[Error]: [ETH]: Ethernet type not supported\n");
            return -1;
        }
        return 0;
    }
}