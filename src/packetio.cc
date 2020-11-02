#include "device.h"
#include "kernel.h"
#include "packetio.h"
#include "common.h"
#include <cstring>

extern FILE* log_stream;
extern Kernel::kernel_t core;

namespace Packet_IO{
    using Device::device_t;
    using Device::find_device_inst;

    int sendFrame(const void* buf, int len, int ethtype, const void* destmac, int id){
        char mac_addr_display[100];
        char errbuf[PCAP_ERRBUF_SIZE];


        if ((buf == NULL) || (destmac == NULL)){
            fprintf(log_stream, "[Error]: No buf or destmac specified\n");
            return -1;
        }

        #ifdef DEBUG_MODE
            gen_mac_str((unsigned char*)destmac, mac_addr_display);
            fprintf(log_stream, "Sending frame to %s\n", mac_addr_display);
        #endif

        
        device_t* cur_device = find_device_inst(id);
        
        if (cur_device == NULL){
            fprintf(log_stream, "[Error]: Could not find device #%d\n", id);
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
        #ifdef DEBUG_MODE
            for (int i = 0; i < 68; i++){
                printf("%c", *(frame_buf + i));
            }
            printf("\n");
        #endif
        // last 4 bits are random: do not compute the checksum


        // send_frame
        if (pcap_sendpacket(cur_device->pcap_itfc, (u_char*)frame_buf, len + sizeof(eth_hdr_t) + 4) != 0){
            fprintf(log_stream, "[Error]: Failed to send this packet\n");
            return -1;
        }
        return 0;
    }

    int setFrameReceiveCallback(frameReceiveCallback callback){
        core.ether_cb = callback;
        return 0;
    }

    int eth_debug_callback(const void* buf, int len, int dev_id){
        char src_addr[100];
        char dst_addr[100];

        #ifdef DEBUG_MODE
            for (int i = 0; i < 68; i++){
                printf("%c", *((char*)buf + i));
            }
            printf("\n");
        #endif
        eth_hdr_t* header = (eth_hdr_t*)buf;
        gen_mac_str((unsigned char*)&header->src_mac, src_addr);
        gen_mac_str((unsigned char*)&header->dst_mac, dst_addr);

        device_t* cur_device = find_device_inst(dev_id);

        if ((header == NULL) || (cur_device == NULL)){
            printf("Error\n");
            return -1;
        }

        fprintf(log_stream, "Address: %s -> %s\nDevice: %s\nPayload length: %d\n", src_addr, dst_addr, cur_device->dev_name.c_str(), len);
        return 0;
    }
}