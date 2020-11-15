#include "arp.h"
#include "common.h"
#include "kernel.h"
#include "packetio.h"
#include <map>
#include <vector>
#include <cstring>

extern Kernel::kernel_t core;
extern FILE* log_stream;

namespace ARP_lyr{
    using std::map;
    using std::pair;
    using std::vector;
    using Device::device_t;
    using Device::find_device_inst;

    using Packet_IO::sendFrame;


    static multi_th_vector<in_flight_arp_item>in_flight_arp_buf;
    static multi_th_uint<uint32_t> global_arp_id;
    
    void init(){
        in_flight_arp_buf.lock.unlock();
        in_flight_arp_buf.vec.clear();
        global_arp_id.lock.unlock();
        global_arp_id.integ = 0;
    }

    void exiting(){
        in_flight_arp_buf.lock.lock();
        for (auto it = in_flight_arp_buf.vec.begin(); it != in_flight_arp_buf.vec.end(); it++){
            delete((char*)it->payload);
        }
        in_flight_arp_buf.vec.clear();
        global_arp_id.lock.lock();
    }

    int send_arp_request_broadcast(const void* tcp_buf, int len, const ipv4_hdr_t* ip_header){
        #ifdef DEBUG_MODE
            fprintf(log_stream, "[ARP]: Sending ARP Request\n");
        #endif
        ipv4_addr_t dst_ip = ip_header->dst;

        int ret = 0;
        char* ip_buf = new char[len + sizeof(ipv4_hdr_t)];
        memcpy(ip_buf, ip_header, sizeof(ipv4_hdr_t));
        memcpy(ip_buf + sizeof(ipv4_hdr_t), tcp_buf, len);

        for (auto it = core.devices.begin(); it != core.devices.end(); it++){
            device_t* cur_dev = *it;
            cur_dev->neighbor_info.lock.lock();

            if ((cur_dev->neighbor_info.vec.empty()) || ((get_time() - cur_dev->neighbor_info.vec[0].timestamp) / 1000000000l >= ARP_NEIGHBOR_TIMEOUT)){
                global_arp_id.lock.lock();
                global_arp_id.integ++;
                uint32_t cur_arp_id = global_arp_id.integ;
                global_arp_id.lock.unlock();

                char* cur_arp_buf = new char[len + sizeof(ipv4_hdr_t)];
                memcpy(cur_arp_buf, ip_buf, len + sizeof(ipv4_hdr_t));
                uint64_t cur_timestamp = get_time();
                in_flight_arp_buf.lock.lock();
                in_flight_arp_buf.vec.push_back((in_flight_arp_item){cur_arp_buf, len + sizeof(ipv4_hdr_t), cur_arp_id, cur_timestamp});

                arp_hdr_t cur_arp_hdr;
                cur_arp_hdr.src = cur_dev->ipv4_addr[0];
                cur_arp_hdr.arp_type = ARP_TYPE_SD;
                cur_arp_hdr.arp_cast = ARP_BROADCAST;
                cur_arp_hdr.arp_id = cur_arp_id;
                
                if (sendFrame(&cur_arp_hdr, sizeof(arp_hdr_t), ETH_TYPE_ARP, &ETH_BROADCAST_ADDR, cur_dev->dev_id) == -1){
                    fprintf(log_stream, "[Error]: [ARP]: Failed to send ARP request at device %d\n", cur_dev->dev_id);
                    ret = -1;
                }

                in_flight_arp_buf.lock.unlock();
            }
            else{
                #ifdef DEBUG_MODE
                    fprintf(log_stream, "[ARP]: ARP hit at device %d\n", cur_dev->dev_id);
                #endif
                for (auto jt = cur_dev->neighbor_info.vec.begin(); jt != cur_dev->neighbor_info.vec.end(); jt++){
                    if (sendFrame(ip_buf, sizeof(ipv4_hdr_t) + len, ETH_TYPE_IPV4, &jt->mac_addr, jt->dev_id) == -1){
                        fprintf(log_stream, "[Error]: [ARP]: Failed to send ARP request at device %d\n", cur_dev->dev_id);
                        ret = -1;
                    }
                }
            }
            cur_dev->neighbor_info.lock.unlock();
        }
        delete(ip_buf);

        return ret;
    }

    void default_arp_rcv_callback(const void* arp_buf, int len, const eth_hdr_t* eth_header, int dev_id){
        arp_hdr_t* arp_header = (arp_hdr_t*)arp_buf;
        uint8_t arp_type = arp_header->arp_type;
        uint8_t arp_cast_type = arp_header->arp_cast;
        device_t* cur_dev = find_device_inst(dev_id);

        if (arp_type == ARP_TYPE_SD){
            #ifdef DEBUG_MODE
                fprintf(log_stream, "[ARP]: Receiving ARP Request Packet\n");
            #endif

            if (arp_cast_type != ARP_BROADCAST){
                fprintf(log_stream, "[Error]: [ARP]: Received an ARP packet with unsupported arp cast type\n");
                return;
            }

            arp_hdr_t reply_msg;
            reply_msg.src = cur_dev->ipv4_addr[0];
            reply_msg.dst = arp_header->src;
            reply_msg.arp_type = ARP_TYPE_RCV;
            reply_msg.arp_cast = ARP_E2E;
            reply_msg.arp_id = arp_header->arp_id;

            // local mac address will be carried in ethernet header.
            
            if (sendFrame(&reply_msg, sizeof(arp_hdr_t), ETH_TYPE_ARP, &eth_header->src_mac, dev_id) == -1){
                fprintf(log_stream, "[Error]: [ARP]: Failed to reply ARP message at device %d\n", dev_id);
            }

            return;
        }

        else if (arp_type == ARP_TYPE_RCV){
            #ifdef DEBUG_MODE
                fprintf(log_stream, "[ARP]: Receiving ARP Reply Packet\n");
            #endif

            if (arp_cast_type != ARP_E2E){
                fprintf(log_stream, "[Error]: [ARP]: Received an ARP packet with unsupported arp cast type\n");
                return;
            }
            
            in_flight_arp_buf.lock.lock();

            bool flag = 0;
            for (auto it = in_flight_arp_buf.vec.begin(); it != in_flight_arp_buf.vec.end();){
                in_flight_arp_item* cur_item = &(*it);
                uint64_t cur_timestamp = get_time();
                if ((cur_timestamp - cur_item->timestamp) / 1000000 >= ARP_IN_FLIGHT_TIMEOUT){
                    delete((char*)cur_item->payload);
                    it = in_flight_arp_buf.vec.erase(it);
                    continue;
                }
                it++;
                if ((arp_header->arp_id == cur_item->arp_id) && (memcmp(&arp_header->dst, &cur_dev->ipv4_addr[0], 4) == 0)){
                    #ifdef DEBUG_MODE
                        fprintf(log_stream, "[ARP]: ARP Receive success at device %d\n", dev_id);
                    #endif
                    
                    flag = 1;

                    cur_dev->neighbor_info.lock.lock();
                    cur_dev->neighbor_info.vec.push_back((arp_neighbor_info){cur_timestamp, dev_id, eth_header->src_mac});
                    cur_dev->neighbor_info.lock.unlock();

                    int res = sendFrame(cur_item->payload, cur_item->len, ETH_TYPE_IPV4, &eth_header->src_mac, dev_id);
                    
                    if (res == -1){
                        fprintf(log_stream, "[Error]: [ARP]: Failed to send IP packet at device %d\n", dev_id);
                    }
                    break;
                }
            }

            #ifdef DEBUG_MODE
                if (!flag){
                    fprintf(log_stream, "[Error]: [ARP]: Receive a wrong ARP response packet\n");
                }
            #endif
            in_flight_arp_buf.lock.unlock();
        }
    }

    int set_arp_callback(arp_receive_callback arp_cb){
        core.arp_cb = arp_cb;
        return 0;
    }
}