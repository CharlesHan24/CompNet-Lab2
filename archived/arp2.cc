#include "arp.h"
#include "common.h"
#include "kernel.h"
#include "packetio.h"
#include <map>
#include <vector>
#include <cstring>

extern Kernel::kernel_t core;
extern FILE* log_stream;

// TODO: delete in_flight_arp_buf if timeout
namespace ARP{
    using std::map;
    using std::pair;
    using std::vector;

    using Packet_IO::sendFrame;
    static multi_th_map<ipv4_addr_t, pair<int, eth_addr_t> >arp_map;

    static multi_th_vector<pair<int, void*> >in_flight_arp_buf;
    
    void init(){
        in_flight_arp_buf.vec.clear();
        arp_map.mp.clear();
    }

    int send_arp_request(const void* tcp_buf, int len, const ipv4_hdr_t* ip_header){
        #ifdef DEBUG_MODE
            fprintf(log_stream, "Sending ARP Request\n");
        #endif
        ipv4_addr_t dst_ip = ip_header->dst;

        char* ip_buf = new char[len + sizeof(ipv4_hdr_t)];
        memcpy(ip_buf, ip_header, sizeof(ipv4_hdr_t));
        memcpy(ip_buf + sizeof(ipv4_hdr_t), tcp_buf, len);

        arp_map.lock.lock();
        if (arp_map.mp.find(dst_ip) != arp_map.mp.end()){ //
            int dev_id = arp_map.mp[dst_ip].first;
            eth_addr_t dst_mac = arp_map.mp[dst_ip].second;
            arp_map.lock.unlock();

            int res = sendFrame(ip_buf, len + sizeof(ipv4_hdr_t), ETH_TYPE_IPV4, &dst_mac, dev_id);
            delete(ip_buf);

            return res;
        }
        else{
            arp_hdr_t arp_header;
            arp_header.src = ip_header->src;
            arp_header.dst = dst_ip;
            arp_header.arp_type = ARP_TYPE_SD;

            in_flight_arp_buf.lock.lock();
            in_flight_arp_buf.vec.push_back(pair<int, void*>(len + sizeof(ipv4_hdr_t), ip_buf));
            in_flight_arp_buf.lock.unlock();
            
            int tot_device = core.devices.size();
            for (int i = 0; i < tot_device; i++){
                int dev_id = core.devices[i]->dev_id;
                if (sendFrame((void*)&arp_header, len + sizeof(ipv4_hdr_t), ETH_TYPE_ARP, &ETH_BROADCAST_ADDR, dev_id) == -1){
                    fprintf(log_stream, "[Error]: Failed to send ARP request at device %d\n", dev_id);
                    in_flight_arp_buf.lock.lock();
                    in_flight_arp_buf.vec.pop_back();
                    in_flight_arp_buf.lock.unlock();
                    delete(ip_buf);
                    return -1;
                }
            }
        }
        return 0;
    }

    void default_arp_rcv_callback(const void* arp_buf, int len, const eth_hdr_t* eth_header, int dev_id){
        arp_hdr_t* arp_header = (arp_hdr_t*)arp_buf;
        uint8_t arp_type = arp_header->arp_type;

        if (arp_type == ARP_TYPE_SD){
            #ifdef DEBUG_MODE
                fprintf(log_stream, "Receiving ARP Request Packet\n");
            #endif

            int ipv4_cnt = core.devices[dev_id]->ipv4_addr.size();
            for (int i = 0; i < ipv4_cnt; i++){
                if (memcmp(&arp_header->dst, &core.devices[dev_id]->ipv4_addr[i], 4) == 0){
                    #ifdef DEBUG_MODE
                        fprintf(log_stream, "ARP Request hit\n");
                    #endif

                    arp_hdr_t reply_msg;
                    reply_msg.src = arp_header->dst;
                    reply_msg.dst = arp_header->src;
                    reply_msg.arp_type = ARP_TYPE_RCV;

                    sendFrame(&reply_msg, sizeof(arp_hdr_t), ETH_TYPE_ARP, &eth_header->src_mac, dev_id); // local mac address will be carried in ethernet header.
                    return;
                }
            }
            #ifdef DEBUG_MODE
                fprintf(log_stream, "ARP Request miss\n");
            #endif
            return;
        }

        else if (arp_type == ARP_TYPE_RCV){
            in_flight_arp_buf.lock.lock();
            int wait_size = in_flight_arp_buf.vec.size();

            bool flag = 0;
            for (int i = 0; i < wait_size; i++){
                ipv4_hdr_t* cur_hdr = (ipv4_hdr_t*)in_flight_arp_buf.vec[i].second;
                if ((memcmp(&arp_header->dst, &core.devices[dev_id]->ipv4_addr[0], 4) == 0) && (memcmp(&arp_header->src, &cur_hdr->dst, 4) == 0)){
                    #ifdef DEBUG
                        fprintf(log_stream, "ARP Receive success at device %d\n", dev_id);
                    #endif
                    
                    flag = 1;
                    arp_map.lock.lock();
                    arp_map.mp[cur_hdr->dst] = pair<int, eth_addr_t>(dev_id, eth_header->src_mac);

                    int res = sendFrame(in_flight_arp_buf.vec[i].second, in_flight_arp_buf.vec[i].first, ETH_TYPE_IPV4, &eth_header->src_mac, dev_id);
                    
                    if (res == -1){
                        fprintf(log_stream, "[Error]: Failed to send IP packet at device %d\n", dev_id);
                    }
                    break;
                }
            }

            #ifdef DEBUG
                if (!flag){
                    fprintf(log_stream, "[Error]: Receive a wrong ARP response packet\n");
                }
            #endif
            in_flight_arp_buf.lock.unlock();
        }
    }
}