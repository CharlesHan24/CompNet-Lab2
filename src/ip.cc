#include "ip.h"
#include "common.h"
#include "arp.h"
#include "packetio.h"
#include "kernel.h"
#include "BOBHash.h"
#include "tcp.h"
#include <vector>
#include <cstring>
#include <unistd.h>
#include <thread>

extern Kernel::kernel_t core;
extern FILE* log_stream;

namespace IP_lyr{
    using std::vector;
    using std::thread;
    using Packet_IO::sendFrame;
    using Device::find_device_inst;
    using Device::findDevice;
    using ARP_lyr::send_arp_request_broadcast;

    static multi_th_vector<route_entry> route_table;
    static BOBHash64* hash_fun;
    static multi_th_map<uint64_t, uint64_t> ip_flood_visited;

    #define lowbit(x) (x? (x & (-x)): 1l << 32)
    static inline uint32_t rev_bit(uint32_t x){
        x = ((x >> 1) & 0x55555555u) | ((x & 0x55555555u) << 1);
        x = ((x >> 2) & 0x33333333u) | ((x & 0x33333333u) << 2);
        x = ((x >> 4) & 0x0f0f0f0fu) | ((x & 0x0f0f0f0fu) << 4);
        x = ((x >> 8) & 0x00ff00ffu) | ((x & 0x00ff00ffu) << 8);
        x = ((x >> 16) & 0xffffu) | ((x & 0xffffu) << 16);
        return x;
    }

    static int lpm(multi_th_vector<route_entry>*route_table, ipv4_addr_t dst){
        route_table->lock.lock();
        int size = route_table->vec.size();

        uint32_t dst_int = *(uint32_t*)&dst;
        int max_entry = -1;
        int64_t max_value = -1;
        for (int i = 0; i < size; i++){
            uint32_t entry_dst = *(uint32_t*)&route_table->vec[i].dst;
            uint32_t entry_mask = *(uint32_t*)&route_table->vec[i].mask;
            int64_t lpm_wo_mask = (uint64_t)(lowbit(rev_bit(entry_dst ^ dst_int)));
            int64_t cur_value = (uint64_t)(lowbit(rev_bit(~entry_mask))) <= lpm_wo_mask? lpm_wo_mask: -2;
            if (cur_value > max_value){
                cur_value = max_value;
                max_entry = i;
            }
        }
        route_table->lock.unlock();
        return max_entry;
    }

    static uint64_t calc_ip_payload_hash(const void* buf, int len){
        return hash_fun->run((char*)buf, len);
    }
    
    static uint16_t calc_ip_csum(ipv4_hdr_t* header){
        uint32_t csum = 0;
        int len = sizeof(ipv4_hdr_t);
        uint16_t* ptr = (uint16_t*)header;
        while (len > 1){
            csum += *ptr;
            ptr++;
            len -= 2;
        }
        if (len == 1){
            csum += (*(char*)ptr) << 8;
        }

        while (csum >> 16){
            csum = (csum & 0xffff) + (csum >> 16);
        }
        return ~((uint16_t)csum);
    }

    void init(){
        route_table.vec.clear();
        ip_flood_visited.mp.clear();
        hash_fun = new BOBHash64(1);
        thread cleaner(ip_flood_cleaner);
        cleaner.detach();
    }

    void exiting(){
        delete(hash_fun);
        route_table.lock.lock();
        route_table.vec.clear();
        ip_flood_visited.lock.lock();
        ip_flood_visited.mp.clear();
    }

    void ip_flood_cleaner(){
        while (!core.quit_flag){
            sleep(1);

            ip_flood_visited.lock.lock();
            for (auto it = ip_flood_visited.mp.begin(); it != ip_flood_visited.mp.end();){
                if ((get_time() - it->second) / 1000000 >= IP_FLOOD_TIMEOUT){
                    it = ip_flood_visited.mp.erase(it);
                }
                else{
                    it++;
                }
            }
            ip_flood_visited.lock.unlock();
        }
    }

    int ip_forwarding(const void* buf, int len, const ipv4_hdr_t* ip_header){
        char* ip_buf = new char[sizeof(ipv4_hdr_t) + len];
        memcpy(ip_buf, ip_header, sizeof(ipv4_hdr_t));
        memcpy(ip_buf + sizeof(ipv4_hdr_t), buf, len);

        ip_flood_visited.lock.lock();
        ip_flood_visited.mp[calc_ip_payload_hash(buf, len)] = get_time();
        ip_flood_visited.lock.unlock();

        int entry = lpm(&route_table, ip_header->dst);

        if (entry == -1){
            if (send_arp_request_broadcast(buf, len, ip_header) == -1){ // also braodcast IP packets
                fprintf(log_stream, "[Error]: [IP]: Failed to send IP packet\n");
                return -1;
            }

        }
        else{
            route_table.lock.lock();
            if (sendFrame(ip_buf, sizeof(ipv4_hdr_t) + len, ETH_TYPE_IPV4, &route_table.vec[entry].next_hop_mac, route_table.vec[entry].dev_id) == -1){
                fprintf(log_stream, "[Error]: [IP]: Failed to send IP packet\n");
            }
            route_table.lock.unlock();
        }
        delete(ip_buf);
        return 0;
    }

    int sendIPPacket(const ipv4_addr_t src, const ipv4_addr_t dst, int proto, const void *buf, int len){
        int ret = 0;

        if (buf == NULL){
            fprintf(log_stream, "[Error]: [IP]: NULL ip payload\n");
            return -1;
        }
        #ifdef DEBUG_MODE
            char src_str[100], dst_str[100];
            gen_ipv4_str((u_char*)&src, src_str);
            gen_ipv4_str((u_char*)&dst, dst_str);
            fprintf(log_stream, "[IP]: Sending IP packet from %s to %s\n", src_str, dst_str);
        #endif

        ipv4_hdr_t ip_header;
        ip_header.dst = dst;
        ip_header.src = src;
        ip_header.proto = proto;
        ip_header.version = 4;
        ip_header.ihl = sizeof(ipv4_hdr_t) / 4;
        ip_header.flags = IP_FLAG_DF;
        ip_header.ttl = IP_DEFAULT_TTL;
        ip_header.len = ENDIAN_REV16(sizeof(ipv4_hdr_t) + len);
        ip_header.ident = 0;
        ip_header.tos = 0;
        ip_header.hdr_csum = 0;
        ip_header.hdr_csum = calc_ip_csum(&ip_header);

        return ip_forwarding(buf, len, &ip_header);
    }

    int setIPPacketReceiveCallback(IPPacketReceiveCallback callback){
        core.ip_cb = callback;
        return 0;
    }

    void default_ip_rcv_callback(const void* buf, int len, const eth_hdr_t* eth_header, int dev_id){
        if (buf == NULL){
            fprintf(log_stream, "[Error]: [IP]: NULL IP payload\n");
            return;
        }
        
        ipv4_hdr_t* header = (ipv4_hdr_t*)buf;
        void* payload = (void*)((uint64_t)buf + sizeof(ipv4_hdr_t));
        len -= sizeof(ipv4_hdr_t);

        if ((len <= 0) || (header->ihl != sizeof(ipv4_hdr_t) / 4) || (len != ENDIAN_REV16(header->len) - sizeof(ipv4_hdr_t)) || (header->version != 4)){
            fprintf(log_stream, "[Warning]: [IP]: Malformed IP packet received. Dropping.\n");
            return;
        }

        if (calc_ip_csum(header) != 0){
            fprintf(log_stream, "[Warning]: [IP]: IP checksum incorrect. Dropping\n");
            return;
        }

        ipv4_addr_t src = header->src, dst = header->dst;

        #ifdef DEBUG_MODE
            char src_str[100], dst_str[100];
            gen_ipv4_str((u_char*)&src, src_str);
            gen_ipv4_str((u_char*)&dst, dst_str);
            fprintf(log_stream, "[IP]: Receiving an IP packet. src=%s, dst=%s\n", src_str, dst_str);
        #endif

        ip_flood_visited.lock.lock();
        uint64_t payload_hash = calc_ip_payload_hash(payload, len);
        if ((ip_flood_visited.mp[payload_hash] != 0) && ((get_time() - ip_flood_visited.mp[payload_hash]) / 1000000 <= IP_FLOOD_TIMEOUT)){
            #ifdef DEBUG_MODE
                fprintf(log_stream, "[IP]: Dup IP packet. Dropping this packet\n");
            #endif
            ip_flood_visited.lock.unlock();
            return;
        }
        ip_flood_visited.lock.unlock();

        if (header->flags != IP_FLAG_DF){
            #ifdef DEBUG_MODE
                fprintf(log_stream, "[IP]: Fragmented IP packet. Dropping this packet\n");
            #endif
            return;
        }

        if (memcmp(&dst, &find_device_inst(dev_id)->ipv4_addr[0], sizeof(ipv4_addr_t)) == 0){
            #ifdef DEBUG_MODE
                fprintf(log_stream, "[IP]: Hand over to TCP layer\n");
            #endif
            ip_flood_visited.lock.lock();
            ip_flood_visited.mp[calc_ip_payload_hash(payload, len)] = get_time();
            ip_flood_visited.lock.unlock();
            core.tcp_cb(payload, len, header);
        }
        else{
            header->ttl -= 1;
            if (header->ttl == 0){
                #ifdef DEBUG_MODE
                    fprintf(log_stream, "[IP]: TTL == 0. Dropping this packet\n");
                #endif
            }
            header->hdr_csum = 0;
            header->hdr_csum = calc_ip_csum(header);

            #ifdef DEBUG_MODE
                fprintf(log_stream, "[IP]: Destination not reached. Forwarding\n");
            #endif
            ip_forwarding(payload, len, header);
        }
    }

    int setRoutingTable(const ipv4_addr_t dst, const ipv4_addr_t mask, const void* nextHopMAC, const char *device){
        #ifdef DEBUG_MODE
            fprintf(log_stream, "[IP]: setting routing table\n");
        #endif
        route_table.lock.lock();
        int dev_id = findDevice(device);
        for (auto it = route_table.vec.begin(); it != route_table.vec.end(); it++){
            if ((memcmp(&it->dst, &dst, 4) == 0) && (memcmp(&it->mask, &mask, 4) == 0)){
                fprintf(log_stream, "[Error]: [IP]: Duplicate adding an entry to the routing table\n");
                route_table.lock.unlock();
                return -1;
            }
        }
        route_table.vec.push_back((route_entry){dst, mask, *(eth_addr_t*)nextHopMAC, dev_id});
        route_table.lock.unlock();
        return 0;
    }
}