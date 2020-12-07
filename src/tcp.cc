#include "tcp.h"
#include "ip.h"
#include "common.h"
#include "kernel.h"
#include <cstring>
#include <thread>
#include <queue>
#include <mutex>

extern FILE* log_stream;
extern Kernel::kernel_t core;

#define PACKET_DROP_RATE 30

namespace TCP_lyr{
    #define TCP_PROTO 6
    #define TCP_WIN_SIZE 32767
    #define TCP_DEFAULT_FLAG 0
    #define TCP_TIMEOUT 1000 // 1000ms
    #define TCP_CLOSED_TIMEOUT 30000 // 30s
    #define SYN_FL (1 << 6)
    #define ACK_FL (1 << 3)
    #define FIN_FL (1 << 7)

    using std::thread;
    using std::queue;
    using std::mutex;
    using IP_lyr::sendIPPacket;
    static tcp_ctx_t* glb_tcp_ctx[MAX_CONNECT_CNT];

    static int map_port_sockfd[65536];

    static const timespec pause_time = (timespec){.tv_sec = 0, .tv_nsec = 10000};

    int init(){
        memset(glb_tcp_ctx, 0, sizeof(glb_tcp_ctx));
        memset(map_port_sockfd, -1, sizeof(map_port_sockfd));
    }

    void exiting(){
        for (int i = 0; i < MAX_CONNECT_CNT; i++){
            if (glb_tcp_ctx[i] != NULL){
                glb_tcp_ctx[i]->lock->lock();
                tcp_close(glb_tcp_ctx[i], 1);
            }
        }
    }

    int tcp_init(tcp_ctx_t* tcp_state, mutex* lock, queue<socket_file_t*>* t2s_file, queue<socket_file_t*>* s2t_file){
        tcp_state->lock = lock;
        tcp_state->stat_code = TCP_CLOSED;
        tcp_state->t2s_file = t2s_file;
        tcp_state->s2t_file = s2t_file;
        tcp_state->last_seq = rand();
        tcp_state->last_ack = rand();

        tcp_state->tcp_backup_state = new tcp_ctx_t;
        tcp_state->wait_item = NULL;
    }

    static uint16_t tcp_calc_csum(void* buf, uint16_t len, ipv4_hdr_t* ipv4_header){
        char* csum_buf = new char[len + 12];
        memcpy(csum_buf, &ipv4_header->src, sizeof(ipv4_addr_t));
        memcpy(csum_buf + sizeof(ipv4_addr_t), &ipv4_header->dst, sizeof(ipv4_addr_t));
        csum_buf[8] = 0;
        csum_buf[9] = TCP_PROTO;
        *(uint16_t*)(csum_buf + 10) = (ENDIAN_REV16(len));
        memcpy(csum_buf + 12, buf, len);

        uint32_t csum = 0;
        len += 12;
        uint16_t* ptr = (uint16_t*)csum_buf;
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

    
    int tcp_set_addr(tcp_ctx_t* tcp_state, sockaddr* address, socklen_t peer_addr_len, int who){
        if (peer_addr_len != sizeof(sockaddr_in)){
            fprintf(log_stream, "[Error]: TCP: current socket address not supported\n");
            return -1;
        }

        if (who == 0){ // local
            tcp_state->local_addr = *address;
            tcp_state->local_addr_len = peer_addr_len;
            tcp_state->local_ipv4 = *(ipv4_addr_t*)(&((sockaddr_in*)address)->sin_addr);
            tcp_state->local_port = ((sockaddr_in*)address)->sin_port;
        }
        
        else{ // peer
            tcp_state->peer_addr = *address;
            tcp_state->peer_addr_len = peer_addr_len;
            tcp_state->peer_ipv4 = *(ipv4_addr_t*)(&((sockaddr_in*)address)->sin_addr);
            tcp_state->peer_port = ((sockaddr_in*)address)->sin_port;
        }
        return 0;
    }

    void tcp_close(tcp_ctx_t* tcp_state, int mode){
        uint16_t self_port = tcp_state->local_port;

        glb_tcp_ctx[map_port_sockfd[self_port] - SOCKET_FD_SHIFT] = NULL;
        map_port_sockfd[self_port] = -1;
        tcp_state->stat_code = TCP_CLOSED;

        delete(tcp_state->wait_item);
        while (!tcp_state->s2t_file->empty()){
            socket_file_t* new_packet = tcp_state->s2t_file->front();
            tcp_state->s2t_file->pop();
            delete(new_packet);
        }
        while (!tcp_state->t2s_file->empty()){
            socket_file_t* new_packet = tcp_state->t2s_file->front();
            tcp_state->t2s_file->pop();
            delete(new_packet);
        }
        tcp_state->lock->unlock();
        
        if (mode){
            delete(tcp_state->lock);
            delete(tcp_state->s2t_file);
            delete(tcp_state->t2s_file);
            delete(tcp_state);
        }
    }

    static void build_tcp_hdr(tcp_hdr_t* header, void* buf, int len, ipv4_hdr_t* ipv4_header, uint16_t src_port, uint16_t dst_port, uint8_t data_offset, uint32_t seq, uint32_t ack, uint16_t urg_ptr, uint16_t win_size, uint8_t ns_flag, uint8_t flags, uint32_t sd_time, uint32_t rc_time){
        header->src_port = src_port;
        header->dst_port = dst_port;
        header->data_offset = data_offset;
        header->seq_num = seq;
        header->ack_num = ack;
        header->urg_ptr = urg_ptr;
        header->win_size = win_size;
        header->ns_flag = ns_flag;
        header->flags = flags;
        header->sd_time = sd_time;
        header->rc_time = rc_time;

        header->csum = 0;
        header->csum = tcp_calc_csum(buf, len, ipv4_header);
    }

    // called by tcp_main_loop & callback
    int tcp_response_syn_ack(void* buf, int len, ipv4_hdr_t* ipv4_header, tcp_ctx_t* tcp_state){
        tcp_hdr_t* tcp_header = (tcp_hdr_t*)buf;

        if (((tcp_header->flags & SYN_FL) == 0) || (tcp_header->flags & ACK_FL)){
            fprintf(log_stream, "[Warning]: TCP: incorrect TCP flags when making TCP SYN-ACK\n");
            return -1;
        }

        delete(tcp_state->wait_item);
        tcp_state->wait_item = new tcp_wait_t;
        memset(tcp_state->wait_item, 0, sizeof(tcp_wait_t));
        tcp_state->wait_item->tcp_buf = new char[len];
        memcpy(tcp_state->wait_item->tcp_buf, buf, len);
        tcp_state->wait_item->ipv4_header = new ipv4_hdr_t;
        memcpy(tcp_state->wait_item->ipv4_header, ipv4_header, sizeof(ipv4_hdr_t));
        tcp_state->wait_item->len = len;
        
        tcp_state->wait_item->timestamp = tcp_state->wait_item->initial_timestamp = get_time();

        tcp_state->stat_code = TCP_SYN_RCVD;
        tcp_state->last_ack =  ENDIAN_REV32(tcp_header->seq_num) + 1;
        //tcp_state->last_seq = rand();
        
        sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = ENDIAN_REV16(tcp_header->src_port);
        memcpy(&address.sin_addr, &ipv4_header->src, sizeof(ipv4_addr_t));

        tcp_set_addr(tcp_state, (sockaddr*)&address, sizeof(sockaddr_in), 1);


        tcp_hdr_t* response = new tcp_hdr_t;
        ipv4_hdr_t ipv4_info;
        ipv4_info.dst = ipv4_header->src;
        ipv4_info.src = ipv4_header->dst;
        
        build_tcp_hdr(response, response, sizeof(tcp_hdr_t), &ipv4_info, tcp_header->dst_port,
            tcp_header->src_port, tcp_header->data_offset, 
            ENDIAN_REV32(tcp_state->last_seq), ENDIAN_REV32(tcp_state->last_ack), 
            tcp_header->urg_ptr, ENDIAN_REV16(TCP_WIN_SIZE),
            tcp_header->ns_flag, TCP_DEFAULT_FLAG | ACK_FL | SYN_FL,
            rand(), rand()
        );

        if (sendIPPacket(ipv4_header->dst, ipv4_header->src, TCP_PROTO, response, sizeof(tcp_hdr_t)) == -1){
            fprintf(log_stream, "[Error]: TCP: Failed to send TCP ACK packet at port %u\n", tcp_state->local_port);
            return -1;
        }
        fprintf(log_stream, "TCP: Sent a SYN-ACK packet\n");
        fflush(log_stream);
        return 0;
    }

    // called by tcp_main_loop
    int tcp_send_syn(tcp_ctx_t* tcp_state){
        if (tcp_state == NULL){
            return -1;
        }

        tcp_hdr_t* request = new tcp_hdr_t;
        ipv4_hdr_t ipv4_info;
        memcpy(&ipv4_info.dst, &tcp_state->peer_ipv4, sizeof(ipv4_addr_t));
        memcpy(&ipv4_info.src, &tcp_state->local_ipv4, sizeof(ipv4_addr_t));
        
        delete(tcp_state->wait_item);
        tcp_state->wait_item = new tcp_wait_t;

        memset(tcp_state->wait_item, 0, sizeof(tcp_wait_t));
        tcp_state->wait_item->timestamp = tcp_state->wait_item->initial_timestamp = get_time();

        tcp_state->stat_code = TCP_SYN_SENT;
        tcp_state->last_ack = 0;
        //tcp_state->last_seq = rand();


        build_tcp_hdr(request, request, sizeof(tcp_hdr_t), &ipv4_info, ENDIAN_REV16(tcp_state->local_port),
            ENDIAN_REV16(tcp_state->peer_port), 7, 
            ENDIAN_REV32(tcp_state->last_seq), 0, 
            0, ENDIAN_REV16(TCP_WIN_SIZE),
            0, TCP_DEFAULT_FLAG | SYN_FL,
            rand(), rand()
        );


        if (sendIPPacket(ipv4_info.src, ipv4_info.dst, TCP_PROTO, request, sizeof(tcp_hdr_t)) == -1){
            fprintf(log_stream, "[Error]: Failed to send TCP SYN packet at port %u\n", tcp_state->local_port);
            return -1;
        }
        fprintf(log_stream, "TCP: Sent a SYN packet\n");
        fflush(log_stream);
        return 0;
    }

    // called by callback
    int tcp_establish(void* buf, int len, ipv4_hdr_t* ipv4_header, tcp_ctx_t* tcp_state, int mode){
        if (tcp_state == NULL){
            return -1;
        }

        tcp_hdr_t* tcp_header = (tcp_hdr_t*)buf;
        if (mode == 0){
            if (((tcp_header->flags & SYN_FL) == 0) || ((tcp_header->flags & ACK_FL) == 0)){
                fprintf(log_stream, "[Warning]: TCP: incorrect TCP flags when making response to TCP SYN-ACK packet\n");
                return -1;
            }

            if ((ENDIAN_REV32(tcp_header->ack_num) != tcp_state->last_seq + 1) && 
                (ENDIAN_REV32(tcp_header->ack_num) != tcp_state->tcp_backup_state->last_seq + 1)){
                fprintf(log_stream, "[Error]: TCP: malformed TCP SYN-ACK packet\n");
                return -1;
            }
            if (ENDIAN_REV32(tcp_header->ack_num) != tcp_state->last_seq + 1){
                tcp_wait_t* wait_item = tcp_state->wait_item;
                memcpy(tcp_state, tcp_state->tcp_backup_state, sizeof(tcp_ctx_t));
                tcp_state->wait_item = wait_item;
            }
            else{
                delete(tcp_state->wait_item);
                tcp_state->wait_item = NULL;
            }

            memcpy(tcp_state->tcp_backup_state, tcp_state, sizeof(tcp_ctx_t));

            tcp_state->stat_code = TCP_ESTAB;

            tcp_state->last_ack = ENDIAN_REV32(tcp_header->seq_num) + 1;
            tcp_state->last_seq++;

            tcp_hdr_t* response = new tcp_hdr_t;
            ipv4_hdr_t ipv4_info;
            ipv4_info.dst = ipv4_header->src;
            ipv4_info.src = ipv4_header->dst;
            
            build_tcp_hdr(response, response, sizeof(tcp_hdr_t), &ipv4_info, tcp_header->dst_port,
                tcp_header->src_port, tcp_header->data_offset, 
                ENDIAN_REV32(tcp_state->last_seq), ENDIAN_REV32(tcp_state->last_ack), 
                tcp_header->urg_ptr, ENDIAN_REV16(TCP_WIN_SIZE),
                tcp_header->ns_flag, TCP_DEFAULT_FLAG | ACK_FL,
                rand(), rand()
            );

            if (sendIPPacket(ipv4_header->dst, ipv4_header->src, TCP_PROTO, response, sizeof(tcp_hdr_t)) == -1){
                fprintf(log_stream, "[Error]: TCP: Failed to send ACK packet at port %u\n", tcp_state->local_port);
                return -1;
            }
            fprintf(log_stream, "TCP: Sent a handshake ACK packet\n");
            fflush(log_stream);
        }

        else{
            if (((tcp_header->flags & SYN_FL) != 0) || ((tcp_header->flags & ACK_FL) == 0)){
                fprintf(log_stream, "[Warning]: TCP: incorrect TCP flags when making response to TCP handshake ACK packet\n");
                return -1;
            }

            if ((ENDIAN_REV32(tcp_header->seq_num) != tcp_state->last_ack) || (ENDIAN_REV32(tcp_header->ack_num) != tcp_state->last_seq + 1)){
                fprintf(log_stream, "[Error]: TCP: incorrect SEQ/ACK number when receiving TCP handshake ack\n");
                return -1;
            }
            
            fprintf(log_stream, "TCP: Received a handshake ACK packet\n");
            fflush(log_stream);

            delete(tcp_state->wait_item);
            tcp_state->wait_item = NULL;

            tcp_state->stat_code = TCP_ESTAB;
            tcp_state->last_seq++;

        }

        socket_file_t* succ_connect_msg = new socket_file_t;
        succ_connect_msg->msg_type = TCP_ACC_MSG;
        succ_connect_msg->content = NULL;

        tcp_state->t2s_file->push(succ_connect_msg);
        return 0;
    }

    // called by callback
    int tcp_send_packet(tcp_ctx_t* tcp_state, void* buf, int len){
        char* send_buf = new char[sizeof(tcp_hdr_t) + len];
        tcp_hdr_t* request = (tcp_hdr_t*)send_buf;
        ipv4_hdr_t ipv4_info;
        memcpy(&ipv4_info.dst, &tcp_state->peer_ipv4, sizeof(ipv4_addr_t));
        memcpy(&ipv4_info.src, &tcp_state->local_ipv4, sizeof(ipv4_addr_t));
        
        memcpy(send_buf + sizeof(tcp_hdr_t), buf, len);
        
        delete(tcp_state->wait_item);
        tcp_state->wait_item = new tcp_wait_t;
        tcp_state->wait_item->tcp_buf = new char[len];
        memcpy(tcp_state->wait_item->tcp_buf, buf, len);
        tcp_state->wait_item->len = len;
        
        tcp_state->wait_item->timestamp = tcp_state->wait_item->initial_timestamp = get_time();


        build_tcp_hdr(request, send_buf, sizeof(tcp_hdr_t) + len, &ipv4_info, ENDIAN_REV16(tcp_state->local_port),
            ENDIAN_REV16(tcp_state->peer_port), 7, 
            ENDIAN_REV32(tcp_state->last_seq), ENDIAN_REV32(tcp_state->last_ack), 
            0, ENDIAN_REV16(TCP_WIN_SIZE),
            0, TCP_DEFAULT_FLAG,
            rand(), rand()
        );


        if (sendIPPacket(ipv4_info.src, ipv4_info.dst, TCP_PROTO, send_buf, len + sizeof(tcp_hdr_t)) == -1){
            fprintf(log_stream, "[Error]: Failed to send TCP data packet at port %u\n", tcp_state->local_port);
            return -1;
        }
        fprintf(log_stream, "TCP: Sent a normal packet\n");
        fflush(log_stream);
        return 0;
    }

    // called by callback
    int tcp_response_ack(void* buf, int len, ipv4_hdr_t* ipv4_header, tcp_ctx_t* tcp_state){
        tcp_hdr_t* tcp_header = (tcp_hdr_t*)buf;

        if (((tcp_header->flags & SYN_FL)) || (tcp_header->flags & ACK_FL)){
            fprintf(log_stream, "[Warning]: TCP: incorrect TCP flags when making TCP normal ACK\n");
            return -1;
        }

        if ((ENDIAN_REV32(tcp_header->seq_num) != tcp_state->last_ack) && (ENDIAN_REV32(tcp_header->seq_num) != tcp_state->tcp_backup_state->last_ack)){
            fprintf(log_stream, "[Error]: TCP: incorrect TCP ACK number\n");
            return -1;
        }

        if (ENDIAN_REV32(tcp_header->seq_num) != tcp_state->last_ack){
            tcp_wait_t* wait_item = tcp_state->wait_item;
            memcpy(tcp_state, tcp_state->tcp_backup_state, sizeof(tcp_ctx_t));
            tcp_state->wait_item = wait_item;
        }
        else{ // first time to receive
            socket_file_t* new_packet = new socket_file_t;
            new_packet->msg_type = TCP_NML_PACKET;
            new_packet->content = new char[4 + len - sizeof(tcp_hdr_t)];
            *(int*)new_packet->content = len - sizeof(tcp_hdr_t);
            memcpy(new_packet->content + 4, buf + sizeof(tcp_hdr_t), len - sizeof(tcp_hdr_t));
            tcp_state->t2s_file->push(new_packet);

            delete(tcp_state->wait_item);
            tcp_state->wait_item = NULL;
        }

        memcpy(tcp_state->tcp_backup_state, tcp_state, sizeof(tcp_ctx_t));

        tcp_state->last_ack = ENDIAN_REV32(tcp_header->seq_num) + len - sizeof(tcp_hdr_t);
        tcp_state->last_seq = ENDIAN_REV32(tcp_header->ack_num);


        tcp_hdr_t* response = new tcp_hdr_t;
        ipv4_hdr_t ipv4_info;
        ipv4_info.dst = ipv4_header->src;
        ipv4_info.src = ipv4_header->dst;
        
        build_tcp_hdr(response, response, sizeof(tcp_hdr_t), &ipv4_info, tcp_header->dst_port,
            tcp_header->src_port, tcp_header->data_offset, 
            ENDIAN_REV32(tcp_state->last_seq), ENDIAN_REV32(tcp_state->last_ack), 
            tcp_header->urg_ptr, ENDIAN_REV16(TCP_WIN_SIZE),
            tcp_header->ns_flag, TCP_DEFAULT_FLAG | ACK_FL,
            rand(), rand()
        );

        if (sendIPPacket(ipv4_header->dst, ipv4_header->src, TCP_PROTO, response, sizeof(tcp_hdr_t)) == -1){
            fprintf(log_stream, "[Error]: TCP: Failed to send TCP ACK packet at port %u\n", tcp_state->local_port);
            return -1;
        }
        fprintf(log_stream, "TCP: Sent a normal ACK packet\n");
        fflush(log_stream);


        return 0;
    }

    int tcp_recv_ack(void* buf, int len, ipv4_hdr_t* ipv4_header, tcp_ctx_t* tcp_state){
        tcp_hdr_t* tcp_header = (tcp_hdr_t*)buf;

        if (((tcp_header->flags & SYN_FL)) || ((tcp_header->flags & ACK_FL) == 0)){
            fprintf(log_stream, "[Warning]: TCP: incorrect TCP flags when receiving TCP normal ACK\n");
            return -1;
        }

        if (ENDIAN_REV32(tcp_header->seq_num) != tcp_state->last_ack){
            fprintf(log_stream, "[Error]: TCP: incorrect TCP ACK number\n");
            return -1;
        }

        delete(tcp_state->wait_item);
        tcp_state->wait_item = NULL;
        tcp_state->last_ack = ENDIAN_REV32(tcp_header->seq_num) + len - sizeof(tcp_hdr_t);
        tcp_state->last_seq = ENDIAN_REV32(tcp_header->ack_num);

        return 0;
    }

    int tcp_launch_listen(tcp_ctx_t* tcp_state, int sock_fd){
        tcp_state->lock->lock();

        uint16_t self_port = tcp_state->local_port;

        if (sock_fd - SOCKET_FD_SHIFT >= MAX_CONNECT_CNT){
            fprintf(log_stream, "[Error]: TCP: incorrect sock_fd.");
            return -1;
        }

        if (map_port_sockfd[self_port] != -1){
            fprintf(log_stream, "[Error]: TCP: Port %d already occupied\n", self_port);
            return -1;
        }
        map_port_sockfd[self_port] = sock_fd;

        glb_tcp_ctx[sock_fd - SOCKET_FD_SHIFT] = tcp_state;

        tcp_state->stat_code = TCP_LISTEN;
        tcp_state->lock->unlock();

        thread wait_ack_thread(tcp_main_loop, tcp_state);
        wait_ack_thread.detach();

        return 0;
    }

    int tcp_launch_connect(tcp_ctx_t* tcp_state, int sock_fd){
        tcp_state->lock->lock();

        uint16_t self_port = tcp_state->local_port;

        if (sock_fd - SOCKET_FD_SHIFT >= MAX_CONNECT_CNT){
            fprintf(log_stream, "[Error]: TCP: incorrect sock_fd.");
            return -1;
        }

        if (map_port_sockfd[self_port] != -1){
            fprintf(log_stream, "[Error]: TCP: Port %d already occupied\n", self_port);
            return -1;
        }
        map_port_sockfd[self_port] = sock_fd;

        glb_tcp_ctx[sock_fd - SOCKET_FD_SHIFT] = tcp_state;

        tcp_send_syn(tcp_state);

        tcp_state->lock->unlock();

        thread wait_ack_thread(tcp_main_loop, tcp_state);
        wait_ack_thread.detach();

        return 0;
    }

    int debug_tcp_rcv_callback(const void* buf, int len, const ipv4_hdr_t* ip_header){
        char src_str[100], dst_str[100];
        gen_ipv4_str((u_char*)&ip_header->dst, dst_str);
        gen_ipv4_str((u_char*)&ip_header->src, src_str);
        fprintf(log_stream, "[TCP]: Receiving a packet: %s -> %s\n", src_str, dst_str);

        tcp_hdr_t* tcp_header = (tcp_hdr_t*)buf;
        fprintf(log_stream, "[TCP]: len: %d, src_port: %u, dst_port: %u, SEQ: %x, ACK: %x\n", len, ENDIAN_REV16(tcp_header->src_port), ENDIAN_REV16(tcp_header->dst_port), ENDIAN_REV32(tcp_header->seq_num), ENDIAN_REV32(tcp_header->ack_num));

        return 0;
    }

    int tcp_basic_check(void* buf, int len, ipv4_hdr_t* ip_header, tcp_ctx_t** tcp_state){
        if ((buf == NULL) || (ip_header == NULL)){
            fprintf(log_stream, "[Error]: TCP: receiving a malformed packet, dropping...\n");
            return -1;
        }
        
        if (tcp_calc_csum(buf, len, ip_header) != 0){
            fprintf(log_stream, "[Error]: TCP: incorrect checksum, dropping\n");
            return -1;
        }

        tcp_hdr_t* tcp_header = (tcp_hdr_t*)buf;
        if (tcp_header->data_offset != 7){
            fprintf(log_stream, "[Error]: TCP: not supported TCP packet type. We require that data offset = 7\n");
            return -1;
        }

        uint16_t self_port = ENDIAN_REV16(tcp_header->dst_port);
        uint32_t base_self_port = map_port_sockfd[self_port] - SOCKET_FD_SHIFT;
        fprintf(log_stream, "[TCP]: Socket_FD: %d\n", map_port_sockfd[self_port]);

        if ((base_self_port >= MAX_CONNECT_CNT) || (glb_tcp_ctx[base_self_port] == NULL)){
            fprintf(log_stream, "[Error]: TCP: no TCP connection on port %u\n", base_self_port);
            return -1;
        }

        *tcp_state = glb_tcp_ctx[base_self_port];
        (*tcp_state)->lock->lock();
        if (((*tcp_state)->stat_code == TCP_CLOSED) || (memcmp(&(*tcp_state)->local_ipv4, &ip_header->dst, sizeof(ipv4_addr_t)) != 0)){
            for (int i = 0; i < 4; i++){
                printf("%02x %02x\n", *((char*)&(*tcp_state)->local_ipv4) + i, *((char*)&ip_header->dst) + i);
            }
            fprintf(log_stream, "[Error]: TCP: five tuple not matched\n");
            (*tcp_state)->lock->unlock();
            return -1;
        }
        if (((*tcp_state)->stat_code != TCP_LISTEN) && ((memcmp(&(*tcp_state)->peer_ipv4, &ip_header->src, sizeof(ipv4_addr_t)) != 0) || (tcp_header->src_port != ENDIAN_REV16((*tcp_state)->peer_port)))){
            fprintf(log_stream, "[Error]: TCP: five tuple not matched\n");
            (*tcp_state)->lock->unlock();
            return -1;
        }
        return 0;
    }


    int default_tcp_rcv_callback(const void* buf, int len, const ipv4_hdr_t* ip_header){
        debug_tcp_rcv_callback(buf, len, ip_header);

        tcp_ctx_t* tcp_state;
        int ret;

        if (tcp_basic_check((void*)buf, len, (ipv4_hdr_t*)ip_header, &tcp_state) == -1){
            return -1;
        }

        if (rand() % 100 < PACKET_DROP_RATE){
            fprintf(log_stream, "[Simulating packet loss]: Dropping a packet\n");
            tcp_state->lock->unlock();
            return 0;
        }
        // returned tcp_state should be locked

        tcp_hdr_t* tcp_header = (tcp_hdr_t*)buf;
        if ((tcp_header->flags & SYN_FL) && (tcp_header->flags & ACK_FL)){
            ret = tcp_establish((void*)buf, len, (ipv4_hdr_t*)ip_header, tcp_state, 0);
        }

        else{
            switch (tcp_state->stat_code){
                case TCP_CLOSED:
                    ret = -1;
                    break;

                case TCP_LISTEN:
                    ret = tcp_response_syn_ack((void*)buf, len, (ipv4_hdr_t*)ip_header, tcp_state);
                    break;

                case TCP_SYN_SENT:
                    ret = tcp_establish((void*)buf, len, (ipv4_hdr_t*)ip_header, tcp_state, 0);
                    break;

                case TCP_SYN_RCVD:
                    ret = tcp_establish((void*)buf, len, (ipv4_hdr_t*)ip_header, tcp_state, 1);
                    break;

                case TCP_ESTAB:
                    if (((tcp_header->flags & SYN_FL) == 0) && ((tcp_header->flags & ACK_FL) == 0)){
                        ret = tcp_response_ack((void*)buf, len, (ipv4_hdr_t*)ip_header, tcp_state);
                    }
                    else if (((tcp_header->flags & SYN_FL) == 0) && ((tcp_header->flags & ACK_FL))){
                        ret = tcp_recv_ack((void*)buf, len, (ipv4_hdr_t*)ip_header
                        , tcp_state);
                    }
                    break;

                default:
                    ret = -1;
                
            }
        }
            
        tcp_state->lock->unlock();
        return ret;
    }

    void tcp_main_loop(tcp_ctx_t* tcp_state){
        printf("Launch main loop\n");
        timespec* _;
        uint64_t latest_timestamp = get_time();

        while (1){
            if (core.quit_flag == 1){
                return;
            }

            tcp_state->lock->lock();
            
            if ((tcp_state->wait_item != NULL) && ((get_time() - tcp_state->wait_item->timestamp) / 1000000 > TCP_TIMEOUT)){
                if ((get_time() - tcp_state->wait_item->initial_timestamp) / 1000000 > TCP_CLOSED_TIMEOUT){
                    fprintf(log_stream, "[TCP]: Timeout reached. Closing TCP connection\n");
                    fflush(log_stream);
                    tcp_close(tcp_state, 0);
                    return;
                }

                uint64_t initial_timestamp = tcp_state->wait_item->initial_timestamp;

                if (tcp_state->stat_code == TCP_SYN_SENT){
                    tcp_send_syn(tcp_state);
                    tcp_state->wait_item->initial_timestamp = initial_timestamp;
                }
                else{
                    char* tcp_buf_copy = new char[tcp_state->wait_item->len];
                    ipv4_hdr_t* ipv4_header_copy = new ipv4_hdr_t;
                    memcpy(tcp_buf_copy, tcp_state->wait_item->tcp_buf, tcp_state->wait_item->len);
                    if (tcp_state->stat_code == TCP_SYN_RCVD){
                        memcpy(ipv4_header_copy, tcp_state->wait_item->ipv4_header, sizeof(ipv4_hdr_t));
                        tcp_response_syn_ack(tcp_buf_copy, tcp_state->wait_item->len, ipv4_header_copy, tcp_state);
                    }
                    else{
                        tcp_send_packet(tcp_state, tcp_buf_copy, tcp_state->wait_item->len);
                    }

                    tcp_state->wait_item->initial_timestamp = initial_timestamp;

                    delete(tcp_buf_copy);
                    delete(ipv4_header_copy);
                }
                latest_timestamp = get_time();
            }

            else if (tcp_state->wait_item == NULL){
                if (!tcp_state->s2t_file->empty()){
                    socket_file_t* new_packet = tcp_state->s2t_file->front();
                    tcp_state->s2t_file->pop();
                    if (new_packet->msg_type == SOCK_INSTRUCT){
                        delete(new_packet);
                        tcp_close(tcp_state, 1);
                        return;
                    }
                    else{
                        int len = *(int*)new_packet->content;
                        void* buf = (void*)(new_packet->content) + 4;
                        tcp_send_packet(tcp_state, buf, len);
                        delete(new_packet);
                    }
                }
            }

            if ((get_time() - latest_timestamp) / 1000000 > TCP_CLOSED_TIMEOUT){
                fprintf(log_stream, "[TCP]: Timeout reached. Closing TCP connection\n");
                fflush(log_stream);
                tcp_close(tcp_state, 0);
                return;
            }

            tcp_state->lock->unlock();

            nanosleep(&pause_time, _);
        }
    }
}