#include "socket.h"
#include "common.h"
#include "ip.h"
#include "kernel.h"
#include "tcp.h"
#include <sys/socket.h>
#include <cstring>
#include <cstdlib>
#include <unistd.h>

extern FILE* log_stream;
extern Kernel::kernel_t core;

#define MAX_SOCKET_CNT 64
#define SOCK_WAIT_TIMEOUT 1000000

namespace Wrap_Socket{
    
    
    using std::min;
    using TCP_lyr::SOCK_INSTRUCT;
    using TCP_lyr::TCP_NML_PACKET;
    using TCP_lyr::TCP_ACC_MSG;
    using TCP_lyr::TCP_CLOSED;
    using TCP_lyr::tcp_init;
    using TCP_lyr::socket_file_t;
    using TCP_lyr::ts_msg_type;
    using TCP_lyr::state_code_t;
    using TCP_lyr::tcp_ctx_t;
    using TCP_lyr::tcp_set_addr;
    using std::mutex;
    using std::queue;

    static wrap_socket_t* glb_sock_ctx[MAX_SOCKET_CNT];
    static const timespec pause_time = (timespec){.tv_sec = 0, .tv_nsec = 10000};
    static int glb_sock_fd = 0;

    static mutex glb_sock_lock;


    static int sock_wait_msg(wrap_socket_t* socket, int len, void* buf, int mode){
        uint64_t start_time = get_time();
        int ret = 0;
        while (1){
            uint64_t cur_time = get_time();
            if ((cur_time - start_time) / 1000000 > SOCK_WAIT_TIMEOUT){
                fprintf(log_stream, "[Error]: Socket: No response after timeout\n");
                return -1;
            }
            if (core.quit_flag){
                return -1;
            }
            if (socket->tcp_state->stat_code == TCP_CLOSED){
                return -1;
            }

            int flag = 0;
            socket->lock->lock();
            if (mode == 0){
                if (!socket->t2s_file->empty()){
                    flag = 1;
                    socket_file_t* cur_msg = socket->t2s_file->front();
                    socket->t2s_file->pop();

                    if (cur_msg->msg_type != TCP_ACC_MSG){
                        fprintf(log_stream, "[Error]: Socket: Receiving a strange response packet\n");
                        ret = -1;
                    }
                    else{
                        ret = 0;
                    }
                    delete(cur_msg);
                }
            }
            else{
                while (!socket->t2s_file->empty()){
                    socket_file_t* cur_msg = socket->t2s_file->front();
                
                    if (cur_msg->msg_type != TCP_NML_PACKET){
                        delete(cur_msg);
                        socket->t2s_file->pop();
                        continue;
                    }
                    
                    flag = 1;
                    void* content = cur_msg->content;
                    int cur_len = *(int*)content;

                    if (len < cur_len){
                        char tmp_buf[cur_len];
                        memcpy(tmp_buf, content + 4, cur_len);
                        memcpy(content + 4, tmp_buf + len, cur_len - len);
                        *(int*)content = cur_len - len;

                        memcpy(buf, tmp_buf, len);
                        ret += len;
                        len = 0;
                    }

                    else{
                        memcpy(buf, content + 4, cur_len);
                        buf = buf + cur_len;
                        ret += cur_len;
                        len -= cur_len;

                        socket->t2s_file->pop();
                        delete(cur_msg);
                    }
                    if (len == 0){
                        break;
                    }
                }
            }
            socket->lock->unlock();
            if (ret == -1){
                return -1;
            }
            if (flag == 1){
                break;
            }

            timespec* _;
            nanosleep(&pause_time, _);
        }
        return ret;
    }

    static wrap_socket_t* _new_sock(int alloc_fd){
        wrap_socket_t* cur_sock = new wrap_socket_t;

        cur_sock->listen_fd = -1;
        cur_sock->socket_fd = alloc_fd;
        cur_sock->lock = new mutex;
        cur_sock->lock->unlock();
        cur_sock->tcp_state = new tcp_ctx_t;

        cur_sock->t2s_file = new queue<socket_file_t*>;
        cur_sock->s2t_file = new queue<socket_file_t*>;

        return cur_sock;
    }

    int __wrap_socket(int domain, int type, int protocol){
        glb_sock_lock.lock();

        if ((domain != AF_INET) || (type != SOCK_STREAM) || (protocol != 0)){
            fprintf(log_stream, "[Error]: Socket: Failed to create a socket with parameter (%d, %d, %d)\n", domain, type, protocol);
            glb_sock_lock.unlock();
            return -1;
        }

        int old_glb_sock_fd = glb_sock_fd, new_sock_fd = -1;
        for (int i = glb_sock_fd; (i + 1) % MAX_SOCKET_CNT != old_glb_sock_fd; i = (i + 1) % MAX_SOCKET_CNT){
            if (glb_sock_ctx[i] == NULL){
                new_sock_fd = i;
                break;
            }
        }
        if (new_sock_fd == -1){
            fprintf(log_stream, "[Error]: Socket: no more socket is available to be allocated\n");
            glb_sock_lock.unlock();
            return -1;
        }
        
        glb_sock_ctx[new_sock_fd] = _new_sock(new_sock_fd + SOCKET_FD_SHIFT);
        glb_sock_fd = (new_sock_fd + 1) % MAX_SOCKET_CNT;

        glb_sock_lock.unlock();

        return new_sock_fd + SOCKET_FD_SHIFT;
    }

    int __wrap_bind(int socket, const struct sockaddr *address,
    socklen_t address_len){
        if ((socket - SOCKET_FD_SHIFT < 0) || (socket - SOCKET_FD_SHIFT >= MAX_SOCKET_CNT)){
            // fall back
            return bind(socket, address, address_len);
        }

        int cur_sock_fd = socket - SOCKET_FD_SHIFT;
        
        if (address->sa_family != AF_INET){
            fprintf(log_stream, "[Error]: Socket: Failed to bind at socket %d because the input sa_family is not supported\n", socket);
            return -1;
        }

        wrap_socket_t* cur_sock_inst = glb_sock_ctx[cur_sock_fd];
        if (cur_sock_inst == NULL){
            fprintf(log_stream, "[Error]: Failed to find socket %d\n", cur_sock_fd);
            return -1;
        }
        cur_sock_inst->lock->lock();

        int ret = tcp_set_addr(cur_sock_inst->tcp_state, (sockaddr*)address, address_len, 0);
        cur_sock_inst->lock->unlock();

        return ret;
    }

    int __wrap_listen(int socket, int backlog){ // ignore backlog
        if ((socket - SOCKET_FD_SHIFT < 0) || (socket - SOCKET_FD_SHIFT >= MAX_SOCKET_CNT)){
            // fall back
            return listen(socket, backlog);
        }

        int cur_sock_fd = socket - SOCKET_FD_SHIFT;
        wrap_socket_t* cur_sock_inst = glb_sock_ctx[cur_sock_fd];
        if (cur_sock_inst == NULL){
            fprintf(log_stream, "[Error]: Failed to find socket %d\n", cur_sock_fd);
            return -1;
        }

        cur_sock_inst->lock->lock();

        cur_sock_inst->listen_fd = cur_sock_fd;

        tcp_init(cur_sock_inst->tcp_state, cur_sock_inst->lock, cur_sock_inst->t2s_file, cur_sock_inst->s2t_file);

        cur_sock_inst->lock->unlock();

        int ret = tcp_launch_listen(cur_sock_inst->tcp_state, socket);
        return ret;
    }

    int __wrap_connect(int socket, const struct sockaddr *address, socklen_t address_len){
        if ((socket - SOCKET_FD_SHIFT < 0) || (socket - SOCKET_FD_SHIFT >= MAX_SOCKET_CNT)){
            // fall back
            return connect(socket, address, address_len);
        }

        if (address->sa_family != AF_INET){
            fprintf(log_stream, "[Error]: Socket: Failed to connect in socket %d because the peer address's sa_family is not supported\n", socket);
            return -1;
        }

        int cur_sock_fd = socket - SOCKET_FD_SHIFT;
        int ret;
        wrap_socket_t* cur_sock_inst = glb_sock_ctx[cur_sock_fd];
        if (cur_sock_inst == NULL){
            fprintf(log_stream, "[Error]: Failed to find socket %d\n", cur_sock_fd);
            return -1;
        }

        cur_sock_inst->lock->lock();

        ret = tcp_set_addr(cur_sock_inst->tcp_state, (sockaddr*)address, address_len, 1);
        if (ret < 0){
            cur_sock_inst->lock->unlock();
            return ret;
        }
        
        uint16_t self_port = AVAIL_PORT_SHIFT + cur_sock_fd;
        sockaddr_in self_addr;
        memset(&self_addr, 0, sizeof(self_addr));
        self_addr.sin_addr = *(in_addr*)&core.devices[0]->ipv4_addr[0];
        self_addr.sin_port = self_port;
        self_addr.sin_family = AF_INET;

        ret = tcp_set_addr(cur_sock_inst->tcp_state, (sockaddr*)&self_addr, sizeof(sockaddr_in), 0);
        if (ret < 0){
            cur_sock_inst->lock->unlock();
            return ret;
        }

        tcp_init(cur_sock_inst->tcp_state, cur_sock_inst->lock, cur_sock_inst->t2s_file, cur_sock_inst->s2t_file);

        cur_sock_inst->lock->unlock();
        ret = tcp_launch_connect(cur_sock_inst->tcp_state, socket);
        
        if (ret == -1){
            return -1;
        }

        if (sock_wait_msg(cur_sock_inst, 0, NULL, 0) == -1){
            return -1;
        }
        return 0;
    }

    int __wrap_accept(int socket, struct sockaddr *address, socklen_t *address_len){
        if ((socket - SOCKET_FD_SHIFT < 0) || (socket - SOCKET_FD_SHIFT >= MAX_SOCKET_CNT)){
            // fall back
            return accept(socket, address, address_len);
        }

        int cur_sock_fd = socket - SOCKET_FD_SHIFT;
        wrap_socket_t* cur_sock_inst = glb_sock_ctx[cur_sock_fd];
        if (cur_sock_inst == NULL){
            fprintf(log_stream, "[Error]: Failed to find socket %d\n", cur_sock_fd);
            return -1;
        }

        if (sock_wait_msg(cur_sock_inst, 0, NULL, 0) == -1){
            return -1;
        }

        cur_sock_inst->lock->lock();
        *address_len = sizeof(sockaddr_in);
        memset(address, 0, *address_len);
        memcpy(&((sockaddr_in*)address)->sin_addr, &cur_sock_inst->tcp_state->peer_ipv4, sizeof(ipv4_addr_t));
        ((sockaddr_in*)address)->sin_family = AF_INET;
        ((sockaddr_in*)address)->sin_port = cur_sock_inst->tcp_state->peer_port;
        cur_sock_inst->lock->unlock();

        return socket;
    }

    ssize_t __wrap_read(int fildes, void *buf, size_t nbyte){
        int socket = fildes;
        if ((socket - SOCKET_FD_SHIFT < 0) || (socket - SOCKET_FD_SHIFT >= MAX_SOCKET_CNT)){
            // fall back
            return read(socket, buf, nbyte);
        }

        int cur_sock_fd = socket - SOCKET_FD_SHIFT;
        wrap_socket_t* cur_sock_inst = glb_sock_ctx[cur_sock_fd];
        if (cur_sock_inst == NULL){
            fprintf(log_stream, "[Error]: Failed to find socket %d\n", cur_sock_fd);
            return -1;
        }

        return sock_wait_msg(cur_sock_inst, nbyte, buf, 1);
    }

    ssize_t __wrap_write(int fildes, const void *buf, size_t nbyte){
        int socket = fildes;
        if ((socket - SOCKET_FD_SHIFT < 0) || (socket - SOCKET_FD_SHIFT >= MAX_SOCKET_CNT)){
            // fall back
            return write(socket, (void*)buf, nbyte);
        }

        int cur_sock_fd = socket - SOCKET_FD_SHIFT;
        wrap_socket_t* cur_sock_inst = glb_sock_ctx[cur_sock_fd];
        if (cur_sock_inst == NULL){
            fprintf(log_stream, "[Error]: Failed to find socket %d\n", cur_sock_fd);
            return -1;
        }

        cur_sock_inst->lock->lock();

        if (cur_sock_inst->tcp_state->stat_code == TCP_CLOSED){
            cur_sock_inst->lock->unlock();
            return -1;
        }

        while (nbyte){
            socket_file_t* new_packet = new socket_file_t;
            
            new_packet->msg_type = TCP_NML_PACKET;

            int cur_len = min((int)nbyte, MAX_PAYLOAD_PER_PACK);
            new_packet->content = new char[cur_len + 4];

            *(int*)new_packet->content = cur_len;
            memcpy(new_packet->content + 4, buf, cur_len);

            cur_sock_inst->s2t_file->push(new_packet);

            buf = buf + cur_len;
            nbyte -= cur_len;
        }

        cur_sock_inst->lock->unlock();

        return 0;
    }

    int __wrap_getaddrinfo(const char *node, const char *service,
        const struct addrinfo *hints, struct addrinfo **res){
        
        if ((node == NULL) || (service == NULL) || (hints->ai_flags != 0) || (hints->ai_family != AF_INET) || (hints->ai_socktype != IPPROTO_TCP)){
            return -1;
        }

        *res = new addrinfo;

        memcpy(*res, hints, sizeof(addrinfo));
        (*res)->ai_next = NULL;

        sockaddr_in* addr_res = (sockaddr_in*)&((*res)->ai_addr);

        sscanf(node, "%u.%u.%u.%u", (char*)(&addr_res->sin_addr), (char*)(&addr_res->sin_addr) + 1, (char*)(&addr_res->sin_addr) + 2, (char*)(&addr_res->sin_addr) + 3);
        addr_res->sin_family = AF_INET;
        sscanf(node, "%hu", addr_res->sin_port);
        memset(&addr_res->sin_zero, 0, sizeof(addr_res->sin_zero));

        (*res)->ai_addrlen = sizeof(sockaddr_in);
        
        return 0;
    }

    int __wrap_close(int socket){
        if ((socket - SOCKET_FD_SHIFT < 0) || (socket - SOCKET_FD_SHIFT >= MAX_SOCKET_CNT)){
            // fall back
            return close(socket);
        }

        int cur_sock_fd = socket - SOCKET_FD_SHIFT;;
        wrap_socket_t* cur_sock_inst = glb_sock_ctx[cur_sock_fd];
        if (cur_sock_inst == NULL){
            fprintf(log_stream, "[Error]: Failed to find socket %d\n", cur_sock_fd);
            return -1;
        }

        cur_sock_inst->lock->lock();

        socket_file_t* new_msg = new socket_file_t;
        new_msg->msg_type = SOCK_INSTRUCT;
        new_msg->content = NULL;

        cur_sock_inst->s2t_file->push(new_msg);
        cur_sock_inst->lock->unlock();

        delete(glb_sock_ctx[cur_sock_fd]);
        glb_sock_ctx[cur_sock_fd] = NULL;
        return 0;
    }
}