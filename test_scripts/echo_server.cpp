#include <cstdio>
#include <kernel.h>
#include <socket.h>
#include <tcp.h>
#include <ip.h>
#include <packetio.h>
#include <device.h>
#include <unistd.h>
#include <cstring>
using namespace std;

Kernel::kernel_t core;
FILE* log_stream;

int main(int argc, char* argv[]){
    srand(time(NULL));

    if (argc != 3){
        printf("Usage: ./echo_server LOG_FILE_NAME DEV1\n");
        return 0;
    }

    log_stream = fopen(argv[1], "w");
    Packet_IO::setFrameReceiveCallback(Packet_IO::default_eth_rcv_callback);
    ARP_lyr::set_arp_callback(ARP_lyr::default_arp_rcv_callback);
    IP_lyr::setIPPacketReceiveCallback(IP_lyr::default_ip_rcv_callback);
    core.tcp_cb = TCP_lyr::default_tcp_rcv_callback;

    Device::addDevice(argv[2]);

    sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(sockaddr_in));
    local_addr.sin_port = 80;
    memcpy(&local_addr.sin_addr, &core.devices[0]->ipv4_addr[0], sizeof(ipv4_addr_t));
    local_addr.sin_family = AF_INET;

    int socket_fd = Wrap_Socket::__wrap_socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1){
        printf("Error: Failed to create a socket\n");
        return 0;
    }

    int ret;
    ret = Wrap_Socket::__wrap_bind(socket_fd, (sockaddr*)&local_addr, sizeof(sockaddr_in));

    if (ret < 0){
        printf("Error: Failed to bind\n");
        return 0;
    }

    while (1){
        printf("(Re)start listening\n");
        ret = Wrap_Socket::__wrap_listen(socket_fd, 0);
        if (ret < 0){
            printf("Error: Failed to launch listen() at socket %d\n", socket_fd);
            return 0;
        }

        sockaddr_in peer_addr;
        int _len;

        fflush(log_stream);

        printf("Prepared to accept\n");
        ret = Wrap_Socket::__wrap_accept(socket_fd, (sockaddr*)&peer_addr, (socklen_t*)&_len);
        if (ret < 0){
            printf("Warning: No accepting connection found\n");
            sleep(1);
            continue;
        }

        fflush(log_stream);

        printf("Connection established\n");

        char display[100];
        gen_ipv4_str((u_char*)&peer_addr.sin_addr, display);
        printf("Peer address: %s, Peer port %d\n", display, peer_addr.sin_port);

        char* read_buf = new char[100];
        memset(read_buf, 0, 100);

        int pac_len = 0, num_len = 0;
        while (true){
            ret = Wrap_Socket::__wrap_read(socket_fd, read_buf + num_len, 1);
            if (read_buf[num_len] == '\n'){
                num_len++;
                break;
            }
            else{
                pac_len = pac_len * 10 + read_buf[num_len] - '0';
                num_len++;
            }
        }
        read_buf += num_len;

        int read_len = 0;
        while (read_len < pac_len){
            ret = Wrap_Socket::__wrap_read(socket_fd, read_buf, pac_len - read_len);
            if (ret < 0){
                printf("Error: Failed to read from socket %d\n", socket_fd);
                return 0;
            }
            read_len += ret;
            read_buf += ret;
        }

        fflush(log_stream);

        read_buf -= pac_len + num_len;

        printf("Received a packet. Its contents are: %s\n", read_buf);

        ret = Wrap_Socket::__wrap_write(socket_fd, read_buf, pac_len + num_len);
        if (ret < 0){
            printf("Error: Failed to write to socket %d\n", socket_fd);
            return 0;
        }

        fflush(log_stream);
        sleep(40);
        delete(read_buf);
    }
    Wrap_Socket::__wrap_close(socket_fd);
    return 0;
}