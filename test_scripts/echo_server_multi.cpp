#include <cstdio>
#include <kernel.h>
#include <socket.h>
#include <tcp.h>
#include <ip.h>
#include <packetio.h>
#include <device.h>
#include <unistd.h>
#include <cstring>
#include <thread>
using namespace std;

Kernel::kernel_t core;
FILE* log_stream;


void server_loop(uint16_t port){

    sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(sockaddr_in));
    local_addr.sin_port = port;
    memcpy(&local_addr.sin_addr, &core.devices[0]->ipv4_addr[0], sizeof(ipv4_addr_t));
    local_addr.sin_family = AF_INET;

    int socket_fd = Wrap_Socket::__wrap_socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1){
        printf("Error: Failed to create a socket\n");
        return;
    }

    int ret;
    ret = Wrap_Socket::__wrap_bind(socket_fd, (sockaddr*)&local_addr, sizeof(sockaddr_in));

    if (ret < 0){
        printf("Error: Failed to bind\n");
        return;
    }

    while (1){
        printf("(Re)start listening\n");
        ret = Wrap_Socket::__wrap_listen(socket_fd, 0);
        if (ret < 0){
            printf("Error: Failed to launch listen() at socket %d\n", socket_fd);
            return;
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
        int read_len = 0;
        while (read_len < 7){
            ret = Wrap_Socket::__wrap_read(socket_fd, read_buf, 7 - read_len);
            if (ret < 0){
                printf("Error: Failed to read from socket %d\n", socket_fd);
                return;
            }
            read_len += ret;
            read_buf += ret;
        }

        fflush(log_stream);

        read_buf -= 7;

        printf("Received a packet. Its contents are: %s\n", read_buf);

        ret = Wrap_Socket::__wrap_write(socket_fd, read_buf, 7);
        if (ret < 0){
            printf("Error: Failed to write to socket %d\n", socket_fd);
            return;
        }

        fflush(log_stream);
        sleep(40);
    }
    Wrap_Socket::__wrap_close(socket_fd);
}


int main(int argc, char* argv[]){
    srand(time(NULL));

    if (argc < 4){
        printf("Usage: ./echo_server LOG_FILE_NAME DEV1 Port_1 Port2 ...\n");
        return 0;
    }

    log_stream = fopen(argv[1], "w");
    Packet_IO::setFrameReceiveCallback(Packet_IO::default_eth_rcv_callback);
    ARP_lyr::set_arp_callback(ARP_lyr::default_arp_rcv_callback);
    IP_lyr::setIPPacketReceiveCallback(IP_lyr::default_ip_rcv_callback);
    core.tcp_cb = TCP_lyr::default_tcp_rcv_callback;

    Device::addDevice(argv[2]);

    uint16_t port;

    for (int i = 3; i < argc; i++){
        printf("%d\n", i);
        
        sscanf(argv[i], "%hu", &port);
        thread server_thread(server_loop, port);
        server_thread.detach();
    }

    sleep(1500);
    return 0;
}