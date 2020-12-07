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
    if (argc != 6){
        printf("Usage: ./echo_client LOG_FILE_NAME IP_DST PORT_DST DEV1 STRING\n");
        return 0;
    }

    log_stream = fopen(argv[1], "w");
    Packet_IO::setFrameReceiveCallback(Packet_IO::default_eth_rcv_callback);
    ARP_lyr::set_arp_callback(ARP_lyr::default_arp_rcv_callback);
    IP_lyr::setIPPacketReceiveCallback(IP_lyr::default_ip_rcv_callback);
    core.tcp_cb = TCP_lyr::default_tcp_rcv_callback;

    ipv4_addr_t dst_addr;
    sscanf(argv[2], "%d.%d.%d.%d", &dst_addr.addr[0], &dst_addr.addr[1], &dst_addr.addr[2], &dst_addr.addr[3]);

    uint16_t dst_port;
    sscanf(argv[3], "%u", &dst_port);

    sockaddr_in dst_sock;
    memset(&dst_sock, 0, sizeof(sockaddr_in));
    dst_sock.sin_family = AF_INET;
    dst_sock.sin_port = dst_port;
    memcpy(&dst_sock.sin_addr, &dst_addr, sizeof(ipv4_addr_t));

    Device::addDevice(argv[4]);

    char buf[100], stored_buf[100];
    sprintf(buf, "%d\n%s", strlen(argv[5]), argv[5]);
    int pac_len = strlen(buf);

    printf("%s\n", buf);

    memcpy(stored_buf, buf, pac_len);

    int socket_fd = Wrap_Socket::__wrap_socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1){
        printf("Error: Failed to create a socket\n");
        return 0;
    }

    int ret;
    ret = Wrap_Socket::__wrap_connect(socket_fd, (sockaddr*)&dst_sock, sizeof(sockaddr_in));

    if (ret < 0){
        printf("Error: Failed to connect\n");
        return 0;
    }

    printf("Connection established\n");

    fflush(log_stream);

    ret = Wrap_Socket::__wrap_write(socket_fd, buf, pac_len);
    if (ret < 0){
        printf("Error: Failed to write to socket %d\n", socket_fd);
        return 0;
    }

    fflush(log_stream);
    
    char* read_buf = new char[100];
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

    read_buf -= pac_len;
    if (memcmp(read_buf, stored_buf, pac_len) == 0){
        printf("Test_Passed\n");
    }
    else{
        printf("Test Failed: incorrect response\n");
        printf("Response is: ");
        for (int i = 0; i < pac_len; i++){
            printf("%d ", read_buf[i]);
        }
        printf("\n");
    }

    return 0;
}