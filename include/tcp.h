#ifndef _TCP_H
#define _TCP_H

#include "common.h"
#include <sys/socket.h>
#include <mutex>
#include <queue>


#define AVAIL_PORT_SHIFT 12345
#define MAX_CONNECT_CNT 64
#define MAX_PAYLOAD_PER_PACK 1000
#define SOCKET_FD_SHIFT 65536

namespace TCP_lyr{
    using std::mutex;
    using std::queue;

    enum ts_msg_type{ // tcp-socket message type
        TCP_NML_PACKET,  // TCP Normal Packet to be transmitted or consumed by socket read
        TCP_ACC_MSG,   // TCP to Socket message indicating that server has accepted a client
        SOCK_INSTRUCT, // close instruction
    };

    /**
     *  Message file between the socket and the TCP main loop. 
     *  The socket and the TCP exchange files and do synchonization through these message files.
     */
    struct socket_file_t{
        enum ts_msg_type msg_type;
        void* content;
        ~socket_file_t(){
            delete(content);
        }
    };
    
    /**
     *  TCP state machine status code. 
     */
    enum state_code_t{
        TCP_CLOSED,
        TCP_LISTEN,
        TCP_SYN_SENT,
        TCP_SYN_RCVD,
        TCP_ESTAB,

    };

    struct tcp_wait_t;

    /**
     *  Whole context of a TCP state machine. 
     */
    struct tcp_ctx_t{
        mutex* lock;
        sockaddr local_addr;
        socklen_t local_addr_len;
        sockaddr peer_addr;
        socklen_t peer_addr_len;

        ipv4_addr_t local_ipv4;
        uint16_t local_port;
        ipv4_addr_t peer_ipv4;
        uint16_t peer_port;

        enum state_code_t stat_code;

        tcp_wait_t* wait_item;           // Our TCP support retransmission by remembering the last transmitted item and by backing up TCP state machine.
        tcp_ctx_t* tcp_backup_state;

        queue<socket_file_t*>* s2t_file; // socket to TCP message
        queue<socket_file_t*>* t2s_file; // TCP to socket message

        uint32_t last_seq;
        uint32_t last_ack;
    };

    /**
     * Packets stored in TCP state machine for retransmission in case for packet loss.
     */
    struct tcp_wait_t{
        void* tcp_buf;
        ipv4_hdr_t* ipv4_header;
        int len;
        uint64_t timestamp;
        uint64_t initial_timestamp;

        tcp_wait_t (){
            tcp_buf = NULL;
            ipv4_header = NULL;
        }

        ~tcp_wait_t(){
            delete(tcp_buf);
            delete(ipv4_header);
        }
    };

    /**
     *  TCP layer initialization.
     */ 
    int init();


    /**
     *  Initialization of a TCP state machine. 
     */
    int tcp_init(tcp_ctx_t* tcp_state, mutex* lock, queue<socket_file_t*>* t2s_file, queue<socket_file_t*>* s2t_file);


    /**
     *  Binding address to the TCP state machine.
     *  @param who: 0: local address, 1: peer address
     */
    int tcp_set_addr(tcp_ctx_t* tcp_state, sockaddr* address, socklen_t peer_addr_len, int who);


    /**
     *  The server launches TCP main loop and starts listening to connect with client.
     */
    int tcp_launch_listen(tcp_ctx_t* tcp_state, int sock_fd);


    /**
     *  The client launches TCP main loop and seeks to connect to the server. 
     */
    int tcp_launch_connect(tcp_ctx_t* tcp_state, int sock_fd);

    /**
     *  Stopping all the threads and freeing all the TCP state machines when exiting. 
     */
    void exiting();

    /**
     *  Close the TCP connection and reset the TCP state machine.
     */
    void tcp_close(tcp_ctx_t* tcp_state, int mode);


    typedef int (*TCP_packet_receive_callback)(const void* buf, int len, const ipv4_hdr_t* ip_header);

    /**
     *  Default TCP callback function on receiving a TCP packet. 
     */
    int default_tcp_rcv_callback(const void* buf, int len, const ipv4_hdr_t* ip_header);

    /**
     * TCP main loop. It repeatedly check for current TCP status for retransmission, 
     * and it accepts commands from the socket to send a new data packet / close the connection.
     */
    void tcp_main_loop(tcp_ctx_t* tcp_state);
}

#endif