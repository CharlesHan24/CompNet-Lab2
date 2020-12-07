#ifndef _SOCKET_H
#define _SOCKET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "common.h"
#include <stdint.h>
#include <queue>
#include "kernel.h"
#include "tcp.h"

namespace Wrap_Socket{
    using std::mutex;
    using std::queue;
    using TCP_lyr::socket_file_t;
    using TCP_lyr::tcp_ctx_t;

    
    /**
     * Contexts of a socket file
     */
    struct wrap_socket_t{
        int socket_fd;
        int listen_fd;

        tcp_ctx_t* tcp_state;

        mutex* lock; // shared lock 

        queue<socket_file_t*>* s2t_file;
        queue<socket_file_t*>* t2s_file;
    };

    /**
     * @see [POSIX.1-2017:socket](http://pubs.opengroup.org/onlinepubs/
     * 9699919799/functions/socket.html)
     */
    int __wrap_socket(int domain, int type, int protocol);

    /**
     * @see [POSIX.1-2017:bind](http://pubs.opengroup.org/onlinepubs/
     * 9699919799/functions/bind.html)
     */
    int __wrap_bind(int socket, const struct sockaddr *address, socklen_t address_len);

    /**
     * @see [POSIX.1-2017:listen](http://pubs.opengroup.org/onlinepubs/
     * 9699919799/functions/listen.html)
     */
    int __wrap_listen(int socket, int backlog);

    /**
     * @see [POSIX.1-2017:connect](http://pubs.opengroup.org/onlinepubs/
     * 9699919799/functions/connect.html)
     */
    int __wrap_connect(int socket, const struct sockaddr *address, socklen_t address_len);

    /**
     * @see [POSIX.1-2017:accept](http://pubs.opengroup.org/onlinepubs/
     * 9699919799/functions/accept.html)
     */
    int __wrap_accept(int socket, struct sockaddr *address, socklen_t *address_len);

    /**
     * @see [POSIX.1-2017:read](http://pubs.opengroup.org/onlinepubs/
     * 9699919799/functions/read.html)
     */
    ssize_t __wrap_read(int fildes, void *buf, size_t nbyte);

    /**
     * @see [POSIX.1-2017:write](http://pubs.opengroup.org/onlinepubs/
     * 9699919799/functions/write.html)
     */
    ssize_t __wrap_write(int fildes, const void *buf, size_t nbyte);

    /**
     * @see [POSIX.1-2017:close](http://pubs.opengroup.org/onlinepubs/
     * 9699919799/functions/close.html)
     */
    int __wrap_close(int fildes);

    /** 
     * @see [POSIX.1-2017:getaddrinfo](http://pubs.opengroup.org/onlinepubs/
     * 9699919799/functions/getaddrinfo.html)
     */
    int __wrap_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
}

#endif