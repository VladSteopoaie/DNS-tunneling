#ifndef CONNECTSOCK_H
#define CONNECTSOCK_H

#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

/**
    @brief Converts a string into an integer that can be used
        for socket() in the socktype attribute.

    @param str Only "tcp" and "udp" are accepted.

    @return SOCK_STREAM, SOCK_DGRAM on success if tcp or udp is provided as 
        argument and -1 on error and a message is printed on stderr.
*/
int str_to_sock_type(const char* str);

/**
    @brief Set a timeout for a socket when listening for connections.

    @param socket the socket to set the timeout
    @param timeout the time specified in seconds

    @return 0 on success, -1 on failure.
*/
int set_socket_timeout(int socket, int timeout);

/**
    @brief Clears a socket's timeout.

    @param socket the socket to set the timeout

    @return 0 on success, -1 on failure.
*/
int clear_socket_timeout(int socket);

/**
    @brief Creates a connection socket of type 'transport', using 
        'host' and 'service' as address and port.

    @param host IP address or "localhost".
    @param service Name or port number.
    @param transport Transport protocol, "udp" and "tcp" are accepted.

    @return A socket file descriptor connected to the 'host' on success 
        and -1 on error.
*/
int connect_sock(const char *host, const char *service, const char *transport);


/**
    @brief Creates a listening socket of type 'transport', using
        'host' and 'service' as address and port.

    @param service Name or port number.
    @param transport Transport protocol, "udp" and "tcp" are accepted.

    @return A socket file descriptor that listens on port 'service' on success
        and -1 on error.
*/
int passive_sock(const char *service, const char *transport);

/*
    Function wrappers
*/

int connect_sock_tcp(const char* host, const char* service);
int connect_sock_udp(const char* host, const char* service);

int passive_sock_tcp(const char* service);
int passive_sock_udp(const char* service);

#endif