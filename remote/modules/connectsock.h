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
int StrToSocktype(const char* str);

/**
    @brief Creates a connection socket of type 'transport', using 
        'host' and 'service' as address and port.

    @param host IP address or "localhost".
    @param service Name or port number.
    @param transport Transport protocol, "udp" and "tcp" are accepted.

    @return A socket file descriptor connected to the 'host' on success 
        and -1 on error.
*/
int ConnectSock(const char *host, const char *service, const char *transport);


/**
    @brief Creates a listening socket of type 'transport', using
        'host' and 'service' as address and port.

    @param service Name or port number.
    @param transport Transport protocol, "udp" and "tcp" are accepted.

    @return A socket file descriptor that listens on port 'service' on success
        and -1 on error.
*/
int PassiveSock(const char *service, const char *transport);

/*
    Function wrappers
*/

int ConnectSockTCP(const char* host, const char* service);
int ConnectSockUDP(const char* host, const char* service);

int PassiveSockTCP(const char* service);
int PassiveSockUDP(const char* service);

#endif