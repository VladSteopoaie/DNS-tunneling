#include "connectsock.h"

#define LISTEN_BACKLOG 128

int str_to_sock_type(const char* str)
{
    if (!strcmp(str, "tcp"))
        return SOCK_STREAM;
    else if (!strcmp(str, "udp"))
        return SOCK_DGRAM;  
    else{
        return -1;
    }
}

int set_socket_timeout(int socket, int _timeout)
{
	struct timeval timeout;
	timeout.tv_sec = _timeout;
	timeout.tv_usec = 0;

	if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
	{
		// std::cerr << "Error setting receive timeout: " << strerror(errno) << std::endl;
        return -1;
    }

	if (setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
	{
		// std::cerr << "Error setting send timeout: " << strerror(errno) << std::endl;
        return -1;
    }

    return 0;
}


int connect_sock(const char *host, const char *service, const char *transport)
{
    // declarations
    int socktype, ret_code, sock;
    struct addrinfo hints;
    struct addrinfo *result, *res_elem;

    if ((socktype = str_to_sock_type(transport)) < 0)
    {
        fprintf(stderr, "Transport protocol not supported!\n");
        return -1;
    }
    
    // initializing hints
    bzero(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = socktype;
    hints.ai_flags = 0;
    hints.ai_protocol = 0; // any protocol

    // get needed credentials
    ret_code = getaddrinfo(host, service, &hints, &result);
    if (ret_code != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret_code));
        return -1;
    }


    // go through the result and select the first socket
    for(res_elem = result; res_elem != NULL; res_elem = res_elem->ai_next)
    {
        sock = socket(res_elem->ai_family, res_elem->ai_socktype, res_elem->ai_protocol);

        if (sock == -1)
            continue;

        if (socktype == SOCK_DGRAM) // if transport is udp -> dosen't need to connect
            break;

        if (connect(sock, res_elem->ai_addr, res_elem->ai_addrlen) == 0)
            break;

        close(sock);
    }

    // free space
    freeaddrinfo(result);

    // verify connection
    if (res_elem == NULL)
    {
        fprintf(stderr, "Could not connect!\n");
        return -1;
    }

    return sock;

}


int connect_sock_tcp(const char* host, const char* service)
{
    return connect_sock(host, service, "tcp");
}

int connect_sock_udp(const char* host, const char* service)
{
    return connect_sock(host, service, "udp");
}


int passive_sock(const char *service, const char *transport)
{
    // declarations
    int socktype, sock, ret_code;
    struct addrinfo hints;
    struct addrinfo *result, *res_elem;

    if ((socktype = str_to_sock_type(transport)) < 0)
    {
        fprintf(stderr, "Transport protocol not supported!\n");
        return -1;
    }
    
    // initializing hints
    bzero(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = socktype;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    // get needed credentials
    ret_code = getaddrinfo(NULL, service, &hints, &result);
    if (ret_code != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret_code));
        return -1;
    }

    // go through the result and select the first socket
    for(res_elem = result; res_elem != NULL; res_elem = res_elem->ai_next)
    {
        sock = socket(res_elem->ai_family, res_elem->ai_socktype, res_elem->ai_protocol);

        if (sock == -1)
            continue;

        // reuse the port if opened earlier (sometimes it's needed to wait to reuse a port, this solves that)
        int reuse = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) == -1) {
            perror("setsockopt");
            close(sock);
            return -1;
        }

        if (bind(sock, res_elem->ai_addr, res_elem->ai_addrlen) == 0)
            break;

        close(sock);
    }

    freeaddrinfo(result);

    // verify result
    if (res_elem == NULL)
    {
        fprintf(stderr, "Could not bind!\n");
        return -1;
    }

    if (socktype == SOCK_STREAM){ // if transport = udp -> doesn't need to listen
        if (listen(sock, LISTEN_BACKLOG) < 0)
        {
            perror("listen");
            return -1;
        }
    }

    return sock;

}

int passive_sock_tcp(const char* service)
{
    return passive_sock(service, "tcp");
}

int passive_sock_udp(const char* service)
{
    return passive_sock(service, "udp");
}