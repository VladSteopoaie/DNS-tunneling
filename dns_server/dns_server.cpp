#include "./modules/dns_module.h"
#include "./modules/connectsock.h"
#include <cstddef>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <fstream>

const char* RECORD_FILE = "./modules/dns_records.txt";


// Function to set a timeout on a socket
void setSocketTimeout(int socket, int timeoutSeconds)
{
	struct timeval timeout;
	timeout.tv_sec = timeoutSeconds;
	timeout.tv_usec = 0;

	if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
	{
		std::cerr << "Error setting receive timeout: " << strerror(errno) << std::endl;
	}

	if (setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
	{
		std::cerr << "Error setting send timeout: " << strerror(errno) << std::endl;
	}
}

std::vector<DNSRecord> records_from_file(char* file)
{
    std::ifstream fin(file);
    if (!fin.is_open())
    {
        throw std::runtime_error("Could not open records file!")
    }

    

    fin.close();
}

// Performs a lookup on a local file to see if there are any names assigned
DnsPacket local_lookup(std::string qname, QueryType qtype)
{
    DnsPacket result;
    try{
        std::vector<DNSRecord> records = records_from_file(RECORD_FILE);
        std::vector<DNSRecord> result = search_in_records(qname, qtype, records);
    }
    catch (std::runtime_error e){
        std::cout << e.what << std::endl;
        result.header.rescode = ResultCode::NXDOMAIN;
        return result;
    }
}

// Sends a DNS question to the specified server 
DnsPacket lookup(std::string qname, QueryType qtype, const struct sockaddr_in& server_addr)
{
    int socket = PassiveSockUDP("43210"); // picking a random port to send the request
    setSocketTimeout(socket, 5);
    DnsPacket packet = DnsPacket();
    
    try{
        // crafting the header
        packet.header.id = 6666; // random id
        packet.header.questions = 1;
        packet.header.recursion_desired = true;

        // crafting the body
        packet.questions.push_back(DnsQuestion(qname, qtype));

        BytePacketBuffer req_buffer = BytePacketBuffer();
 
        packet.write(req_buffer);

        char req_bytes[req_buffer.getPos()];
        std::copy(req_buffer.buf.begin(), req_buffer.buf.end(), req_bytes);

        // sending the request
        ssize_t bytes_sent = sendto(socket, req_bytes, req_buffer.getPos(), 0, (struct sockaddr*) &server_addr, sizeof(server_addr));
        if (bytes_sent <= 0)
        {
            close(socket);
            throw std::runtime_error("Some error occurred when sending data!\n");
        }

        // receiving response
        char res_bytes[BytePacketBuffer::packetSize];
        ssize_t bytes_read = recv(socket, res_bytes, BytePacketBuffer::packetSize, 0); 
        if (bytes_read <= 0)
        {
            close(socket);
            throw std::runtime_error("Some error occurred when receiving data!\n");
        }

        BytePacketBuffer res_buffer = BytePacketBuffer(res_bytes, bytes_read);
        
        close(socket);
        return DnsPacket::from_buffer(res_buffer);

    }
    catch (std::runtime_error e)
    {
        close(socket);
        throw e;
    }
}

// Tries to resolve a domain name through recursive lookups
DnsPacket recursive_lookup(std::string qname, QueryType qtype)
{
    IPv4Addr ns = IPv4Addr("198.41.0.4"); // this is a.root-servers.net

    while (true)
    {
        std::cout << "Attepmpting lookup of " << QueryTypeFunc::to_string(qtype) << " " << qname << " with NS " << ns.to_string() << std::endl;

        IPv4Addr ns_copy = ns;

        struct sockaddr_in server_addr;
        std::memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(53);
        inet_pton(AF_INET, ns_copy.to_string().c_str(), &server_addr.sin_addr);

        DnsPacket response;
        try {
            // first perform a local lookup to see if there is a local domain assigned
            response = local_lookup(qname, qtype);

            if (response.header.rescode == ResultCode::NXDOMAIN) // no domain found locally
            {
                response = lookup(qname, qtype, server_addr);
            }
        }
        catch (std::runtime_error e)
        {
            throw e;
        }
        
        // success
        if (!response.answers.empty() && response.header.rescode == ResultCode::NOERROR)
            return response;

        // domain not found
        if (response.header.rescode == ResultCode::NXDOMAIN)
            return response;

        IPv4Addr new_ns = response.get_resolved_ns(qname);
        if (new_ns.to_string() != "0.0.0.0"){ // if the ip is 0.0.0.0 it means there are no entries
            ns = new_ns;
            continue;
        }
        
        std::vector<std::string> new_ns_names = response.get_unresolved_ns(qname);
        if (new_ns_names.empty())
            return response;

        // trying to get the ip of the unresolved ns
        DnsPacket recursive_response = recursive_lookup(new_ns_names.front(), QueryType::A);

        new_ns = recursive_response.get_random_a();

        if (new_ns.to_string() != "0.0.0.0") // if the ip is 0.0.0.0 it means there are no entries
            ns = new_ns;
        else 
            return response;
    }
}

void handle_query(int socket)
{
    // Variable definition
    struct sockaddr_storage source_addr;
    socklen_t source_addrlen = sizeof(source_addr);
    char req_bytes[BytePacketBuffer::packetSize];

    // Waiting for data
    ssize_t bytes_read = recvfrom(socket, req_bytes, BytePacketBuffer::packetSize, 0, (struct sockaddr*) &source_addr, &source_addrlen);
    if (bytes_read <= 0)
    {
        throw std::runtime_error("An error occured when receiving data! (handle_query)");
    }

    try
    {
        // Processing the data
        BytePacketBuffer req_buffer = BytePacketBuffer(req_bytes, (size_t) bytes_read);
        DnsPacket request = DnsPacket::from_buffer(req_buffer);

        DnsPacket packet;   
        packet.header.id = request.header.id;
        packet.header.recursion_desired = true;
        packet.header.recursion_available = true;
        packet.header.response = true;

        if (request.header.questions == 1 && request.questions.size() == 1)
        {
            DnsQuestion question = request.questions.front();
            std::cout << "Received query:\n" << question.to_string() << std::endl;

            DnsPacket result;
            try{
                // perform a recursive lookup
                result = recursive_lookup(question.name, question.qtype);
                packet.header.rescode = result.header.rescode;

            }
            catch(std::runtime_error e)
            {
                std::cout << e.what() << std::endl;
                packet.header.rescode = ResultCode::SERVFAIL;
            }

            packet.questions.push_back(question);

            std::cout << "Answer:\n";
            for (size_t i = 0; i < result.answers.size(); i ++)
            {
                std::cout << result.answers[i].to_string() << std::endl;
                packet.answers.push_back(result.answers[i]);
            }
            std::cout << "Authorities:\n";
            for (size_t i = 0; i < result.authorities.size(); i ++)
            {
                std::cout << result.authorities[i].to_string() << std::endl;
                packet.authorities.push_back(result.authorities[i]);
            }
            std::cout << "Resources:\n";
            for (size_t i = 0; i < result.resources.size(); i ++)
            {
                std::cout << result.resources[i].to_string() << std::endl;
                packet.resources.push_back(result.resources[i]);
            }
        }
        else{
            packet.header.rescode = ResultCode::FORMERR;
        }

        // Sending data back
        BytePacketBuffer res_buffer;

        packet.write(res_buffer);
        size_t datalen = res_buffer.getPos();
        char res_bytes[datalen];
        std::copy(res_buffer.buf.begin(), res_buffer.buf.end(), res_bytes);

        ssize_t bytes_sent = sendto(socket, res_bytes, datalen, 0, (struct sockaddr*) &source_addr, source_addrlen);
    
        if (bytes_sent <= 0)
        {
            throw std::runtime_error("An error occured when sending data! (handle_query)");
        }
    }
    catch (std::runtime_error e)
    {
        std::cout << strerror(errno) << std::endl;
        throw e;
    }
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        std::cout << "Usage: " << argv[0] << " port" << std::endl;
        return 0;
    }

    // Start listening
    int socket = PassiveSockUDP(argv[1]);
    if (socket < 0){
        return -1;
    }

    std::cout << "Listening on 0.0.0.0:" << argv[1] << " ..." << std::endl;

    srand(time(NULL));

    while (true)
    {
        try {
            handle_query(socket);
        }
        catch (std::runtime_error e) {
            std::cout << e.what() << std::endl;
        }
    }

    return 0;
}
