#include "./modules/dns_module.h"
#include "./modules/connectsock.h"
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <fstream>

const char* RECORD_FILE = "./modules/dns_records.txt"; // records file for local lookups
std::vector<DnsRecord> RECORDS; // where local records will be stored
IPv4Addr AROOT = IPv4Addr("198.41.0.4"); // this is a.root-servers.net

// Parses a file with records and stores them in a vector
// record example: tunnel.mydomain.top IN NS ns.mydomain.top
std::vector<DnsRecord> records_from_file(const char* file)
{
    std::vector<DnsRecord> result; 

    // opening the file
    std::ifstream fin(file);
    char reader[500]; // a buffer to read into
    if (!fin.is_open())
    {
        throw std::runtime_error("Could not open records file!");
    }

    while (fin >> reader) { // domain
        DnsRecord record;
        record.domain = reader;
        fin >> reader; // class
        fin >> reader; // qtype
        record.qtype = QueryTypeFunc::from_string(reader);

        fin.getline(reader, sizeof(reader)-1); // data
        get_byte_array_from_string(record.value, reader);

        // trim white spces
        record.value.erase(record.value.begin(), std::find_if(record.value.begin(), record.value.end(), [](unsigned char ch) {
            return !std::isspace(ch);
        }));

        record.ttl = 300;
        result.push_back(record);
    }

    fin.close();
    return result;
}

// Searches for a domain with a specific type within a vector of records
std::vector<DnsRecord> search_in_records(std::string qname, QueryType qtype, std::vector<DnsRecord> &records)
{
    std::vector<DnsRecord> result;

    for (auto &rec : records)
    {
        if (strcmp(rec.domain.c_str(), qname.c_str()) == 0) {
            // the domain is the one we are looking for
            if (rec.qtype == QueryType::NS || rec.qtype == qtype) // checking for the same type or maybe an NS
                result.push_back(rec);
        }
        else if (qname.ends_with(rec.domain)) // if the domain is ending whith the string we aim for an NS 
            if (rec.qtype == QueryType::NS)
                result.push_back(rec);
    }

    return result;
}

// Performs a lookup on the RECORDS vector for a domain and a type
DnsPacket local_lookup(std::string qname, QueryType qtype)
{
    DnsPacket result;
    std::vector<DnsRecord> records = search_in_records(qname, qtype, RECORDS);

    if (records.empty())
        result.header.rescode = ResultCode::NXDOMAIN; // nothing found
    else {
        for (auto &rec : records) 
        {
            if (qname == rec.domain && qtype == rec.qtype) // if everything is matching we have an answer
            {
                result.answers.push_back(rec);
                result.header.answers ++;
            }
            else // otherwise there is an NS that we can ask
            {
                result.header.authoritative_entries ++;
                result.authorities.push_back(rec); 
            }
        }
    }

    return result;
}

// Queryes a DNS server for a specific domain and type
DnsPacket lookup(std::string qname, QueryType qtype, IPv4Addr ns)
{
    // connection stuff
    struct sockaddr_in server_addr;
    bzero(&server_addr, sizeof(server_addr)); // clearing
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);
    inet_pton(AF_INET, ns.to_string().c_str(), &server_addr.sin_addr);
    
    // this socket is for listening for responses
    int socket = passive_sock_udp("43210"); // picking a random port to send the request
    if (set_socket_timeout(socket, 5) < 0)
    {
        std::cout << "Warning: Error when setting socket timeout" << std::endl;
    }

    DnsPacket packet = DnsPacket(); // the packet that will be sent

    try{
        // crafting the header
        packet.header.id = 1234; // random id
        packet.header.questions = 1;
        packet.header.recursion_desired = true;

        // crafting the body
        packet.questions.push_back(DnsQuestion(qname, qtype));

        // converting the packet into a buffer
        BytePacketBuffer request_buffer = BytePacketBuffer(); // request buffer
        packet.write(request_buffer);

        const size_t request_size = request_buffer.getPos(); // pakcet size

        // char request_bytes[p_size];
        // std::copy(request_buffer.buf.begin(), request_buffer.buf.end(), request_bytes);

        // sending the request
        ssize_t bytes_sent = sendto(socket, request_buffer.buf.data(), request_size, 0, (struct sockaddr*) &server_addr, sizeof(server_addr));
        if (bytes_sent <= 0)
        {
            close(socket);
            throw std::runtime_error("Some error occurred when sending data!\n");
        }

        // receiving response
        char response_bytes[BytePacketBuffer::packet_size]; // response goes here
        ssize_t bytes_read = recv(socket, response_bytes, BytePacketBuffer::packet_size, 0); 
        if (bytes_read <= 0)
        {
            close(socket);
            throw std::runtime_error("Some error occurred when receiving data!\n");
        }
        
        BytePacketBuffer response_buffer = BytePacketBuffer(response_bytes, bytes_read);
        
        close(socket);
        return DnsPacket::from_buffer(response_buffer);

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
    IPv4Addr ns = IPv4Addr("127.0.0.1"); // first we try a local lookup
    DnsPacket response;

    while (true)
    {

        try {
            
            if (ns.to_string() == "127.0.0.1") {
                // first perform a local lookup to see if there is a local domain assigned
                std::cout << "Attepmpting LOCAL lookup of " << QueryTypeFunc::to_string(qtype) << " " << qname << std::endl;
                response = local_lookup(qname, qtype);
            }
            else {
                std::cout << "Attepmpting ONLINE lookup of " << QueryTypeFunc::to_string(qtype) << " " << qname << " with NS " << ns.to_string() << std::endl;
                response = lookup(qname, qtype, ns);
            }
            
        }
        catch (std::runtime_error e)
        {
            throw e;
        }
        
        if (response.header.rescode == ResultCode::NXDOMAIN && ns.to_string() == "127.0.0.1") // no domain found locally
        {
            // local lookup failed, trying to ask a-root
            ns = AROOT;
            continue;
        }

        // success
        if (!response.answers.empty() && response.header.rescode == ResultCode::NOERROR)
            return response;

        // domain not found
        if (response.header.rescode == ResultCode::NXDOMAIN)
            return response;
        
        // if we are here it means that there are some resources we can check
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

// The main function that handles a request
void handle_query(int socket)
{
    struct sockaddr_storage source_addr;
    socklen_t source_addrlen = sizeof(source_addr);
    char request_bytes[BytePacketBuffer::packet_size];

    // Waiting for data
    ssize_t bytes_read = recvfrom(socket, request_bytes, BytePacketBuffer::packet_size, 0, (struct sockaddr*) &source_addr, &source_addrlen);
    if (bytes_read <= 0)
    {
        throw std::runtime_error("An error occured when receiving data! (handle_query)");
    }

    try
    {
        // Processing the data
        BytePacketBuffer request_buffer = BytePacketBuffer(request_bytes, (size_t) bytes_read);
        DnsPacket request = DnsPacket::from_buffer(request_buffer);

        DnsPacket packet; // response packet
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

            // building the packet's body
            packet.questions.push_back(question);

            std::cout << "Response packet:" << std::endl;
            for (size_t i = 0; i < result.answers.size(); i ++)
            {
                if (i == 0)
                    std::cout << "Answer:\n";
                std::cout << result.answers[i].to_string() << std::endl;
                packet.answers.push_back(result.answers[i]);
            }
            for (size_t i = 0; i < result.authorities.size(); i ++)
            {
                if (i == 0)
                    std::cout << "Authorities:\n";
                std::cout << result.authorities[i].to_string() << std::endl;
                packet.authorities.push_back(result.authorities[i]);
            }
            for (size_t i = 0; i < result.resources.size(); i ++)
            {
                if (i == 0)
                    std::cout << "Resources:\n";
                std::cout << result.resources[i].to_string() << std::endl;
                packet.resources.push_back(result.resources[i]);
            }
        }
        else{
            packet.header.rescode = ResultCode::FORMERR;
        }

        // Sending data back
        BytePacketBuffer response_buffer;

        packet.write(response_buffer);

        const size_t response_size = response_buffer.getPos();
        // char response_bytes[datalen];
        // std::copy(response_buffer.buf.begin(), response_buffer.buf.end(), response_bytes);

        ssize_t bytes_sent = sendto(socket, response_buffer.buf.data(), response_size, 0, (struct sockaddr*) &source_addr, source_addrlen);

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

    // getting the local records
    RECORDS = records_from_file(RECORD_FILE);

    // Start listening
    int socket = passive_sock_udp(argv[1]);
    if (socket < 0){
        return -1;
    }

    std::cout << "Listening on 0.0.0.0:" << argv[1] << " ..." << std::endl;

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
