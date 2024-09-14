/*################################*/
/*---------[ Disclaimer ]---------*/
/*################################*/

/**
 * This simple DNS server is a C++ adaptation from a Rust DNS server
 * You can see the server and the full documentation here: https://github.com/EmilHernvall/dnsguide/tree/master
 */

#ifndef DNS_MODULE_H
#define DNS_MODULE_H

#include <cstdint>
#include <cstring>
#include <cstddef>
#include <exception>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/types.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>

// Structs and namespaces for value representations

enum QueryType {
    UNKNOWN,
    A = 1,
    NS = 2,
    CNAME = 5, 
    MX = 15,
    TXT = 16,
    AAAA = 28
};

namespace QueryTypeFunc {
    // convertors
    uint16_t to_num(QueryType x);
    QueryType from_num(uint16_t n);
    std::string to_string(QueryType qtype);
    QueryType from_string(std::string str);
}

enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
};

namespace ResultCodeFunc{
    ResultCode from_num (int n);
}

// Structs for IPv4 and IPv6

struct IPv4Addr{
    std::vector<uint8_t> bytes = std::vector<uint8_t>(4); // each byte from the IP address

    IPv4Addr(uint32_t x);
    IPv4Addr(std::vector<uint8_t> bytes);
    IPv4Addr(std::string addr);

    std::string to_string() const;
};

struct IPv6Addr {
    std::vector<uint8_t> bytes = std::vector<uint8_t>(16); // each byte from the IP address

    // normally IPv6 parsing is more complex than this, this is only for my
    // dns server to manage IPv6 in case it receives an AAAA record
    IPv6Addr(std::vector<uint8_t> bytes);
    IPv6Addr(std::vector<uint16_t> bytes);
    IPv6Addr(std::string s);

    std::string to_string() const;
};

// This is where the code from the Rust server tutorial starts (https://github.com/EmilHernvall/dnsguide/tree/master)

// A struct to easily read and write bytes into a buffer
struct BytePacketBuffer{
    static size_t packet_size;
    std::vector<uint8_t> buf; // raw buffer to store all the bytes
    size_t pos; // current position within the buffer

    BytePacketBuffer();
    BytePacketBuffer(char* new_buf, size_t len);

    size_t getPos();

    // move the position over a specific number of bytes
    void step(size_t steps);

    // change current position
    void seek(size_t pos);

    // get the current byte from buffer's position without changing the position
    uint8_t get(size_t pos);

    // get a range of bytes from buf without changing the position
    uint8_t* get_range(size_t start, size_t len);

    // read one byte from the buffer's position and change the position
    uint8_t read_u8();
    uint16_t read_u16(); // 2 bytes
    uint32_t read_u32();

    // reads a domain name from the buffer
    void read_qname(char* outstr);
    // writes a domain name into the buffer
    void write_qname(const char* qname);

    void write_u8(uint8_t val);
    void write_u16(uint16_t val);
    void write_u32(uint32_t val);

    // set a byte to have the value of val without changing the possition
    void set_u8(size_t pos, uint8_t val);
    void set_u16(size_t pos, uint16_t val);
};

// DNS specific structs
struct DnsHeader {
    uint16_t id;
    
    uint16_t questions; // number of questions
    // number of records in specific sections
    uint16_t answers; 
    uint16_t authoritative_entries;
    uint16_t resource_entries;

    uint8_t opcode;
    ResultCode rescode;

    bool recursion_desired;
    bool truncated_message;
    bool authoritative_answer;
    bool response;

    bool checking_disabled;
    bool authed_data;
    bool z;
    bool recursion_available;

    DnsHeader();

    void read(BytePacketBuffer &buffer);
    void write(BytePacketBuffer &buffer);
    std::string to_string() const;
};

struct DnsQuestion {
    std::string name;
    QueryType qtype;

    DnsQuestion();
    DnsQuestion(std::string name, QueryType qtype);

    void read(BytePacketBuffer &buffer);
    void write(BytePacketBuffer &buffer);
    std::string to_string();
};

// complete documentation in .cpp file
struct DnsRecord {
    std::string domain;
    QueryType qtype;
    std::vector<uint8_t> value;
    uint32_t ttl;
    static const size_t txt_size;

    DnsRecord();
    DnsRecord(std::string domain, QueryType qtype, std::vector<uint8_t> value, uint32_t ttl) ;

    static DnsRecord read(BytePacketBuffer &buffer);
    size_t write(BytePacketBuffer &buffer);
    std::string to_string();
};

// The DNS packet struct incorporating everything
struct DnsPacket{
    DnsHeader header;
    std::vector<DnsQuestion> questions;
    std::vector<DnsRecord> answers;
    std::vector<DnsRecord> authorities;
    std::vector<DnsRecord> resources;

    DnsPacket();

    static DnsPacket from_buffer(BytePacketBuffer &buffer);
    void write(BytePacketBuffer &buffer);

    // returning -> (domain, host)
    std::vector<std::pair<std::string, std::string>> get_ns(std::string qname);
    IPv4Addr get_resolved_ns(std::string qname);
    IPv4Addr get_random_a();
    std::vector<std::string> get_unresolved_ns(std::string qname);

    std::string to_string();
};

// Some additional helper functions

std::vector<uint8_t> get_byte_array_from_string(std::string string); 
std::string get_string_from_byte_array(std::vector<uint8_t> byte_array);


#endif 