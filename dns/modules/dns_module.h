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
    uint16_t to_num(QueryType x);
    QueryType from_num(uint16_t n);
    std::string to_string(QueryType qtype);
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

// Structs to represent IPv4 and IPv6

struct IPv4Addr{
    uint8_t bytes[4];

    IPv4Addr(uint32_t x);
    IPv4Addr(std::string addr);
    std::string to_string() const;
};

struct IPv6Addr {
    uint16_t bytes[8];

    IPv6Addr(std::vector<uint16_t> bytes);
    IPv6Addr(std::string s);
    std::string to_string() const;
};

// This is where the Rust server starts

// A struct to easily read and write bytes to a buffer
struct BytePacketBuffer{
    static size_t packetSize;
    std::vector<uint8_t> buf; 
    size_t pos;

    BytePacketBuffer();
    BytePacketBuffer(char* new_buf, size_t len);

    // current position within buffer
    size_t getPos();

    // move the position over a specific number of steps
    void step(size_t steps);

    // change current position
    void seek(size_t pos);

    // get the current byte from buffer's position without changing the position
    uint8_t get(size_t pos);

    // get a range of bytes from buf
    uint8_t* get_range(size_t start, size_t len);

    // read one byte from the buffer's position and change the position
    uint8_t read_u8();
    uint16_t read_u16(); // 2 bytes
    uint32_t read_u32();

    void read_qname(char* outstr);
    void write_qname(char* qname);

    void write_u8(uint8_t val);
    void write_u16(uint16_t val);
    void write_u32(uint32_t val);

    void set_u8(size_t pos, uint8_t val);
    void set_u16(size_t pos, uint16_t val);
};

// DNS specific structs
struct DnsHeader {
    uint16_t id;
    
    uint16_t questions;
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

struct DNSRecord {
    std::string domain;
    QueryType qtype;
    std::string value;
    uint32_t ttl;
    static const size_t txt_size;

    DNSRecord();
    DNSRecord(std::string domain, QueryType qtype, std::string value, uint32_t ttl) ;\

    static DNSRecord read(BytePacketBuffer &buffer);
    size_t write(BytePacketBuffer &buffer);
    std::string to_string();
};

// The DNS packet struct incorporating everything
struct DnsPacket{
    DnsHeader header;
    std::vector<DnsQuestion> questions;
    std::vector<DNSRecord> answers;
    std::vector<DNSRecord> authorities;
    std::vector<DNSRecord> resources;

    DnsPacket();

    static DnsPacket from_buffer(BytePacketBuffer &buffer);
    void write(BytePacketBuffer &buffer);

    // returning -> (domain, host)
    std::vector<std::pair<std::string, std::string>> get_ns(std::string qname);
    IPv4Addr get_resolved_ns(std::string qname);
    IPv4Addr get_random_a();
    std::vector<std::string> get_unresolved_ns(std::string qname);
};

// This is a helper function that takes the first 4 bytes from a string
uint32_t take_4_bytes(std::string val, int index);

#endif 