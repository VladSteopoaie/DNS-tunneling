/*################################*/
/*---------[ Disclaimer ]---------*/
/*################################*/

/**
 * This simple DNS server is a C++ adaptation from a Rust DNS server
 * You can see the server and the full documentation here: https://github.com/EmilHernvall/dnsguide/tree/master
 */

#include "dns_module.h"
#include <stdexcept>
#include <vector>

/*###################################*/
/*---------[ QueryTypeFunc ]---------*/
/*###################################*/

uint16_t QueryTypeFunc::to_num(QueryType x){
    switch (x){
        case A: 
            return 1;   
        case NS:
            return 2;
        case CNAME:
            return 5;
        case MX:
            return 15;
        case TXT:
            return 16;
        case AAAA:
            return 28;
        default:
            return 0;
    }
}

QueryType QueryTypeFunc::from_num(uint16_t n)
{
    switch(n)
    {
        case 1:
            return QueryType::A;
        case 2:
            return QueryType::NS;
        case 5:
            return QueryType::CNAME;
        case 15:
            return QueryType::MX;
        case 16:
            return QueryType::TXT;
        case 28:
            return QueryType::AAAA;
        default:
            return QueryType::UNKNOWN;
    }
}

std::string QueryTypeFunc::to_string(QueryType qtype)
{
    switch(qtype)
    {
        case QueryType::A:
            return std::string("A");
        case QueryType::NS:
            return std::string("NS");
        case QueryType::CNAME:
            return std::string("CNAME");
        case QueryType::MX:
            return std::string("MX");
        case QueryType::TXT:
            return std::string("TXT");
        case QueryType::AAAA:
            return std::string("AAAA");
        default:
            return std::string("UNKNOWN");
    }
}

QueryType QueryTypeFunc::from_string(std::string str) 
{
    if (!strcmp(str.c_str(), "A"))
        return QueryType::A;
    if (!strcmp(str.c_str(), "NS"))
        return QueryType::NS;
    if (!strcmp(str.c_str(), "CNAME"))
        return QueryType::CNAME;
    if (!strcmp(str.c_str(), "MX"))
        return QueryType::MX;
    if (!strcmp(str.c_str(), "TXT"))
        return QueryType::TXT;
    if (!strcmp(str.c_str(), "AAAA"))
        return QueryType::AAAA;
    
    return QueryType::UNKNOWN;
}


/*################################*/
/*---------[ ResultCode ]---------*/
/*################################*/

ResultCode ResultCodeFunc::from_num (int n)
{
    switch(n){
        case 1:
            return FORMERR;
        case 2: 
            return SERVFAIL;
        case 3:
            return NXDOMAIN;
        case 4:
            return NOTIMP;
        case 5:
            return REFUSED;
        default:
            return NOERROR;
    }
}


/*##############################*/
/*---------[ IPv4Addr ]---------*/
/*##############################*/

IPv4Addr::IPv4Addr(uint32_t x)
{
    bytes[0] = (uint8_t) ((x >> 24) & 0xFF);
    bytes[1] = (uint8_t) ((x >> 16) & 0xFF);
    bytes[2] = (uint8_t) ((x >> 8) & 0xFF);
    bytes[3] = (uint8_t) ((x >> 0) & 0xFF);
}

IPv4Addr::IPv4Addr(std::vector<uint8_t> bytes)
{
    this->bytes = bytes;
}

IPv4Addr::IPv4Addr(std::string addr)
{
    char* ip = (char*) addr.c_str();

    // breaking the address into tokens to get each byte
    char* token = strtok(ip, ".");
    int i = 0;

    while (token != NULL)
    {
        // if the string is empty the returned address will be 0.0.0.0
        if (strcmp(token, "") == 0)
        {
            for (int j = 0; j < 4; j ++)
                bytes[j] = 0;
            break;
        }

        // simple conversion for each byte
        bytes[i] = (uint8_t) atoi(token);

        token = strtok(NULL, ".");
        i ++;
    }
}

std::string IPv4Addr::to_string() const
{
    std::string addr = "";

    addr += std::to_string(bytes[0]) + ".";
    addr += std::to_string(bytes[1]) + ".";
    addr += std::to_string(bytes[2]) + ".";
    addr += std::to_string(bytes[3]);

    return addr;
}

/*##############################*/
/*---------[ IPv6Addr ]---------*/
/*##############################*/

IPv6Addr::IPv6Addr(std::vector<uint8_t> bytes)
{
    this->bytes = bytes;
}

IPv6Addr::IPv6Addr(std::vector<uint16_t> bytes)
{
    for (int i = 0; i < bytes.size(); i += 2)
    {
        this->bytes[i * 2] = bytes[i] >> 8; 
        this->bytes[i * 2 + 1] = bytes[i] & 0xF; 
    }
}

IPv6Addr::IPv6Addr(std::string str)
{
    std::stringstream ss(str);
    ss << std::hex << std::setfill('0');

    uint16_t word; // 2 bytes = 1 word
    int i = 0;
    while (ss >> std::setw(4) >> word) {
        bytes[i * 2] = word >> 8;
        bytes[i * 2 + 1] = word & 0xF;
        if (ss.peek() == ':') {
            ss.ignore();
        }
        i ++;
    }
    if (i != 8) {
        throw std::invalid_argument("Invalid IPv6 address string");
    }
}

std::string IPv6Addr::to_string() const
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (int i = 0; i < 8; ++i) {
        ss << std::setw(4) << static_cast<unsigned>((bytes[i * 2] << 8) + bytes[i * 2 + 1]);
        if (i < 7) {
            ss << ":";
        }
    }
    return ss.str();
}


/*######################################*/
/*---------[ BytePacketBuffer ]---------*/
/*######################################*/

size_t BytePacketBuffer::packet_size = 1024;

BytePacketBuffer::BytePacketBuffer()
{
    buf = std::vector<uint8_t>();
    pos = 0;            
}

BytePacketBuffer::BytePacketBuffer(char* new_buf, size_t len)
{
    pos = 0;            
    buf = std::vector<uint8_t>();

    if (len > packet_size)
    {
        throw std::runtime_error("BytePacketBuffer: Size provided is greater that the packet size (512 bytes).");
    }

    for (size_t i = 0; i < len; i ++)
    {
        buf.push_back(new_buf[i]);
    }
}

// current position within buffer
size_t BytePacketBuffer::getPos()
{
    return pos;
}

// move the position over a specific number of bytes
void BytePacketBuffer::step(size_t steps)
{
    pos += steps;
}

// change current position
void BytePacketBuffer::seek(size_t pos)
{
    this->pos = pos;
}

// get the current byte from buffer's position without changing the position
uint8_t BytePacketBuffer::get(size_t pos)
{
    if (pos >= packet_size)
        throw std::runtime_error("End of buffer 2!");
    return buf[pos];
}

// get a range of bytes from buf without changing the position
uint8_t* BytePacketBuffer::get_range(size_t start, size_t len)
{
    if (start + len >= packet_size)
        throw std::runtime_error("End of buffer 3!");

    uint8_t* res = new uint8_t[len + 1];
    std::copy(buf.begin() + start, buf.begin() + start + len, res);
    res[len] = 0;
    return res;
}

// read one byte from the buffer's position and change the position
uint8_t BytePacketBuffer::read_u8()
{
    if (pos >= packet_size)
        throw std::runtime_error("End of buffer 1!");
    
    uint8_t r = buf[pos];
    pos += 1;
    return r;
}

// reads 2 bytes from buf
uint16_t BytePacketBuffer::read_u16()
{
    uint16_t rez; 
    try {
        rez = (uint16_t) read_u8() << 8;
        rez += (uint16_t) read_u8();
    } catch (std::runtime_error e) {
        throw e;
    }
    return rez;
}

// reads 4 bytes from buf
uint32_t BytePacketBuffer::read_u32()
{
    uint32_t rez;
    try{
        rez = (uint32_t) read_u16() << 16;
        rez += read_u16();
    } catch (std::runtime_error e)
    {
        throw e;
    }
    
    return rez;
}

// reads a domain name from the buffer

// The tricky part: Reading domain names, taking labels into consideration.
// Will take something like [3]www[6]google[3]com[0] and append
// www.google.com to outstr.
void BytePacketBuffer::read_qname(char* outstr)
{
    // Since we might encounter jumps, we'll keep track of our position
    // locally as opposed to using the position within the struct. This
    // allows us to move the shared position to a point past our current
    // qname, while keeping track of our progress on the current qname
    // using this variable.
    size_t local_pos = this->pos;

    // tracking whether a jump was performed
    bool jumped = false;
    int max_jumps = 5;
    int jumps_performed = 0;

    // Our delimiter which we append for each label. Since we don't want a
    // dot at the beginning of the domain name we'll leave it empty for now
    // and set it to "." at the end of the first iteration.
    std::string delim = "";
    
    outstr[0] = '\0'; // clearing the result string
    
    while (true)
    {
        if (jumps_performed > max_jumps) 
            throw std::runtime_error("Limit of jumps exceeded!");

        // At this point, we're always at the beginning of a label. Recall
        // that labels start with a length byte.
        uint8_t len = get(local_pos);

        // If len has the two most significant bit are set, it represents a
        // jump to some other offset in the packet:
        if ((len & 0xC0) == 0xC0)
        {
            // Update the buffer position to a point past the current
            // label. We don't need to touch it any further.
            if (!jumped) 
                seek(local_pos + 2);
        
            // Read another byte, calculate offset and perform the jump by
            // updating our local position variable
            // the offset for the jump has 2 bytes so I converted it to uint16_t
            uint16_t byte2 = (uint16_t) get(local_pos + 1);
            uint16_t offset = ((((uint16_t) len) ^ 0xC0) << 8) | byte2;
            local_pos = (size_t) offset;

            jumped = true;
            jumps_performed ++;
            continue;
        }
        // The base scenario, where we're reading a single label and
        // appending it to the output:
        else
        {
            local_pos ++;

            // Domain names are terminated by an empty label of length 0,
            // so if the length is zero we're done.
            if (len == 0)
                break;

            // Append the delimiter to our output buffer first.
            strcat(outstr, delim.c_str());

            // Extract the actual ASCII bytes for this label and append them
            // to the output buffer.
            char* temp_buffer = (char*) get_range(local_pos, (size_t) len);
            strcat(outstr, temp_buffer);
            delim = ".";

            local_pos += (size_t) len;
            delete[] temp_buffer;
        }
    }

    if (!jumped) {
        seek(local_pos);
    }

}

// writes a domain name into the buffer
void BytePacketBuffer::write_qname(const char* qname)
{
    // making a copy of the const string
    char c_qname[strlen(qname) + 1];
    strncpy(c_qname, qname, strlen(qname));
    c_qname[strlen(qname)] = '\0';

    // spliting the domain by "."
    char* token = strtok(c_qname, ".");

    while(token != NULL)
    {
        size_t len = strlen(token);
        if (len > 0x3f)
            throw std::runtime_error("Single label exceeds 63 characters of length!");
        
        // first we write the length of the token
        write_u8((uint8_t) len);

        // then the token is written
        for (int i = 0; token[i]; i ++)
            write_u8((uint8_t) token[i]);

        token = strtok(NULL, ".");
    }
        
    write_u8(0);
}

// writing 1 byte into the buffer
void BytePacketBuffer::write_u8(uint8_t val)
{
    if (pos >= packet_size)
        throw std::runtime_error("End of buffer! (write_u8)");

    if (pos < buf.size())
        buf[pos] = val;
    else 
        buf.push_back(val);
    pos += 1;
}

// writing 2 bytes into the buffer
void BytePacketBuffer::write_u16(uint16_t val)
{
    try{
        write_u8((uint8_t) (val >> 8));
        write_u8((uint8_t) (val & 0xFF));
    }
    catch(std::runtime_error e)
    {
        throw e;
    }
}

// writing 4 bytes into the buffer
void BytePacketBuffer::write_u32(uint32_t val)
{
    try{
        write_u8((uint8_t) (val >> 24 & 0xFF));
        write_u8((uint8_t) (val >> 16 & 0xFF));
        write_u8((uint8_t) (val >> 8 & 0xFF));
        write_u8((uint8_t) (val >> 0 & 0xFF));
    }
    catch(std::runtime_error e)
    {
        throw e;
    }
}

// set a byte to have the value of val without changing the possition
void BytePacketBuffer::set_u8(size_t pos, uint8_t val)
{
    buf[pos] = val;
}

// set 2 bytes to have the value of val without changing the possition
void BytePacketBuffer::set_u16(size_t pos, uint16_t val)
{
    set_u8(pos, (uint8_t) (val >> 8));
    set_u8(pos + 1, (uint8_t) (val & 0xFF));
}


/*################################*/
/*---------[ DnsHeader ]---------*/
/*################################*/

DnsHeader::DnsHeader()
{
    id = 0;

    questions = 0;
    answers = 0;
    authoritative_entries = 0;
    resource_entries = 0;

    opcode = 0;
    rescode = ResultCode::NOERROR;
    
    recursion_desired = false;
    truncated_message = false;
    authoritative_answer = false;
    response = false;

    checking_disabled = false;
    authed_data = false;
    z = false;
    recursion_available = false;

}

/*
 * Structure of a DNS Header:
 * 
 * A DNS header is 12 bytes long and contains several fields used to identify and manage DNS queries and responses.
 * 
 * 1. ID (Packet Identifier) - 16 bits:
 *    A unique identifier assigned to each query packet. The response packet must have the same ID to match the query.
 *    This helps differentiate responses due to the stateless nature of UDP.
 * 
 * 2. QR (Query/Response Flag) - 1 bit:
 *    0 for queries, 1 for responses.
 * 
 * 3. OPCODE (Operation Code) - 4 bits:
 *    Typically 0 (standard query). Other values exist but are rarely used. See RFC 1035 for details.
 * 
 * 4. AA (Authoritative Answer Flag) - 1 bit:
 *    Set to 1 if the responding server is authoritative for the domain in the query.
 * 
 * 5. TC (Truncated Message Flag) - 1 bit:
 *    Set to 1 if the message is too long to fit in a single UDP packet (greater than 512 bytes). This indicates that the client
 *    should retry the request over TCP, where this limitation does not apply.
 * 
 * 6. RD (Recursion Desired Flag) - 1 bit:
 *    Set by the client if recursive query resolution is desired. If the server does not know the answer, it will query other servers.
 * 
 * 7. RA (Recursion Available Flag) - 1 bit:
 *    Set by the server in its response to indicate that it supports recursive query resolution.
 * 
 * 8. Z (Reserved) - 3 bits:
 *    Reserved for future use, typically set to 0 in standard queries but may be used for DNSSEC.
 * 
 * 9. RCODE (Response Code) - 4 bits:
 *    Set in responses to indicate success or failure of the query. Common values include:
 *      - 0: No error (success).
 *      - 1: Format error (query could not be parsed).
 *      - 2: Server failure (internal error).
 *      - 3: Name error (domain does not exist).
 * 
 * 10. QDCOUNT (Question Count) - 16 bits:
 *     The number of entries in the Question section. Typically 1 for a standard query.
 * 
 * 11. ANCOUNT (Answer Count) - 16 bits:
 *     The number of entries in the Answer section (the response section for query results).
 * 
 * 12. NSCOUNT (Authority Count) - 16 bits:
 *     The number of entries in the Authority section, which lists authoritative name servers for the queried domain.
 * 
 * 13. ARCOUNT (Additional Count) - 16 bits:
 *     The number of entries in the Additional section, which contains additional information, like extra resource records.
 */


void DnsHeader::read(BytePacketBuffer &buffer)
{
    try {
        id = buffer.read_u16();
        uint16_t flags = buffer.read_u16();
        uint8_t first_byte = (uint8_t) (flags >> 8);
        uint8_t second_byte = (uint8_t) (flags & 0xFF);

        recursion_desired = (first_byte & (1 << 0)) > 0;
        truncated_message = (first_byte & (1 << 1)) > 0;
        authoritative_answer = (first_byte & (1 << 2)) > 0;
        opcode = (first_byte >> 3) & 0x0F;
        response = (first_byte & (first_byte << 7)) > 0;

        rescode = ResultCodeFunc::from_num(second_byte & 0x0F);
        checking_disabled = (second_byte & (1 << 4)) > 0;
        authed_data = (second_byte & (1 << 5)) > 0;
        z = (second_byte & (1 << 6)) > 0;
        recursion_available = (second_byte & (1 << 7)) > 0;

        questions = buffer.read_u16();
        answers = buffer.read_u16();
        authoritative_entries = buffer.read_u16();
        resource_entries = buffer.read_u16();
    } catch (std::runtime_error e) {
        throw e;
    }
}

void DnsHeader::write(BytePacketBuffer &buffer)
{
    try{
        buffer.write_u16(id);

        buffer.write_u8(
            (uint8_t) (recursion_desired)
            | (((uint8_t) (truncated_message)) << 1)
            | (((uint8_t) (authoritative_answer)) << 2)
            | (opcode << 3)
            | (((uint8_t) (response)) << 7)
        );

        buffer.write_u8(
            (uint8_t) rescode 
            | (((uint8_t) (checking_disabled)) << 4)
            | (((uint8_t) (authed_data)) << 5)
            | (((uint8_t) (z)) << 6)
            | (((uint8_t) (recursion_available)) << 7)
        );

        buffer.write_u16(questions);
        buffer.write_u16(answers);
        buffer.write_u16(authoritative_entries);
        buffer.write_u16(resource_entries);
    }
    catch(std::runtime_error e)
    {
        throw e;
    }
}

std::string DnsHeader::to_string() const {
    std::string result = "DnsHeader {\n";
    result += "\tid: " + std::to_string(id) + ",\n";
    result += "\tquestions: " + std::to_string(questions) + ",\n";
    result += "\tanswers: " + std::to_string(answers) + ",\n";
    result += "\tauthoritative_entries: " + std::to_string(authoritative_entries) + ",\n";
    result += "\tresource_entries: " + std::to_string(resource_entries) + ",\n";
    result += "\topcode: " + std::to_string(static_cast<int>(opcode)) + ",\n";
    result += "\trescode: " + std::to_string(static_cast<int>(rescode)) + ",\n";
    result += std::string("\trecursion_desired: ") + (recursion_desired ? "true" : "false") + ",\n";
    result += std::string("\ttrucated_message: ") + (truncated_message ? "true" : "false") + ",\n";
    result += std::string("\tauthoritative_answer: ") + (authoritative_answer ? "true" : "false") + ",\n";
    result += std::string("\tresponse: ") + (response ? "true" : "false") + ",\n";
    result += std::string("\tchecking_disabled: ") + (checking_disabled ? "true" : "false") + ",\n";
    result += std::string("\tauthed_data: ") + (authed_data ? "true" : "false") + ",\n";
    result += std::string("\tz: ") + (z ? "true" : "false") + ",\n";
    result += std::string("\trecursion_available: ") + (recursion_available ? "true" : "false") + ",\n";
    result += "}\n";
    return result;
}


/*#################################*/
/*---------[ DnsQuestion ]---------*/
/*#################################*/

/*
 * Structure of the DNS Question Section:
 *
 * Each DNS query contains one or more entries in the "Question" section, which specifies the name, type, and class of the query.
 *
 * 1. Name (Label Sequence):
 *    The domain name is encoded as a sequence of labels. Each label consists of a length byte followed by that number of bytes of text.
 *    The domain name is terminated by a null byte (0x00).
 * 
 * 2. Type (2-byte Integer):
 *    Specifies the record type being queried. Common values include:
 *      - 1: A (IPv4 address)
 *      - 2: NS (Name Server)
 *      - 5: CNAME (Canonical Name)
 *      - 15: MX (Mail Exchange)
 *      - 28: AAAA (IPv6 address)
 * 
 * 3. Class (2-byte Integer):
 *    Specifies the class of the query, which is almost always set to 1 (IN for Internet).
 */


DnsQuestion::DnsQuestion(std::string name, QueryType qtype)
{
    this->name = name;
    this->qtype = qtype;
}

DnsQuestion::DnsQuestion()
{
    this->name = "";
    this->qtype = QueryType::UNKNOWN;
}


void DnsQuestion::read(BytePacketBuffer &buffer)
{
    char* qname = new char[1024];
    try{
        buffer.read_qname(qname);

        this->name = qname;
        this->qtype = QueryTypeFunc::from_num(buffer.read_u16());
        buffer.read_u16(); // class

        delete[] qname;
    }
    catch(std::runtime_error e)
    {
        delete[] qname;
        throw e;
    }
}

void DnsQuestion::write(BytePacketBuffer &buffer)
{
    try {
        buffer.write_qname((char*) this->name.c_str());
        buffer.write_u16(QueryTypeFunc::to_num(qtype));
        buffer.write_u16(1);
    } catch (std::runtime_error e) {
        throw e;
    }
}

std::string DnsQuestion::to_string()
{
    std::string s = "DnsQuestion { ";
    s += "\tname: " + name + ", ";
    s += "\tqtype: " + QueryTypeFunc::to_string(qtype) + ' ';
    s += "}\n";
    return s;
}

/*###############################*/
/*---------[ DnsRecord ]---------*/
/*###############################*/

/*
 * Structure of a DNS Resource Record (RR):
 *
 * Each Resource Record (RR) contains the following fields:
 *
 * 1. Name (Label Sequence):
 *    The domain name, encoded as a sequence of labels. Each label consists of a length byte followed by that number of bytes of text.
 *    The domain name is terminated by a null byte (0x00).
 *
 * 2. Type (2-byte Integer):
 *    Specifies the type of the resource record. Common types include:
 *      - 1: A (IPv4 address)
 *      - 2: NS (Name Server)
 *      - 5: CNAME (Canonical Name)
 *      - 15: MX (Mail Exchange)
 *      - 28: AAAA (IPv6 address)
 *
 * 3. Class (2-byte Integer):
 *    Specifies the class of the record, typically set to 1 (IN for Internet).
 *
 * 4. TTL (4-byte Integer):
 *    Time-To-Live specifies how long the record can be cached by a resolver before it should be queried again. 
 *    It's a value in seconds.
 *
 * 5. Length (Len) (2-byte Integer):
 *    Indicates the length (in bytes) of the resource data that follows. This length is specific to the record type.
 */


const size_t DnsRecord::txt_size = 400;

DnsRecord::DnsRecord()
{
    this->domain = "";
    this->qtype = QueryType::UNKNOWN;
    this->value = std::vector<uint8_t>();
    this->ttl = 0;
}

DnsRecord::DnsRecord(std::string domain, QueryType qtype, std::vector<uint8_t> value, uint32_t ttl) 
{
    this->domain = domain;
    this->qtype = qtype;
    this->value = value;
    this->ttl = ttl;
}

DnsRecord DnsRecord::read(BytePacketBuffer &buffer)
{
    char* domain = new char[1024];

    try {
        buffer.read_qname(domain);
        QueryType qtype = QueryTypeFunc::from_num(buffer.read_u16());
        buffer.read_u16(); // class
        uint32_t ttl = buffer.read_u32();
        size_t data_len = (size_t) buffer.read_u16();
    
        DnsRecord record;

        switch(qtype)
        {
            case QueryType::A:
            {
                /*
                * Structure of a DNS A (Address) Record:
                *
                * 1. Preamble (Record Preamble):
                *    The record preamble, as described above, with the length field set to 4.
                *
                * 2. IP (4-byte Integer):
                *    An IP address encoded as a four-byte integer.
                */

                uint32_t raw_addr = buffer.read_u32();
                IPv4Addr addr = IPv4Addr(raw_addr);
                record = DnsRecord(domain, qtype, addr.bytes, ttl);
                break;
            }   
            case QueryType::NS:
            {
                /*
                * Structure of a DNS NS (Name Server) Record:
                *
                * 1. Preamble (Record Preamble):
                *    The record preamble, as described above.
                *
                * 2. Name Server (Label Sequence):
                *    The domain name of the authoritative name server, encoded as a sequence of labels.
                */

                char ns[1024];
                buffer.read_qname(ns);
                
                std::vector<uint8_t> ns_bytes = get_byte_array_from_string(ns);

                record = DnsRecord(domain, qtype, ns_bytes, ttl);
                break;
            }
            case QueryType::CNAME:
            {
                /*
                * Structure of a DNS CNAME (Canonical Name) Record:
                *
                * 1. Preamble (Record Preamble):
                *    The record preamble, as described above.
                *
                * 2. Canonical Name (Label Sequence):
                *    The canonical domain name that this alias points to, encoded as a sequence of labels.
                */

                char cname[1024];
                buffer.read_qname(cname);

                std::vector<uint8_t> cname_bytes = get_byte_array_from_string(cname);
                record = DnsRecord(domain, qtype, cname_bytes, ttl);
                break;
            }
            case QueryType::MX:
            {
                /*
                * Structure of a DNS MX (Mail Exchange) Record:
                *
                * 1. Preamble (Record Preamble):
                *    The record preamble, as described above.
                *
                * 2. Preference (2-byte Integer):
                *    The priority of this mail exchange server, lower values are preferred.
                *
                * 3. Mail Server (Label Sequence):
                *    The domain name of the mail server, encoded as a sequence of labels.
                */

                uint16_t priority = buffer.read_u16();
                char mx[1024];
                buffer.read_qname(mx);

                std::string mx_value = std::to_string(priority) + ", " + mx;
                std::vector<uint8_t> mx_bytes = get_byte_array_from_string(mx_value);                
                record = DnsRecord(domain, qtype, mx_bytes, ttl);
                break;
            }
            case QueryType::AAAA:
            {
                /*
                * Structure of a DNS AAAA (IPv6 Address) Record:
                *
                * 1. Preamble (Record Preamble):
                *    The record preamble, as described above, with the length field set to 16.
                *
                * 2. IPv6 Address (16-byte Integer):
                *    A 128-bit (16-byte) IPv6 address encoded as 16 bytes.
                */

                std::vector<uint8_t> bytes;
                for (int i = 0; i < 16; i ++)
                    bytes.push_back(buffer.read_u8());
                
                record = DnsRecord(domain, qtype, bytes, ttl);
                break;
            }
            case QueryType::TXT:
            {
                /*
                * Structure of a DNS TXT (Text) Record:
                *
                * 1. Preamble (Record Preamble):
                *    The record preamble, as described above.
                *
                * 2. Text Length (1-byte Integer):
                *    The length of the following text data.
                *
                * 3. Text (Variable Length String):
                *    Arbitrary text data stored in the record.
                */

                const size_t chunk_size = 255;
                std::vector<uint8_t> txt_value;
                for (int i = 0; i < data_len; i ++)
                {
                    if (i == 0) // reading chunk len
                    {
                        size_t chunk_len = (size_t) buffer.read_u8();
                        if (chunk_len + 1 != data_len && chunk_len != chunk_size)
                            throw std::runtime_error("TXT data length different from first chunk lengths!");
                        continue;
                    }
                    
                    if (i == 256) // reading chunk len
                    {
                        size_t chunk_len = (size_t) buffer.read_u8();
                        if (chunk_len + chunk_size + 2 != data_len)
                            throw std::runtime_error("TXT data length different from second chunk lengths!");
                        continue;
                    }

                    txt_value.push_back(buffer.read_u8());
                }


                record = DnsRecord(domain, qtype, txt_value, ttl);
                break;
            }
            default:
            {
                char *default_value = (char*) buffer.get_range(buffer.getPos(), data_len);
                buffer.step(data_len);

                std::vector<uint8_t> default_bytes = get_byte_array_from_string(default_value);

                record = DnsRecord(domain, qtype, default_bytes, ttl);
                delete[] default_value;
                break;
            }
        }

        delete[] domain;
        return record;
    }
    catch (std::runtime_error e)
    {
        delete[] domain;
        throw e;
    }
}

size_t DnsRecord::write(BytePacketBuffer &buffer)
{
    size_t start_pos = buffer.getPos();

    try{
        switch(qtype)
        {
            case QueryType::A:
            {
                // preamble
                buffer.write_qname((char*) domain.c_str());
                buffer.write_u16(QueryTypeFunc::to_num(QueryType::A));
                buffer.write_u16(1);
                buffer.write_u32(ttl);
                buffer.write_u16(4); // data_len

                // A specific
                buffer.write_u8(value[0]);
                buffer.write_u8(value[1]);
                buffer.write_u8(value[2]);
                buffer.write_u8(value[3]);
                break;
            }
            case QueryType::NS:
            {
                // preamble
                buffer.write_qname((char*) domain.c_str());
                buffer.write_u16(QueryTypeFunc::to_num(QueryType::NS));
                buffer.write_u16(1);
                buffer.write_u32(ttl);

                size_t pos = buffer.getPos();
                buffer.write_u16(0); // the real length will be set after the domain is written
                
                // NS specific
                std::string ns_name = get_string_from_byte_array(value);
                buffer.write_qname(ns_name.c_str());

                size_t size = buffer.getPos() - (pos + 2);
                buffer.set_u16(pos, (uint16_t) size); // setting the data_len
                break;
            }
            case QueryType::CNAME:
            {
                // preamble
                buffer.write_qname((char*) domain.c_str());
                buffer.write_u16(QueryTypeFunc::to_num(QueryType::CNAME));
                buffer.write_u16(1);
                buffer.write_u32(ttl);

                // same as for NX
                size_t pos = buffer.getPos();
                buffer.write_u16(0);
                
                // CNAME specific
                std::string cname = get_string_from_byte_array(value);
                buffer.write_qname(cname.c_str());

                // setting data_len
                size_t size = buffer.getPos() - (pos + 2);
                buffer.set_u16(pos, (uint16_t) size);
                break;
            }
            case QueryType::MX:
            {
                // preamble
                buffer.write_qname((char*) domain.c_str());
                buffer.write_u16(QueryTypeFunc::to_num(QueryType::MX));
                buffer.write_u16(1);
                buffer.write_u32(ttl);

                size_t pos = buffer.getPos();
                buffer.write_u16(0);

                // MX specific
                std::string mx_name = get_string_from_byte_array(value);
                size_t delim_pos = mx_name.find(", ");
                std::string priority = mx_name.substr(0, delim_pos);
                std::string host = mx_name.substr(delim_pos + 2);

                buffer.write_u16((uint16_t) atoi(priority.c_str()));
                buffer.write_qname(host.c_str());

                // setting data_len
                size_t size = buffer.getPos() - (pos + 2);
                buffer.set_u16(pos, (uint16_t) size);
                break;
            }
            case QueryType::AAAA:
            {
                // preamble
                buffer.write_qname((char*) domain.c_str());
                buffer.write_u16(QueryTypeFunc::to_num(QueryType::AAAA));
                buffer.write_u16(1);
                buffer.write_u32(ttl);
                buffer.write_u16(16);

                // AAAA specific
                for (int i = 0; i < 16; i ++)
                    buffer.write_u8(value[i]);

                break;
            }
            case QueryType::TXT:
            {
                // preamble
                buffer.write_qname((char*) domain.c_str());
                buffer.write_u16(QueryTypeFunc::to_num(QueryType::TXT));
                buffer.write_u16(1);
                buffer.write_u32(ttl);

                /*
                * TXT values must be splitted into chunks of 255 length.
                * The data_len is a 2 bytes space which takes the length of the whole data.
                * After that there is a byte dennoting the lenght of the next chunk.
                */

                if (value.size() > txt_size + 2)
                    throw std::runtime_error("TXT size exceeded!");
                
                size_t chunk_size = 255;

                if (value.size() > chunk_size){
                    // if the value's size is greater that a chunk
                    // the maximum size is written in the length byte
                    buffer.write_u16(value.size() + 2); // size of data + 2 (length bytes for 2 chunks)
                    buffer.write_u8(chunk_size); // chunk size

                    // the maximum size is 400 bytes, so we know that there can be a maximum of 2 chunks
                }
                else{
                    buffer.write_u16(value.size() + 1); // size of data + 1 (only 1 length byte)
                    buffer.write_u8(value.size()); // chunk size
                }

                // writing the data
                for (int i = 0; i < value.size(); i ++){
                    if (i == chunk_size)
                        buffer.write_u8(value.size() - chunk_size);
                    buffer.write_u8(value[i]);
                }
                break;
            }
            default:
                std::cout << "Skipping record:\n" << this->to_string();
                break;
        }

        return buffer.getPos() - start_pos;
    }
    catch(std::runtime_error e)
    {
        throw e;
    }
}

std::string DnsRecord::to_string()
{
    std::string s = QueryTypeFunc::to_string(qtype) + " { ";
    s += "domain: " + domain + ", ";
    s += "data: ";
    switch(qtype)
    {
        case QueryType::A: 
        {
            s += IPv4Addr(value).to_string();
            break;
        }
        case QueryType::AAAA:
        {
            s += IPv6Addr(value).to_string();
            break;
        }
        default:
        {
            std::string str_value = get_string_from_byte_array(value);
            s += str_value;
            break;
        }
    }
    s += ", ";
    s += "ttl: " + std::to_string(ttl) + " ";
    s += "}\n";
    return s;
}

/*###############################*/
/*---------[ DnsPacket ]---------*/
/*##############################*/

DnsPacket::DnsPacket()
{
    header = DnsHeader();
    questions = std::vector<DnsQuestion>();
    answers = std::vector<DnsRecord>();
    authorities = std::vector<DnsRecord>();
    resources = std::vector<DnsRecord>();
}

DnsPacket DnsPacket::from_buffer(BytePacketBuffer &buffer)
{
    try {
        DnsPacket result;
        result.header.read(buffer);

        for (size_t i = 0; i < result.header.questions; i ++)
        {
            DnsQuestion question;
            question.read(buffer);
            result.questions.push_back(question);
        }

        for (size_t i = 0; i < result.header.answers; i ++)
        {
            DnsRecord answer = DnsRecord::read(buffer);
            result.answers.push_back(answer);
        }

        for (size_t i = 0; i < result.header.authoritative_entries; i ++)
        {
            DnsRecord entry = DnsRecord::read(buffer);
            result.authorities.push_back(entry);
        }

        for (size_t i = 0; i < result.header.resource_entries; i ++)
        {
            DnsRecord resource = DnsRecord::read(buffer);
            result.resources.push_back(resource);
        }
    
        return result;
    }
    catch(std::runtime_error e)
    {
        throw e;
    }
}

void DnsPacket::write(BytePacketBuffer &buffer)
{
    header.questions = (uint16_t) questions.size();
    header.answers = (uint16_t) answers.size();
    header.authoritative_entries = (uint16_t) authorities.size();
    header.resource_entries = (uint16_t) resources.size();

    try {
        header.write(buffer);

        for (int i = 0; i < questions.size(); i ++)
            questions[i].write(buffer);
        for (int i = 0; i < answers.size(); i ++)
            answers[i].write(buffer);
        for (int i = 0; i < authorities.size(); i ++)
            authorities[i].write(buffer);
        for (int i = 0; i < resources.size(); i ++)
            resources[i].write(buffer);
    } catch (std::runtime_error e) {
        throw e;
    }

}

IPv4Addr DnsPacket::get_random_a()
{
    std::vector<IPv4Addr> a_answers;
    for (auto rec : answers)
    {
        if (rec.qtype == QueryType::A)
            a_answers.push_back(IPv4Addr(rec.value));
    }

    if (!a_answers.empty())
        return IPv4Addr(a_answers[std::rand() % a_answers.size()]);
    else 
        return IPv4Addr(0);
}

std::vector<std::pair<std::string, std::string>> DnsPacket::get_ns(std::string qname)
{
    std::vector<std::pair<std::string, std::string>> result;

    for (auto rec : authorities)
    {
        bool ok_ending;
        if (rec.domain.length() > qname.length())
            continue;
        else if (rec.domain.length() == qname.length())
            ok_ending = qname.compare(rec.domain) == 0;
        else 
            ok_ending = qname.compare(
                qname.length() - rec.domain.length(), 
                rec.domain.length(),
                rec.domain.c_str()
                ) == 0;

        if (rec.qtype == QueryType::NS && ok_ending){
            std::string string_from_bytes = get_string_from_byte_array(rec.value);
            result.push_back({rec.domain, string_from_bytes});
        }
    }

    return result;
}

IPv4Addr DnsPacket::get_resolved_ns(std::string qname)
{
    std::vector<std::pair<std::string, std::string>> nses = get_ns(qname);

    for (auto rec : this->resources)
    {
        bool ok_domain =  std::any_of(nses.begin(), nses.end(), [&](const auto& pair) {
                return pair.second == rec.domain;
            });
        if (rec.qtype == QueryType::A && ok_domain)
            return IPv4Addr(rec.value);
    }
    return IPv4Addr(0);
}

std::vector<std::string> DnsPacket::get_unresolved_ns(std::string qname)
{
    std::vector<std::string> result;
    std::vector<std::pair<std::string, std::string>> nses = get_ns(qname);

    for (auto& ns : nses)
    {
        result.push_back(ns.second);
    }

    return result;
}

std::string DnsPacket::to_string() {
    std::string result = "DnsPacket {\n";

    result += this->header.to_string();
    for (auto q : this->questions)
        result += q.to_string();
    result += "Answers:\n";
    for (auto a : this->answers)
        result += a.to_string();
    result += "Authorities:\n";
    for (auto a : this->authorities)
        result += a.to_string();
    result += "Resources:\n";
    for (auto r : this->resources)
        result += r.to_string();
    
    result += "}\n";

    return result;
}

/*######################################*/
/*---------[ Helper Functions ]---------*/
/*######################################*/

// Conversion funtions
std::vector<uint8_t> get_byte_array_from_string(std::string string)
{
    std::vector<uint8_t> byte_array = std::vector<uint8_t>(0);
    for (int i = 0; i < string.size(); i ++)
        byte_array.push_back(string[i]);
    return byte_array;
}

std::string get_string_from_byte_array(std::vector<uint8_t> byte_array)
{
    std::string result(byte_array.size(), '\0');

    for (int i = 0; i < byte_array.size(); i ++){
        result[i] = byte_array[i];
        // std::cout << byte_array[i] << " " << string << std::endl;
    }
    return result;
}