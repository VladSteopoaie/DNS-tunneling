/*################################*/
/*---------[ Disclaimer ]---------*/
/*################################*/

/**
 * This simple DNS server is a C++ adaptation from a Rust DNS server
 * You can see the server and the full documentation here: https://github.com/EmilHernvall/dnsguide/tree/master
 */

#include "dns_module.h"

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

IPv4Addr::IPv4Addr(std::string addr)
{
    char* ip = (char*) addr.c_str();

    char* token = strtok(ip, ".");
    int i = 0;

    while (token != NULL)
    {
        if (strcmp(token, "") == 0)
        {
            for (int j = 0; j < 4; j ++)
                bytes[j] = 0;
            break;
        }

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

IPv6Addr::IPv6Addr(std::vector<uint16_t> bytes)
{
    for (int i = 0; i < 8; i ++)
        this->bytes[i] = bytes[i];
}

IPv6Addr::IPv6Addr(std::string str)
{
    std::stringstream ss(str);
    ss << std::hex << std::setfill('0');
    uint16_t byte;
    int i = 0;
    while (ss >> std::setw(4) >> byte) {
        bytes[i] = byte;
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
        ss << std::setw(4) << static_cast<unsigned>(bytes[i]);
        if (i < 7) {
            ss << ":";
        }
    }
    return ss.str();
}

/*######################################*/
/*---------[ BytePacketBuffer ]---------*/
/*######################################*/

size_t BytePacketBuffer::packetSize = 1024;

BytePacketBuffer::BytePacketBuffer()
{
    buf = std::vector<uint8_t>();
    pos = 0;            
}

BytePacketBuffer::BytePacketBuffer(char* new_buf, size_t len)
{
    pos = 0;            
    buf = std::vector<uint8_t>();

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

// move the position over a specific number of steps
void BytePacketBuffer::step(size_t steps)
{
    pos += steps;
}

// change current position
void BytePacketBuffer::seek(size_t pos)
{
    this->pos = pos;
}

// read one byte from the buffer's position and change the position
uint8_t BytePacketBuffer::read_u8()
{
    if (pos >= packetSize)
        throw std::runtime_error("End of buffer 1!");
    
    uint8_t r = buf[pos];
    pos += 1;
    return r;
}

// get the current byte from buffer's position without changing the position
uint8_t BytePacketBuffer::get(size_t pos)
{
    if (pos >= packetSize)
        throw std::runtime_error("End of buffer 2!");
    return buf[pos];
}

// get a range of bytes from buf
uint8_t* BytePacketBuffer::get_range(size_t start, size_t len)
{
    if (start + len >= packetSize)
        throw std::runtime_error("End of buffer 3!");

    uint8_t* res = new uint8_t[len + 1];
    std::copy(buf.begin() + start, buf.begin() + start + len, res);
    res[len] = 0;
    return res;
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

void BytePacketBuffer::read_qname(char* outstr)
{
    outstr[0] = '\0';
    size_t lpos = this->pos;
    bool jumped = false;
    int max_jumps = 5;
    int jumps_performed = 0;

    std::string delim = "";

    while (true)
    {
        if (jumps_performed > max_jumps) 
            throw std::runtime_error("Limit of jumps exceeded!");

        uint8_t len = get(lpos);

        if ((len & 0xC0) == 0xC0)
        {
            if (!jumped) 
                seek(lpos + 2);
        
            // the offset for the jump has 2 bytes so I converted it to uint16_t
            uint16_t byte2 = (uint16_t) get(lpos + 1);
            uint16_t offset = ((((uint16_t) len) ^ 0xC0) << 8) | byte2;
            lpos = (size_t) offset;

            jumped = true;
            jumps_performed ++;
            continue;
        }
        else
        {
            lpos ++;

            if (len == 0)
                break;

            strcat(outstr, delim.c_str());

            char* str_buffer = (char*) get_range(lpos, (size_t) len);
            strcat(outstr, str_buffer);
            delim = ".";

            lpos += (size_t) len;
            delete[] str_buffer;
        }
    }

    if (!jumped) {
        seek(lpos);
    }

}

void BytePacketBuffer::write_u8(uint8_t val)
{
    if (pos >= packetSize)
        throw std::runtime_error("End of buffer! (write_u8)");

    if (pos < buf.size())
        buf[pos] = val;
    else 
        buf.push_back(val);
    pos += 1;
}

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

void BytePacketBuffer::write_qname(char* qname)
{
    char* p = strtok(qname, ".");
    while(p != NULL)
    {
        size_t len = strlen(p);
        if (len > 0x3f)
            throw std::runtime_error("Single label exceeds 63 characters of length!");

        write_u8((uint8_t) len);
        for (int i = 0; p[i]; i ++)
            write_u8((uint8_t) p[i]);

        p = strtok(NULL, ".");
    }
        
    write_u8(0);
}

void BytePacketBuffer::set_u8(size_t pos, uint8_t val)
{
    buf[pos] = val;
}

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

    recursion_desired = false;
    truncated_message = false;
    authoritative_answer = false;
    opcode = 0;
    response = false;

    rescode = ResultCode::NOERROR;
    checking_disabled = false;
    authed_data = false;
    z = false;
    recursion_available = false;

    questions = 0;
    answers = 0;
    authoritative_entries = 0;
    resource_entries = 0;
}

void DnsHeader::read(BytePacketBuffer &buffer)
{
    try {
        id = buffer.read_u16();
        //std::cout << id << std::endl;
        uint16_t flags = buffer.read_u16();
        //std::cout << flags << std::endl;
        uint8_t a = (uint8_t) (flags >> 8);
        uint8_t b = (uint8_t) (flags & 0xFF);

        recursion_desired = (a & (1 << 0)) > 0;
        truncated_message = (a & (1 << 1)) > 0;
        authoritative_answer = (a & (1 << 2)) > 0;
        opcode = (a >> 3) & 0x0F;
        response = (a & (a << 7)) > 0;

        rescode = ResultCodeFunc::from_num(b & 0x0F);
        checking_disabled = (b & (1 << 4)) > 0;
        authed_data = (b & (1 << 5)) > 0;
        z = (b & (1 << 6)) > 0;
        recursion_available = (b & (1 << 7)) > 0;

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
    result += "id: " + std::to_string(id) + ",\n";
    result += "questions: " + std::to_string(questions) + ",\n";
    result += "answers: " + std::to_string(answers) + ",\n";
    result += "authoritative_entries: " + std::to_string(authoritative_entries) + ",\n";
    result += "resource_entries: " + std::to_string(resource_entries) + ",\n";
    result += "opcode: " + std::to_string(static_cast<int>(opcode)) + ",\n";
    result += "rescode: " + std::to_string(static_cast<int>(rescode)) + ",\n";
    result += std::string("recursion_desired: ") + (recursion_desired ? "true" : "false") + ",\n";
    result += std::string("trucated_message: ") + (truncated_message ? "true" : "false") + ",\n";
    result += std::string("authoritative_answer: ") + (authoritative_answer ? "true" : "false") + ",\n";
    result += std::string("response: ") + (response ? "true" : "false") + ",\n";
    result += std::string("checking_disabled: ") + (checking_disabled ? "true" : "false") + ",\n";
    result += std::string("authed_data: ") + (authed_data ? "true" : "false") + ",\n";
    result += std::string("z: ") + (z ? "true" : "false") + ",\n";
    result += std::string("recursion_available: ") + (recursion_available ? "true" : "false") + ",\n";
    result += "}\n";
    return result;
}


/*#################################*/
/*---------[ DnsQuestion ]---------*/
/*#################################*/


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

std::string DnsQuestion::to_string()
{
    std::string s = "DnsQuestion { ";
    s += "name: " + name + ", ";
    s += "qtype: " + QueryTypeFunc::to_string(qtype) + ' ';
    s += "}";
    return s;
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


/*###############################*/
/*---------[ DnsRecord ]---------*/
/*###############################*/

const size_t DNSRecord::txt_size = 400;

DNSRecord::DNSRecord(std::string domain, QueryType qtype, std::string value, uint32_t ttl) 
{
    this->domain = domain;
    this->qtype = qtype;
    this->value = value;
    this->ttl = ttl;
}

DNSRecord::DNSRecord()
{
    this->domain = "";
    this->qtype = QueryType::UNKNOWN;
    this->value = "";
    this->ttl = 0;
}

DNSRecord DNSRecord::read(BytePacketBuffer &buffer)
{
    char* domain = new char[1024];

    try {
        buffer.read_qname(domain);
        QueryType qtype = QueryTypeFunc::from_num(buffer.read_u16());
        buffer.read_u16();
        uint32_t ttl = buffer.read_u32();
        size_t data_len = (size_t) buffer.read_u16();
    
        DNSRecord record;

        switch(qtype)
        {
            case QueryType::A:
            {
                uint32_t raw_addr = buffer.read_u32();
                IPv4Addr addr = IPv4Addr(raw_addr);
                record = DNSRecord(domain, qtype, addr.to_string(), ttl);
                break;
            }   
            case QueryType::NS:
            {
                char ns[1024];
                buffer.read_qname(ns);
                record = DNSRecord(domain, qtype, ns, ttl);
                break;
            }
            case QueryType::CNAME:
            {
                char cname[1024];
                buffer.read_qname(cname);
                record = DNSRecord(domain, qtype, cname, ttl);
                break;
            }
            case QueryType::MX:
            {
                uint16_t priority = buffer.read_u16();
                char mx[1024];
                buffer.read_qname(mx);
                record = DNSRecord(domain, qtype, std::to_string(priority) + ", " + mx, ttl);
                break;
            }
            case QueryType::AAAA:
            {
                std::vector<uint16_t> bytes;
                for (int i = 0; i < 8; i ++)
                    bytes.push_back(buffer.read_u16());

                IPv6Addr addr = IPv6Addr(bytes);
                record = DNSRecord(domain, qtype, addr.to_string(), ttl);
                break;
            }
            default:
            {
                char *value = (char*) buffer.get_range(0, data_len);
                buffer.step(data_len);
                record = DNSRecord(domain, qtype, value, ttl);
                delete[] value;
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

size_t DNSRecord::write(BytePacketBuffer &buffer)
{
    size_t start_pos = buffer.getPos();

    try{
        switch(qtype)
        {
            case QueryType::A:
            {
                buffer.write_qname((char*) domain.c_str());
                buffer.write_u16(QueryTypeFunc::to_num(QueryType::A));
                buffer.write_u16(1);
                buffer.write_u32(ttl);
                buffer.write_u16(4); // data_len

                IPv4Addr ip = IPv4Addr(value);
                buffer.write_u8(ip.bytes[0]);
                buffer.write_u8(ip.bytes[1]);
                buffer.write_u8(ip.bytes[2]);
                buffer.write_u8(ip.bytes[3]);
                break;
            }
            case QueryType::NS:
            {
                buffer.write_qname((char*) domain.c_str());
                buffer.write_u16(QueryTypeFunc::to_num(QueryType::NS));
                buffer.write_u16(1);
                buffer.write_u32(ttl);

                size_t pos = buffer.getPos();
                buffer.write_u16(0);
                buffer.write_qname((char*) value.c_str());

                size_t size = buffer.getPos() - (pos + 2);
                buffer.set_u16(pos, (uint16_t) size);
                break;
            }
            case QueryType::CNAME:
            {
                buffer.write_qname((char*) domain.c_str());
                buffer.write_u16(QueryTypeFunc::to_num(QueryType::CNAME));
                buffer.write_u16(1);
                buffer.write_u32(ttl);

                size_t pos = buffer.getPos();
                buffer.write_u16(0);
                buffer.write_qname((char*) value.c_str());

                size_t size = buffer.getPos() - (pos + 2);
                buffer.set_u16(pos, (uint16_t) size);
                break;
            }
            case QueryType::MX:
            {
                buffer.write_qname((char*) domain.c_str());
                buffer.write_u16(QueryTypeFunc::to_num(QueryType::MX));
                buffer.write_u16(1);
                buffer.write_u32(ttl);

                size_t pos = buffer.getPos();
                buffer.write_u16(0);

                char *priority = strtok((char*)value.c_str(), ", ");
                char *host = strtok(NULL, ", ");

                buffer.write_u16((uint16_t) atoi(priority));
                buffer.write_qname(host);

                size_t size = buffer.getPos() - (pos + 2);
                buffer.set_u16(pos, (uint16_t) size);
                break;
            }
            case QueryType::TXT:
            {
                buffer.write_qname((char*) domain.c_str());
                buffer.write_u16(QueryTypeFunc::to_num(QueryType::TXT));
                buffer.write_u16(1);
                buffer.write_u32(ttl);

                if (value.size() > txt_size) // if the message is smaller a padding of \n bytes will be added
                                        // the \n bytes will be replaced with null bytes in take_4_bytes
                    throw std::runtime_error("TXT size exceeded!");
                if (value.size() > 255){
                    buffer.write_u16(value.size() + 2);
                    buffer.write_u8(255);
                }
                else{
                    buffer.write_u16(value.size() + 1);
                    buffer.write_u8(value.size());
                }
                // std::cout << "Buffer size: " << value.size() << std::endl;
                for (int i = 0; i < value.size(); i ++){
                    if (i == 255)
                        buffer.write_u8(value.size() - 255);
                    buffer.write_u8((uint8_t) value[i]);
                }
                break;
            }
            case QueryType::AAAA:
            {
                buffer.write_qname((char*) domain.c_str());
                buffer.write_u16(QueryTypeFunc::to_num(QueryType::AAAA));
                buffer.write_u16(1);
                buffer.write_u32(ttl);
                buffer.write_u16(16);

                IPv6Addr addr = IPv6Addr(value);
                for (int i = 0; i < 8; i ++)
                    buffer.write_u16(addr.bytes[i]);

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

std::string DNSRecord::to_string()
{
    std::string s = QueryTypeFunc::to_string(qtype) + " { ";
    s += "domain: " + domain + ", ";
    s += "data: " + value + ", ";
    s += "ttl: " + std::to_string(ttl) + " ";
    s += "}";
    return s;
}

/*###############################*/
/*---------[ DnsPacket ]---------*/
/*##############################*/

DnsPacket::DnsPacket()
{
    header = DnsHeader();
    questions = std::vector<DnsQuestion>();
    answers = std::vector<DNSRecord>();
    authorities = std::vector<DNSRecord>();
    resources = std::vector<DNSRecord>();
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
            DNSRecord answer = DNSRecord::read(buffer);
            result.answers.push_back(answer);
        }

        for (size_t i = 0; i < result.header.authoritative_entries; i ++)
        {
            DNSRecord entry = DNSRecord::read(buffer);
            result.authorities.push_back(entry);
        }

        for (size_t i = 0; i < result.header.resource_entries; i ++)
        {
            DNSRecord resource = DNSRecord::read(buffer);
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
    std::vector<std::string> a_answers;

    for (auto rec : answers)
    {
        if (rec.qtype == QueryType::A)
            a_answers.push_back(rec.value);
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
        bool okEnding;
        if (rec.domain.length() > qname.length())
            continue;
        else if (rec.domain.length() == qname.length())
            okEnding = qname.compare(rec.domain) == 0;
        else 
            okEnding = qname.compare(
                qname.length() - rec.domain.length(), 
                rec.domain.length(),
                rec.domain.c_str()
                ) == 0;

        if (rec.qtype == QueryType::NS && okEnding){
            result.push_back({rec.domain, rec.value});
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

    for (auto& x : nses)
    {
        result.push_back(x.second);
    }

    return result;
}


/*######################################*/
/*---------[ Helper Functions ]---------*/
/*######################################*/

uint32_t take_4_bytes(std::string val, int index)
{
    int real_index = index * 4;
    uint32_t result = 0;

    for (int i = 0; i < 4; i ++)
    {
        if ((char) val[real_index + i] != '\n')  
            result = (char) val[real_index] << 8 * (3 - i);
    }

    return result;
}