# helper functions to use for the dns server

# simple conversion functions
def type_number_from_string(string):
    match(string):
        case "A":
            return 1
        case "NS":
            return 2
        case "CNAME":
            return 5
        case "MX":
            return 15
        case "TXT":
            return 16
        case "AAAA":
            return 28
    return -1

def type_number_to_string(qtype):
    match(qtype):
        case 1:
            return "A"
        case 2:
            return "NS"
        case 5:
            return "CNAME"
        case 15:
            return "MX"
        case 16:
            return "TXT"
        case 28:
            return "AAAA"
    return -1

def response_code_to_number(string):
    match(string):
        case "NOERROR":
            return 0
        case "FORMERR":
            return 1
        case "SERVFAIL":
            return 2
        case "NXDOMAIN":
            return 3
        case "NOTIMP":
            return 4
        case "REFUSED":
            return 5
    return -1

# Gets all the records from the authorities section of the packet
# that either have the same domain as qname or qname ends with domain.
# Returns a list of tuples representing the domain and the NS value: (domain name, NS value of the domain)
def get_ns(packet, qname):
    result = list()
    if packet.nscount > 0:
        for record in packet.ns:
            domain = record.rrname.decode()
            ok_ending = False
            if (len(domain) > len(qname)): # if the domain name is larger there is no chance we meet the requirements
                continue 
            elif len(domain) == len(qname):
                ok_ending = (domain == qname)
            else: # len(domain) < len(qname)
                # check if qname ends with domain
                ok_ending = (qname[-len(domain):] == domain)
            
            if record.type == 2 and ok_ending: # NS is type 2
                result.append((domain, record.rdata.decode()))

    return result

# Gets all the NS records from the authorities section with the above function
# and searches through the additional resources section to find if the NS is resolved.
# Returns the first match it finds
def get_resolved_ns(packet, qname):
    nses = get_ns(packet, qname)

    if packet.arcount > 0:
        for record in packet.ar:
            domain = record.rrname.decode()

            # checks if the domain is within the authorities
            ok_domain = domain in [ns[1] for ns in nses] # ns = (domain, NS value) 

            if record.type == 1 and ok_domain: # A is type 1
                return record.rdata 
    return None

# Gets all the NS records from the authorities section with the get_ns function
# and returns the list of the NS names
def get_unresolved_ns(packet, qname):
    result = list()
    nses = get_ns(packet, qname)

    for ns in nses:
        result.append(ns[1]) # ns = (domain, NS value)
    
    return result