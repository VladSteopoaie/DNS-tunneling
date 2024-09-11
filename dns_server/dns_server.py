import socket
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
import sys
from loguru import logger as logging
from modules import dns_module

PACKET_SIZE = 1024
AROOT = "194.41.0.4" # a.root-servers.net
RECORDS = list()
RECORDS_FILE = "./modules/dns_records.txt"

# loguru configurations
logging.remove()
logging.add(sys.stdout, colorize=True, format="<level>{level.icon}</level> <level>{message}</level>", level="TRACE")
logging.level(name='INFO', icon='[~]', color='<cyan><bold>')
logging.level(name='WARNING', icon='[!]', color='<yellow><bold>')
logging.level(name='DEBUG', icon='[*]', color='<blue><bold>')
logging.level(name='ERROR', icon='[X]', color='<red><bold>')
logging.level(name='SUCCESS', icon='[#]', color='<green><bold>')

# Parses a file with records and stores them in a list
# record example: tunnel.mydomain.top IN NS ns.mydomain.top
def records_from_file(file):
    result = list()

    with open(file, "r") as f:
        for line in f.readlines():
            tokens = line.split() # dns record: ns.mydomain.top IN A 10.8.8.16
                                  # tokens: [domain, class, type, data]
            result.append(DNSRR(rrname=tokens[0], rclass=1, type=dns_module.type_number_from_string(tokens[2]), rdata=tokens[3]))

    return result

# Searches for a domain with a specific type within a vector of records
def search_in_records(qname, qtype, records):
    result = list()

    for record in records:
        domain = record.rrname.decode()
        if qname == domain: # looking for the same domain
            # looking for the same type or for NS type
            if qtype == record.type or record.type == 2: # NS has type == 2
                result.append(record)
        elif (qname[-len(domain):] == domain): # if the domain is ending whith the string we aim for an NS 
            if (record.type == 2):
                result.append(record)

    return result


# Performs a lookup on the RECORDS vector for a domain and a type
def local_lookup(qname, qtype):
    result = DNS(ancount=0, nscount=0, an=[], ns=[])
    records = search_in_records(qname, qtype, RECORDS)

    if len(records) == 0:
        result.rcode = dns_module.response_code_to_number("NXDOMAIN")
    else:
        for record in records:
            if qname == record.rrname.decode() and qtype == record.type: # if everything is matching we have an answer
                result.an.append(record)
                result.ancount += 1
            else: # otherwise there is an NS that we can ask
                result.ns.append(record)
                result.nscount += 1
    return result

# Queryes a DNS server for a specific domain and type
def lookup(qname, qtype, ns):
    # this socket is for listening for responses
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.bind(('', 43210)) # picking a random port to send the request

    packet = DNS(id=1234, rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    request_bytes = bytes(packet)

    try:
        # sending the request
        sock.sendto(request_bytes, (ns, 53))
        # receiving a response
        response_bytes, _ = sock.recvfrom(PACKET_SIZE)
        response = DNS(response_bytes)
        sock.close()
        return response
    except Exception as e:
        sock.close()
        raise RuntimeError(f"Some error occurred when sending/receiving data! {e}") from e

# Tries to resolve a domain name through recursive lookups
def recursive_lookup(qname, qtype):
    ns = "127.0.0.1" # first we try a local lookup
    response = None

    while True:
        try:
            if ns == "127.0.0.1":
                # first perform a local lookup to see if there is a local domain assigned
                logging.info(f"Attempting LOCAL lookup of {dns_module.type_number_to_string(qtype)} {qname}")
                response = local_lookup(qname, qtype)
            else:
                logging.info(f"Attempting ONLINE lookup of {dns_module.type_number_to_string(qtype)} {qname} with NS {ns}")
                response = lookup(qname, qtype, ns)
        except RuntimeError as e:
            logging.error(f"recursive_lookup error: {e}")
            raise e 

        if response.rcode == 3 and ns == "127.0.0.1": # no domain found locally
            ns = AROOT
            continue
        
        # success
        if response and response.rcode == 0 and response.ancount > 0:
            return response

        # domain not found
        if response.rcode == 3:  # NXDOMAIN
            return response
        
        # if we are here it means that there are some resources we can check
        new_ns = None
        for rr in response.ns: # looping through authorities records
            if rr.type == 2: # NS record
                new_ns = rr.rdata.decode()
                break
        
        if new_ns:
            # the dns packet might contain the addres of the NS already
            additional_ip = None
            for rr in response.ar: # looping through additional records
                if rr.type == 1 and new_ns == rr.rrname: # A record
                    additional_ip = rr.rdata
                    break

            if additional_ip:
                ns = additional_ip
            else:
                # if the dns packet does not contain the address of the NS we can find it by searching recursively
                try:
                    new_response = recursive_lookup(new_ns, dns_module.type_number_from_string('A'))
                    if new_response.ancount > 0:
                        ns = new_response.an[0].rdata.decode()
                except RuntimeError as e:
                    logging.error(f"recursive_lookup error: {e}")
                    raise e
        else:
            break

    return response


# The main function that handles a request
def handle_query(sock):
    data, addr = sock.recvfrom(PACKET_SIZE)
    request = DNS(data)

    if request.opcode == 0 and request.qr == 0:  # Standard query
        qname = request.qd.qname.decode()
        qtype = request.qd.qtype

        logging.info(f"Received query for {qname} type {qtype}")

        response = DNS(id=request.id, qr=1, rd=request.rd, ra=1, qd=request.qd)

        try:
            result = recursive_lookup(qname, qtype)
            response.rcode = result.rcode
            response.ancount = result.ancount
            response.nscount = result.nscount
            response.arcount = result.arcount
            response.an = result.an
            response.ns = result.ns
            response.ar = result.ar
            response.show()
            sock.sendto(bytes(response), addr)
        except RuntimeError as e:
            response.rcode = 2  # SERVFAIL
            

    logging.info("Query handeled!")
    

if __name__ == "__main__":
    if len(sys.argv) != 2:
        logging.debug(f"Usage: {sys.argv[0]} port")
        sys.exit(0)

    RECORDS = records_from_file(RECORDS_FILE)
    for rec in RECORDS:
        rec.show()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # start listening
        sock.bind(('0.0.0.0', int(sys.argv[1])))
    except Exception as e:
        logging.error(f"main error: {e}")
        sys.exit(0)

    logging.info(f"DNS server listening on port {sys.argv[1]}")

    while True:
        try:
            handle_query(sock)
        except KeyboardInterrupt:
            logging.warning("Shutting down DNS server")
            sock.close()
            exit()
        except RuntimeError as e:
            logging.error(f"main error: {e}")
            logging.warning("Shutting down DNS server")
            sock.close()
            exit()
