import socket
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
import sys
from loguru import logger as logging

logging.remove()
logging.add(sys.stdout, colorize=True, format="<level>{level.icon}</level> <level>{message}</level>", level="TRACE")


# logging.level(name='TRACE', icon='>', color='<magenta><bold>')
logging.level(name='INFO', icon='[~]', color='<cyan><bold>')
logging.level(name='WARNING', icon='[!]', color='<yellow><bold>')
logging.level(name='DEBUG', icon='[*]', color='<blue><bold>')
logging.level(name='ERROR', icon='[X]', color='<red><bold>')
logging.level(name='SUCCESS', icon='[#]', color='<green><bold>')

def lookup(qname, qtype, server_addr):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 43210))

    packet = DNS(id=6666, rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    req_bytes = bytes(packet)

    try:
        sock.sendto(req_bytes, (server_addr, 53))
        res_bytes, _ = sock.recvfrom(512)
        response = DNS(res_bytes)
        return response
    except Exception as e:
        raise RuntimeError("Some error occurred when sending/receiving data!") from e
    finally:
        sock.close()

def recursive_lookup(qname, qtype):
    ns = "198.41.0.4"  # a.root-servers.net
    response = None
    while True:
        logging.info(f"Attempting lookup of {qtype} {qname} with ns {ns}")

        try:
            response = lookup(qname, qtype, ns)
        except RuntimeError as e:
            logging.error(f"Error: {e}")
            raise e

        if response and response.rcode == 0 and response.ancount > 0:
            return response

        if response.rcode == 3:  # NXDOMAIN
            return response
        
        new_ns = None
        if response.nscount > 0:
            for i in range(response.nscount):
                rr = response.ns[i]
                if rr.type == 2: # NS record
                    new_ns = rr.rdata.decode()
                    break
        
        if new_ns:
            additional_ip = None
            for i in range(response.arcount):
                rr = response.ar[i]
                if rr.type == 1: # A record
                    additional_ip = rr.rdata
                    break

            if additional_ip:
                ns = additional_ip
            else:
                try:
                    new_response = recursive_lookup(new_ns, 'A')
                    if new_response.ancount > 0:
                        ns = new_response.an[0].rdata
                except RuntimeError as e:
                    logging.error(f"Error: {e}")
                    raise e
        else:
            break

    return response

def handle_query(sock):
    data, addr = sock.recvfrom(512)
    request = DNS(data)
    if request.opcode == 0 and request.qr == 0:  # Standard query
        qname = request.qd.qname.decode()
        qtype = request.qd.qtype

        logging.info(f"Received query for {qname} type {qtype}")

        response = DNS(id=request.id, qr=1, rd=request.rd, ra=1, qd=request.qd)

        try:
            result = recursive_lookup(qname, qtype)
            response.rcode = result.rcode
            response.an = result.an
            response.ns = result.ns
            response.ar = result.ar
        except RuntimeError as e:
            response.rcode = 2  # SERVFAIL

        sock.sendto(bytes(response), addr)

    logging.info("Query handeled!")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        logging.debug(f"Usage: {sys.argv[0]} port")
        sys.exit(0)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('0.0.0.0', int(sys.argv[1])))
    except Exception as e:
        logging.error(f"Error: {e}")
        sys.exit(0)

    logging.info(f"DNS server running on port {sys.argv[1]}")

    while True:
        try:
            handle_query(sock)
        except KeyboardInterrupt:
            logging.warning("Shutting down DNS server")
            sock.close()
            exit()
        except Exception as e:
            logging.error(f"Error: {e}")
            logging.warning("Shutting down DNS server")
            sock.close()
            exit()
