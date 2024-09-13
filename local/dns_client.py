from scapy.all import *
import sys
import random
import base64
import socket
import time
from loguru import logger as logging
import re

DOMAIN = "tunnel.mydomain.top"
DNS_SERVER = ("172.11.180.232", 53)
PACKET_SIZE = 1024


# loguru configurations
logging.remove()
logging.add(sys.stdout, colorize=True, format="<level>{level.icon}</level> <level>{message}</level>", level="TRACE")
logging.level(name='INFO', icon='[~]', color='<cyan><bold>')
logging.level(name='WARNING', icon='[!]', color='<yellow><bold>')
logging.level(name='DEBUG', icon='[*]', color='<blue><bold>')
logging.level(name='ERROR', icon='[X]', color='<red><bold>')
logging.level(name='SUCCESS', icon='[#]', color='<green><bold>')
   
def send_receive_reliable(sock, packet, to):
    sock.sendto(bytes(packet), to)
    
    for i in range(10): # we are trying 10 times
        try:
            data, address = sock.recvfrom(PACKET_SIZE)
            
            if address != to:
                raise Exception
            break
        except:
            time.sleep(2) # a little delay before trying again
            if i == 9:
                return None
            else:
                logging.warning("No response received! Resending packet.")
                sock.sendto(bytes(packet), to) # resending the packet
    return data

# Process a received DNS packet and returns the relevant data
# it also does some validation
def parse_data(packet_bytes):
    packet = DNS(packet_bytes)
    dns = packet.getlayer(DNS) 
    
    if dns is None or dns.ancount == 0:
        return (None, None)

    if dns.an.type != 5: # 5 stands for CNAME
        return (None, None)

    # data we expect looks like this: (number).(stream id).down.(domain)
    cname = dns.an.rdata.decode("utf-8")
    tokens = cname.split(".")
    try:
        result = (int(tokens[0]), int(tokens[1])) # (number, stream id)
    except ValueError as e:
        logging.error(f"Invalid CNAME: {e}")
        return (None, None)

    if result[0] == 0 or result[1] == 0:
        logging.error("No file with that name!")
        return (None, None)
    if tokens[2] != "down":
        logging.error("Wrong channel!")
        return (None, None)
    
    domain = ".".join(tokens[3:])[:-1]
    if domain != DOMAIN:
        logging.error("Wrong domain!")
        return (None, None)
    
    return result

# Function that handles data transfer logic
def transfer_data(server, qname):
    logging.info("Starting transfer!")
    transfer_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    transfer_socket.bind(("0.0.0.0", random.randint(1024, 2**16))) # ensuring the port is greater than 1024
    transfer_socket.settimeout(5)
    
    # dns packet
    question = DNS(id=RandShort(), rd=1, qd=DNSQR(qname=qname, qtype="A"))
    
    # sending the question and waiting for a response
    data = send_receive_reliable(transfer_socket, question, server)
    if data is None:
        logging.error("Data could no be received!")
        return -1
    
    # processing the response
    num_packets, stream_id = parse_data(data)
    if num_packets is None:
        logging.error("Data received is not valid!")
        return -1
    
    file_name = re.split(r"[\\/]", sys.argv[1])[-1] # in case we specify a path, the file name is the last token after a / or \
    file = open("client_data/" + file_name, "wb")
    
    packet_iteration = 1
    while packet_iteration <= num_packets:
        domain = str(packet_iteration) + "." + str(stream_id) + ".up." + DOMAIN # asking for a specific packet
        question = DNS(id=RandShort(), rd=1, qd=DNSQR(qname=domain, qtype="A"))
        data = send_receive_reliable(transfer_socket, question, server)

        if data is None:
            logging.warning(f"Data could not be received!")
            return -1
        else:
            # some validation would be good here, but I'm too lazy
            dns_packet = DNS(data)
            file.write(base64.b64decode(b''.join(dns_packet.an.rdata)))
            logging.success(f"Received packet {packet_iteration}.")
            packet_iteration += 1
        
    return 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        logging.debug(f"Usage: {sys.argv[0]} file_name")
        sys.exit(0)
        
    
    file_name = bytes(sys.argv[1].encode("utf-8"))
    stream_id = RandShort() # random Id for the stream
    
    # constructing the question
    # example: (base 32 encoded file name).(stream id).(up / down).(domain)
    # up meaning client to server flow of data
    # down meaning server to client flow of data
    qname = base64.b32encode(file_name).decode("utf-8") + "." + str(stream_id) + ".up." + DOMAIN 
    
    response = transfer_data(DNS_SERVER, qname)
    
    if response != 0:
        logging.error("An error occurred!")
