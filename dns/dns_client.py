from scapy.all import *
import sys
import random
import base64
import socket
import time

DOMAIN = "retele.littlecloud.engineer"
   
def send_receive_reliable(sock, packet, to):
    sock.sendto(bytes(packet), to)
    
    for i in range(10): # we are trying 3 times
        try:
            data, address = sock.recvfrom(512)
            
            if address != to:
                raise Exception
            break
        except:
            time.sleep(3)
            if i == 9:
                return None
            else:
                sock.sendto(bytes(packet), to)
    return data

# (num_packets, id) for CNAME
# (id_packet, base64) for TXT
def parse_data(packet_bytes):
    packet = DNS(packet_bytes)
    dns = packet.getlayer(DNS) 
    
    if dns is None or dns.an.type != 5:
        return None

    cname = dns.an.rdata.decode("utf-8")
    tokens = cname.split(".")
    result = (int(tokens[0]), int(tokens[1]))
    
    if result[0] == 0 or result[1] == 0:
        print("No file with that name!")
        return None 
    if tokens[2] != "down":
        print("Wrong channel!")
        return None
    
    domain = ".".join(tokens[3:])[:-1]
    if domain != DOMAIN:
        print("Wrong domain!")
        return None
    
    return result

def start_transfer(server, qname):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", RandShort()))
    sock.settimeout(4)
    
    question = DNS(id=RandShort(), rd=1, qd=DNSQR(qname=qname, qtype="A"))
    
    data = send_receive_reliable(sock, question, dns_server)
    
    if data is None:
        print("Data could no be received!")
        question.show()
        return 1
    
    parsed_data = parse_data(data) 
    if parsed_data is None:
        print("Data received is not valid!")
        return 1
    
    file_name = sys.argv[1]
    file = open("client_data/" + file_name, "wb")
    
    i = 1
    while i <= parsed_data[0]:
        domain = str(i) + "." + str(parsed_data[1]) + ".up." + DOMAIN 
        question = DNS(id=RandShort(), rd=1, qd=DNSQR(qname=domain, qtype="A"))
        data = send_receive_reliable(sock, question, dns_server)
        p = DNS(data)
        p.show()
            
        if data is None:
            print("Data could not be received! Repeating step", i)
            return 1
        else:
            file.write(b''.join(p.an.rdata))
            i += 1
        

    return 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Please provide the name of the file.")
        sys.exit(0)
        
    
    dns_server = ("89.35.251.30", 53)
    file_name = bytes(sys.argv[1].encode("utf-8"))
    id = RandShort()
    
    qname = base64.b32encode(file_name).decode("utf-8") + "." + str(id) + ".up." + DOMAIN 
    
    response = start_transfer(dns_server, qname)
    
    if response != 0:
        print("An error occurred!")
