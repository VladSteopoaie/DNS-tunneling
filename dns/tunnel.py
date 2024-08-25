import socket
import struct
import time
import base64
from scapy.all import *

DOMAIN = "tunnel.proiect-retele.live."
DOMAIN_LEN = 3
DNS_PORT = 53

def parse_qname(qname, decode=True):
    try:
        tokens = qname.split('.')

        domain = ".".join(tokens[-DOMAIN_LEN - 1:])
        # print("Domain:", domain)
        tokens = tokens[:-DOMAIN_LEN - 1]
        # print("Tokens:", *tokens)
        if domain != DOMAIN or tokens[-1] != 'up':
            print(f"Wrong domain or wrong stream! Domain: {domain}, Stream: {tokens[-1]}")
            return -1, ""

        tokens.pop()
        file_id = int(tokens.pop())
        file_name = tokens.pop()

        if decode:
            file_name = base64.b32decode(file_name).decode('utf-8')

        return file_id, file_name
    except:
        return -1, ""

def send_data(sock, res_buffer, source_addr):
    try:
        bytes_sent = sock.sendto(res_buffer, source_addr)
        if bytes_sent <= 0:
            print("An error occurred when sending data!")
            return 1
    except:
        return 1
    return 0

def receive_data(sock):
    try:
        req_bytes, source_addr = sock.recvfrom(512)
        req = DNS(req_bytes)
        return req, source_addr
    except socket.timeout:
        print("Socket timed out!")
        return None, None

def handle_connection(sock):
    sock.settimeout(None)
    req, source_addr = receive_data(sock)
    if req is None:
        return 1

    packet = DNS(id=req.id, qr=1, aa=0, rd=0, ra=0, qdcount=1)

    if req.qdcount != 1:
        print(f"Number of questions: {req.qdcount}")
        return 1
    packet.show()
    question = req.qd[0]
    print(f"Received query: {question.qname.decode()}")

    req_info = parse_qname(question.qname.decode())
    if req_info[0] <= 0:
        print("Id is <= 0!")
        return 1

    file_id, file_name = req_info

    try:
        with open(file_name, 'rb') as file:
            file_size = len(file.read())
            file.seek(0)

            num_packets = file_size // 255 + 1

            ack = f"{num_packets}.{file_id}.down.{DOMAIN}"
            packet.qd = [question]
            packet.an = [DNSRR(rrname=question.qname, type='CNAME', rdata=ack)]
            packet.ancount = 1

            res_buffer = bytes(packet)
            
            if send_data(sock, res_buffer, source_addr) != 0:
                raise Exception("")
            
            print("Sent:", ack)

            current_packet = 1
            err_count = 10
            previous_batch = 0
            read_previous = False
            resend = False

            sock.settimeout(4)

            while current_packet <= num_packets and err_count > 0:
                if resend:
                    send_data(sock, res_buffer, source_addr)    
                    err_count -= 1
                    resend = False
                    continue

                req, source_addr = receive_data(sock)
                if req is None or req.qdcount != 1:
                    resend = True
                    continue

                q = req.qd[0]
                print(f"Received query: {q.qname.decode()}")

                info = parse_qname(q.qname.decode(), False)
                if info[0] == -1:
                    resend = True 
                    continue
                packet_number = int(info[1])

                if info[0] != file_id or packet_number == 0:
                    print("Packet number is 0!")
                    resend = True
                    continue
                
                if current_packet != packet_number:
                    print("Wrong packet number!")
                    if packet_number == current_packet - 1:
                        current_packet = packet_number
                        read_previous = True
                    else:
                        return -1

                if read_previous:
                    file.seek(previous_batch)
                previous_batch = file.tell()

                buffer = file.read(255)
                packet.qd = [q]
                packet.an = [DNSRR(rrname=q.qname, type='TXT', rdata=buffer)]
                packet.ancount = 1

                res_buffer = bytes(packet)
                send_data(sock, res_buffer, source_addr)

                print("Sent:", buffer.decode(errors='ignore'))
                err_count = 10
                current_packet += 1
                read_previous = False

            if err_count == 0:
                print("Lost connection!")
                return -1

    except FileNotFoundError:
        ack = f"0.{file_id}.down.{DOMAIN}"
        packet.qd = [question]
        packet.an = [DNSRR(rrname=question.qname, type='CNAME', rdata=ack)]
        packet.ancount = 1

        res_buffer = bytes(packet)
        send_data(sock, res_buffer, source_addr)
        print(f"File {file_name} not found!")
        return 0

    return 0

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('10.0.0.101', DNS_PORT))

    while True:
        r = handle_connection(sock)
        if r != 0:
            print("An error occurred!")
        else:
            print("Handled successfully!")

if __name__ == "__main__":
    main()
