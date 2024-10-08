from scapy.all import *
import socket
import struct
import time
import base64
from loguru import logger as logging

DOMAIN = "tunnel.mydomain.top."
DOMAIN_LEN = 3 # 3 tokens for the domain as it is (tunnel, mydomain and top)
DNS_PORT = 53
RESOURCES_DIR = "/etc/tunnel/"
READING_SIZE = 300 # the TXT size on the server is 400 bytes, since we are encoding the text with base64
				   # for each 3 bytes of data we get 4 bytes of encoded data
PACKET_SIZE = 1024

# loguru configurations
logging.remove()
logging.add(sys.stdout, colorize=True, format="<level>{level.icon}</level> <level>{message}</level>", level="TRACE")
logging.level(name='INFO', icon='[~]', color='<cyan><bold>')
logging.level(name='WARNING', icon='[!]', color='<yellow><bold>')
logging.level(name='DEBUG', icon='[*]', color='<blue><bold>')
logging.level(name='ERROR', icon='[X]', color='<red><bold>')
logging.level(name='SUCCESS', icon='[#]', color='<green><bold>')


# Parses a specialy crafted domain and returns the important data (the stream id, the data)
# request fomat: (data).(stream id).(stream type).(domain)
# data -> it can be a file name encoded in base32 or a number
# stream id -> the id of the stream given by the client
# stream type -> "up" for (client -> server), "down" for (server -> client)
# domain -> the domain of the nameserver
def parse_qname(qname, decode=True):
    try:
        tokens = qname.split('.')

        domain = ".".join(tokens[-DOMAIN_LEN - 1:])
        tokens = tokens[:-DOMAIN_LEN - 1]

        # validation
        if domain != DOMAIN or tokens[-1] != 'up':
            logging.error(f"Wrong domain or wrong stream! Domain: {domain}, Stream: {tokens[-1]}")
            return -1, ""

        tokens.pop() # stream id
        
        try:
            stream_id = int(tokens.pop())
        except ValueError as e:
            logging.error(f"Wrong stream id! {e}")
            return -1, ""
            
        file_name = tokens.pop()

        if decode:
            file_name = base64.b32decode(file_name).decode('utf-8')

        return stream_id, file_name
    except:
        return -1, ""

def send_data(sock, packet_bytes, source_addr):
    try:
        bytes_sent = sock.sendto(packet_bytes, source_addr)
        if bytes_sent <= 0:
            logging.error("An error occurred when sending data!")
            return -1
    except:
        return -1
    return 0

def receive_data(sock):
    try:
        request_bytes, source_addr = sock.recvfrom(PACKET_SIZE)
        request = DNS(request_bytes)
        return request, source_addr
    except socket.timeout:
        logging.error("Socket timed out!")
        return None, None

def handle_connection(sock):
    # receiving data
    sock.settimeout(None)
    request, source_addr = receive_data(sock)
    if request is None:
        logging.warning("No request was received!")
        return -1

    # building the response packet
    response = DNS(id=request.id, qr=1, aa=0, rd=0, ra=0, qdcount=1)

    if request.qdcount != 1: # validating there is only one question
        logging.warning(f"Number of questions: {request.qdcount}")
        return -1

    request_question = request.qd[0]
    logging.info(f"Received query: {request_question.qname.decode()}")


    stream_id, file_name = parse_qname(request_question.qname.decode())
    if stream_id <= 0: # usualy it means that the question was invalid
        logging.warning("Stream ID is <= 0! Probably question is invalid.")
        return -1

    try:
        # We received a query, firstly we have to send an acknowledgement
		# Acknowledgement example: n.3333.down.nsserver.com (where n is the
		# number of packets that we have to send back to complete a file transfer)
        with open(RESOURCES_DIR + file_name, 'rb') as file:
            file_size = len(file.read())
            file.seek(0)

            # calculation the total number of packets that need to be transfered
            num_packets = file_size // READING_SIZE + (0 if file_size % READING_SIZE == 0 else 1)

            # building and sending the acknowledgement
            ack = f"{num_packets}.{stream_id}.down.{DOMAIN}"
            response.qd = request_question
            response.qdcount = 1
            response.an = DNSRR(rrname=request_question.qname, type='CNAME', rdata=ack)
            response.ancount = 1
            
            if send_data(sock, bytes(response), source_addr) != 0:
                raise Exception("Error when sending data!")
            
            # now we have to wait for confirmation and the client should ask for packet number 1
            current_packet = 1
            err_count = 10 # this is the number of retried connections before considering the connection closed
            previous_batch = 0
            read_previous = False # read the preavious batch instead of the current one if true
            resend = False # this bool is to determine if the packet should be resent

            sock.settimeout(4)

            while current_packet <= num_packets and err_count > 0:
                if resend == True:
                    r = send_data(sock, res_buffer, source_addr)
                    if r != 0:
                        return -1
                    err_count -= 1
                    resend = False
                    continue
                
                # waiting for a packet request: (packet number).(stream id).up.(domain)
                request, source_addr = receive_data(sock)
                if request is None or request.qdcount != 1:
                    resend = True
                    continue
                
                # same processing steps
                question = request.qd[0]
                logging.info(f"Received query: {question.qname.decode()}")

                stream_id_local, packet_number = parse_qname(question.qname.decode(), False)
                if stream_id_local == -1:
                    resend = True 
                    continue
                packet_number = int(packet_number)

                # validating the packet received
                if stream_id_local != stream_id or packet_number == 0:
                    logging.warning("Packet number is 0!")
                    resend = True
                    continue
                
                if current_packet != packet_number:
                    if packet_number == current_packet - 1:
                        current_packet = packet_number
                        read_previous = True
                        logging.warning(f"Previous packet requested!")
                    else:
                        logging.error(f"Wrong packet number! Exptected packet {current_packet}, received value {packet_number}")
                        return -1

                if read_previous:
                    file.seek(previous_batch)
                previous_batch = file.tell()

                # building the response with the necessary data
                buffer = file.read(READING_SIZE)
                response.qd = [question]
                response.an = [DNSRR(rrname=question.qname, type='TXT', rdata=base64.b64encode(buffer))]
                response.ancount = 1

                send_data(sock, bytes(response), source_addr)

                # reseting values
                logging.success(f"Packet {current_packet} sent!")
                err_count = 10
                current_packet += 1
                read_previous = False

            if err_count == 0:
                logging.warning("Lost connection!")
                return -1

    except FileNotFoundError:
        ack = f"0.{stream_id}.down.{DOMAIN}"
        response.qd = [request_question]
        response.an = [DNSRR(rrname=request_question.qname, type='CNAME', rdata=ack)]
        response.ancount = 1

        send_data(sock, bytes(response), source_addr)
        logging.warning(f"File {file_name} not found!")
        return 0
    except Exception as e:
        logging.error(f"handle_connection: {e}")
        return -1

    return 0


if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', DNS_PORT))
    logging.info(f"Listening on 0.0.0.0:{DNS_PORT} ...")

    while True:
        r = handle_connection(sock)
        if r != 0:
            logging.error("An error occurred!")
        else:
            logging.success("Handled successfully!")
