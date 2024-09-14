#include "modules/connectsock.h"
#include "modules/dns_module.h"
#include "modules/encoders.h"
#include <cstddef>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <fstream>

#define DOMAIN "tunnel.mydomain.top."
#define DOMAIN_LEN 3 // 3 tokens for the domain as it is (tunnel, mydomain and top)
#define READING_SIZE 300 // the TXT size on the server is 400 bytes, since we are encoding the text with base64
						 // for each 3 bytes of data we get 4 bytes of encoded data
#define RESOURCES_DIR "/etc/tunnel/"

// Splits a string into a vector of strings
std::vector<std::string> split(const std::string str, char delimiter)
{
	std::vector<std::string> tokens;
	std::string token;
	std::istringstream tokenStream(str);
	while (std::getline(tokenStream, token, delimiter))
	{
		tokens.push_back(token);
	}
	return tokens;
}

// Parses a specialy crafted domain and returns the important data (the stream id, the data)
// request fomat: (data).(stream id).(stream type).(domain)
// data -> it can be a file name encoded in base32 or a number
// stream id -> the id of the stream given by the client
// stream type -> "up" for (client -> server), "down" for (server -> client)
// domain -> the domain of the nameserver
std::pair<int, std::string> parse_qname(std::string qname, bool decode = true)
{
	std::vector<std::string> tokens = split(qname, '.');

	std::string domain = "";
	size_t initial_size = tokens.size();
	for (size_t i = 0; i < DOMAIN_LEN && i < initial_size; i++) // building the domain
	{
		domain = tokens.back() + "." + domain;
		tokens.pop_back();
	}

	if (domain.compare(DOMAIN) != 0 || tokens.back().compare("up") != 0) // verifying communication channel
	{
		std::cout << "Wrong domain or wrong stream!" << std::endl;
		std::cout << "Domain: " + domain << std::endl;
		std::cout << "Stream: " + tokens.back() << std::endl;
		return {-1, ""};
	}
	tokens.pop_back(); // stream

	int id = atoi(tokens.back().c_str());
	tokens.pop_back();

	std::string data = tokens.back();

	if (decode)
		data = base32_decode(data);

	return {id, data};
}

// Sends the bytes from the buffer to the specified address
int SendData(int socket, BytePacketBuffer response_buffer, struct sockaddr *source_addr, socklen_t source_addrlen)
{
	const size_t response_size = response_buffer.getPos();

	ssize_t bytes_sent = sendto(socket, response_buffer.buf.data(), response_size, 0, source_addr, source_addrlen);

	if (bytes_sent <= 0)
	{

		std::cout << strerror(errno) << std::endl;
		std::cout << "An error occured when sending data!" << std::endl;
		return 1;
	}

	return 0;
}

// Receive data into the buffer from a specified address
DnsPacket ReceiveData(int socket, struct sockaddr *source_addr, socklen_t &source_addrlen)
{
	char request_bytes[BytePacketBuffer::packet_size];
	ssize_t bytes_read =
		recvfrom(socket, request_bytes, BytePacketBuffer::packet_size, 0, source_addr, &source_addrlen);

	if (bytes_read <= 0)
	{
		std::cout << "An error occured when receiving data!" << std::endl;

		return DnsPacket();
	}

	BytePacketBuffer request_buffer = BytePacketBuffer(request_bytes, (size_t)bytes_read);
	return DnsPacket::from_buffer(request_buffer);
}

// main function that handles all logic when a request is made
int handle_connection(int socket)
{
	DnsPacket packet, request;
	BytePacketBuffer response_buffer, last_buffer;
	struct sockaddr_storage source_addr; // storing where the data is coming from so we know where to send it back
	socklen_t source_addrlen = sizeof(source_addr);

	try
	{
		if (clear_socket_timeout(socket) < 0)
			std::cout << "Warninig: clearing socket timeout failed!";

		// receiving data
		request = ReceiveData(socket, (struct sockaddr *)&source_addr, source_addrlen);

		if (request.header.id == 0)
			return 1;

		// building response header
		packet.header.id = request.header.id;
		packet.header.recursion_desired = false;
		packet.header.recursion_available = false;
		packet.header.response = true;

		DnsQuestion request_question = request.questions.front();
		std::cout << "Received query:\n"
				  << request_question.to_string() << std::endl;

		// we need to know what kind of request we have
		// first -> id
		// second -> data
		std::pair<int, std::string> request_info = parse_qname(request_question.name);
		int stream_id = request_info.first;
		std::string file_name = request_info.second;

		if (stream_id <= 0)
		{
			std::cout << "Stream id is <= 0!" << std::endl;
			return 1;
		}

		// We received a query, firstly we have to send an acknowledgement
		// Acknowledgement example: n.3333.down.nsserver.com (where n is the
		// number of packets that we have to send back to complete a file transfer)

		std::ifstream file(RESOURCES_DIR + file_name, std::ios::binary); // opening the file requested by the client

		if (!file.is_open()) // the file requested cannot be accessed
		{
			packet.questions.push_back(request_question);

			// file not found, sending the packet with n == 0
			std::vector<uint8_t> ack = get_byte_array_from_string("0." + std::to_string(stream_id) + ".down." + DOMAIN);
			packet.answers.push_back(DnsRecord(request_question.name, QueryType::CNAME, ack, 300));
			packet.header.answers = 1;
			packet.write(response_buffer);
			int r = SendData(socket, response_buffer, (struct sockaddr *)&source_addr, source_addrlen);

			if (r == 0)
			{
				std::cout << "File " + file_name + " not found!" << std::endl;
				return 0;
			}
			else
			{
				return 1;
			}
		}

		// if we are here a file was found on the system

		// getting file size
		file.seekg(0, std::ios::end);
		const size_t file_size = (size_t)file.tellg();
		file.seekg(0, std::ios::beg);

		// we need to know the number of packets to send back in order to successfully transfer the file
		const int num_packets = file_size / READING_SIZE + (file_size % READING_SIZE == 0 ? 0 : 1);

		DnsPacket last_sent = packet; // by knowing the last packet we sent we can make the server more robust
									  // if the connection is interupted we can resent the packet untill it's received
		last_sent.questions.push_back(request_question);
		
		// sending the confirmation + number of packets to expect
		std::vector<uint8_t> ack = get_byte_array_from_string(std::to_string(num_packets) + "." + std::to_string(stream_id) + ".down." + DOMAIN);
		last_sent.answers.push_back(DnsRecord(request_question.name, QueryType::CNAME, ack, 300));
		last_sent.header.answers = 1;
		last_sent.write(response_buffer);
		int r = SendData(socket, response_buffer, (struct sockaddr *)&source_addr, source_addrlen);
		if (r == 0)
		{
			std::cout << "Confirmation sent! Number of packets: " << num_packets << std::endl;
			std::cout << last_sent.answers.front().to_string() << std::endl;
		}
		else
			return 1;
		
		last_buffer = response_buffer;
		response_buffer = BytePacketBuffer();


		// now we have to wait for confirmation and the client should ask for packet number 1
		int current_packet = 1;
		int err_count = 10; // this is the number of retried connections before considering the connection closed
		std::streampos previous_batch = 0;
		bool read_previous; // read the preavious batch instead of the current one if true
		bool resend = false; // this bool is to determine if the packet should be resent

		set_socket_timeout(socket, 4);

		while (current_packet <= num_packets && err_count > 0)
		{
			if (resend == true) // resending the packet if the condition is true
			{
				int r = SendData(socket, last_buffer, (struct sockaddr *)&source_addr, source_addrlen);
				if (r != 0)
					return -1;
				err_count--;
				resend = false;
				continue;
			}

			read_previous = false;
			DnsPacket request = ReceiveData(socket, (struct sockaddr *)&source_addr, source_addrlen);
			if (request.questions.size() != 1)
			{
				std::cout << "Error: question count is: " + std::to_string(request.questions.size()) << std::endl;
				resend = true;
				continue;
			}

			if (request.header.id == 0) // this means an error happened and nothing was received
			{
				resend = true;
				continue;
			}

			DnsQuestion question = request.questions.front();
			std::cout << "Received query:\n"
					  << question.to_string() << std::endl;

			std::pair<int, std::string> info = parse_qname(question.name, false);
			int stream_id_local = info.first;
			int packet_number = atoi(info.second.c_str());

			if (stream_id != stream_id_local)
			{
				std::cout << "Error: wrong id!" << std::endl;
				resend = true;
				continue;
			}
			
			if (packet_number == 0)
			{
				std::cout << "Packet number is 0!" << std::endl;
				resend = true;
				continue;
			}

			if (current_packet != packet_number)
			{
				std::cout << "Error: wrong packet number! " << packet_number << std::endl;
				if (packet_number == current_packet - 1) // if the packet requested is the current_packet - 1 we will resend the packet
				{
					current_packet = packet_number;
					read_previous = true;
				}
				else
					return -1;
			}

			if (read_previous == true)
				file.seekg(previous_batch);

			previous_batch = file.tellg(); // storing the possition of the last batch that was read
			std::string buffer(READING_SIZE, '\0');
			file.read(&buffer[0], READING_SIZE); // reading file content into the buffer

			size_t bytes_read = file.gcount();
			std::cout << "Read " << bytes_read << " bytes." << std::endl;
			buffer.resize(bytes_read);

			last_sent = packet;
			last_sent.questions.push_back(question);
			
			// this will be used to store the string into a dns record
			std::vector<uint8_t> bytes_from_string = get_byte_array_from_string(base64_encode(buffer)); // we also want to encode the content in base64

			last_sent.answers.push_back(DnsRecord(question.name, QueryType::TXT, bytes_from_string, 300));
			last_sent.header.answers = 1;
			last_sent.write(response_buffer);

			r = SendData(socket, response_buffer, (struct sockaddr *)&source_addr, source_addrlen);

			if (r == 0)
			{
				std::cout << last_sent.answers.front().to_string() << std::endl;
				err_count = 10;
				current_packet += 1;
				last_buffer = response_buffer;
				response_buffer = BytePacketBuffer();
			}
			else
			{
				return 1;
			}
		}

		if (err_count == 0)
		{
			std::cout << "Lost connection!" << std::endl;
			return -1;
		}
	}
	catch (std::runtime_error e)
	{
		std::cout << e.what() << std::endl;
		return 1;
	}
	return 0;
}

int main(int argc, char** argv)
{

	int socket = passive_sock_udp("53"); // DNS port 53
	if (socket < 0)
	{
		return -1;
	}
	std::cout << "Listening on 0.0.0.0:53 ..." << std::endl;

	while (true)
	{
		int r = handle_connection(socket);
		if (r != 0)
			std::cout << "An error occurred!" << std::endl;
		else
			std::cout << "Handled successfully!" << std::endl;
	}

	return 0;
}
