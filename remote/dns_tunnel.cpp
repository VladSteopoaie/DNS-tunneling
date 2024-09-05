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
#define DOMAIN_LEN 3

std::vector<std::string> split(const std::string &s, char delimiter)
{
	std::vector<std::string> tokens;
	std::string token;
	std::istringstream tokenStream(s);
	while (std::getline(tokenStream, token, delimiter))
	{
		tokens.push_back(token);
	}
	return tokens;
}

std::pair<int, std::string> parse_qname(std::string qname, bool decode = true)
{
	// request fomat: file_name_b32.3333.up.(nsserver.com) or other domain

	std::vector<std::string> tokens = split(qname, '.');

	std::string domain = "";
	size_t initalSize = tokens.size();
	for (size_t i = 0; i < DOMAIN_LEN && i < initalSize; i++)
	{
		domain = tokens.back() + "." + domain;
		tokens.pop_back();
	}

	if (domain.compare(DOMAIN) != 0 || tokens.back().compare("up") != 0)
	{
		std::cout << "Wrong domain or wrong stream!" << std::endl;
		std::cout << "Domain: " + domain << std::endl;
		std::cout << "Stream: " + tokens.back() << std::endl;
		return {-1, ""};
	}
	tokens.pop_back();

	int id = atoi(tokens.back().c_str());

	tokens.pop_back();
	std::string file_name = tokens.back();

	if (decode)
		file_name = base32_decode(file_name);

	return {id, file_name};
}

// Function to set a timeout on a socket
void setSocketTimeout(int socket, int timeoutSeconds)
{
	struct timeval timeout;
	timeout.tv_sec = timeoutSeconds;
	timeout.tv_usec = 0;

	if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
	{
		std::cerr << "Error setting receive timeout: " << strerror(errno) << std::endl;
	}

	if (setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
	{
		std::cerr << "Error setting send timeout: " << strerror(errno) << std::endl;
	}
}

// Function to clear a timeout on a socket
void clearSocketTimeout(int socket)
{
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
	{
		std::cerr << "Error clearing receive timeout: " << strerror(errno) << std::endl;
	}

	if (setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
	{
		std::cerr << "Error clearing send timeout: " << strerror(errno) << std::endl;
	}
}

int SendData(int socket, BytePacketBuffer res_buffer, struct sockaddr *source_addr, socklen_t source_addrlen)
{
	size_t datalen = res_buffer.getPos();
	const char *res_bytes = (char *)res_buffer.buf.data();

	ssize_t bytes_sent = sendto(socket, res_bytes, datalen, 0, source_addr, source_addrlen);

	if (bytes_sent <= 0)
	{

		std::cout << strerror(errno) << std::endl;
		std::cout << "An error occured when sending data!" << std::endl;
		return 1;
	}

	return 0;
}

DnsPacket ReceiveData(int socket, struct sockaddr *source_addr, socklen_t &source_addrlen)
{
	char req_bytes[BytePacketBuffer::packet_size];
	ssize_t bytes_read =
		recvfrom(socket, req_bytes, BytePacketBuffer::packet_size, 0, source_addr, &source_addrlen);

	if (bytes_read <= 0)
	{
		std::cout << "An error occured when receiving data!" << std::endl;

		return DnsPacket();
	}

	BytePacketBuffer req_buffer = BytePacketBuffer(req_bytes, (size_t)bytes_read);
	return DnsPacket::from_buffer(req_buffer);
}

int handle_connection(int socket)
{
	BytePacketBuffer res_buffer, last_buffer;
	struct sockaddr_storage source_addr;
	socklen_t source_addrlen = sizeof(source_addr);
	DnsPacket packet, request;

	try
	{
		clearSocketTimeout(socket);
		// Receiving data
		request = ReceiveData(socket, (struct sockaddr *)&source_addr, source_addrlen);
		if (request.header.id == 0)
			return 1;

		packet.header.id = request.header.id;
		packet.header.recursion_desired = false;
		packet.header.recursion_available = false;
		packet.header.response = true;

		if (request.questions.size() != 1)
		{
			std::cout << "Number of questions: " << std::to_string(request.questions.size()) << std::endl;
			return 1;
		}

		DnsQuestion question = request.questions.front();
		std::cout << "Received query:\n"
				  << question.to_string() << std::endl;

		// we need to know what kind of request we have
		std::pair<int, std::string> req_info = parse_qname(question.name);

		if (req_info.first <= 0)
		{
			std::cout << "Id is <= 0!" << std::endl;
			return 1;
		}
		// We received a query, firstly we have to send an acknowledgement
		// packet ack: n.3333.down.nsserver.com (where n is the
		// number of packets that we have to send back)

		std::ifstream file(req_info.second, std::ios::binary);

		if (!file.is_open())
		{
			// file not found, sending the packet with n == 0
			std::string ack = "0." + std::to_string(req_info.first) + ".down." + DOMAIN;

			packet.questions.push_back(question);
			packet.answers.push_back(DnsRecord(question.name, QueryType::CNAME, ack, 300));
			packet.header.answers = 1;
			packet.write(res_buffer);
			int r = SendData(socket, res_buffer, (struct sockaddr *)&source_addr, source_addrlen);

			if (r == 0)
			{
				std::cout << "File " + req_info.second + " not found!" << std::endl;
				std::cout << packet.answers.front().to_string() << std::endl;
				return 0;
			}
			else
			{
				return 1;
			}
		}

		file.seekg(0, std::ios::end);
		size_t file_size = (size_t)file.tellg();
		file.seekg(0, std::ios::beg);

		int num_packets = file_size / DnsRecord::txt_size + 1;

		DnsPacket last_sent = packet; // by knowing the last packet we sent we can make the server more robust
									  // if the connection is interupted we can resent the packet untill it's received
		// sending the confirmation + number of packets to expect
		std::string ack = std::to_string(num_packets) + "." + std::to_string(req_info.first) + ".down." + DOMAIN;
		last_sent.questions.push_back(question);
		last_sent.answers.push_back(DnsRecord(question.name, QueryType::CNAME, ack, 300));
		last_sent.header.answers = 1;
		last_sent.write(res_buffer);
		int r = SendData(socket, res_buffer, (struct sockaddr *)&source_addr, source_addrlen);
		if (r == 0)
		{
			std::cout << "Sent!" << std::endl;
			std::cout << last_sent.answers.front().to_string() << std::endl;
		}
		else
			return 1;
		
		last_buffer = res_buffer;
		res_buffer = BytePacketBuffer();


		// now we have to wait for confirmation and the client should ask for packet number 1
		int current_packet = 1;
		int err_count = 10; // this is the number of retried connections before considering the connection closed
		std::streampos previous_batch = 0;
		bool read_previous;
		bool resend = false; // this bool is to determine if the packet should be resent

		setSocketTimeout(socket, 4);

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
			DnsPacket req = ReceiveData(socket, (struct sockaddr *)&source_addr, source_addrlen);
			if (req.questions.size() != 1)
			{
				std::cout << "Error: question count is: " + std::to_string(req.questions.size()) << std::endl;
				resend = true;
				continue;
			}

			if (req.header.id == 0) // this means an error happened and nothing was received
			{
				resend = true;
				continue;
			}

			DnsQuestion q = req.questions.front();
			std::cout << "Received query:\n"
					  << q.to_string() << std::endl;

			std::pair<int, std::string> info = parse_qname(q.name, false);
			int id = info.first;
			// std::cout << info.first << " " << info.second << std::endl;
			int packet_number = atoi(info.second.c_str());

			if (req_info.first != id)
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

			previous_batch = file.tellg();
			std::string buffer(DnsRecord::txt_size, '\0');
			file.read(&buffer[0], DnsRecord::txt_size);

			std::size_t bytesRead = file.gcount();
			std::cout << "Read " << bytesRead << " bytes." << std::endl;
			buffer.resize(bytesRead);

			last_sent = packet;
			last_sent.questions.push_back(q);
			last_sent.answers.push_back(DnsRecord(q.name, QueryType::TXT, buffer, 300));
			last_sent.header.answers = 1;
			last_sent.write(res_buffer);
			r = SendData(socket, res_buffer, (struct sockaddr *)&source_addr, source_addrlen);

			if (r == 0)
			{
				std::cout << last_sent.answers.front().to_string() << std::endl;
				err_count = 10;
				current_packet += 1;
				last_buffer = res_buffer;
				res_buffer = BytePacketBuffer();
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

int main()
{
	int socket = PassiveSockUDP("53");
	std::cout << "Listening on 0.0.0.0:53 ..." << std::endl;

	srand(time(NULL));

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
