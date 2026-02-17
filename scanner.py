"""
Filename: scanner.py
Author: Owen Ross
Date Created: 01/30/2026
Last Modified: 02/16/2026
Description: Performs a basic port scan of the specified destinaton
Dependancies: socket, sys, random, logging, struct
"""

import socket, sys, random, logging
from struct import *

# Configuring the logging
logging.basicConfig(filename="scan_result.log",
                    format='%(asctime)s %(levelname)s: %(message)s',
                    filemode='w')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Getting IP address from command line
src_address = "10.0.2.15"
dst_address = sys.argv[1]

# Initilizing the list that will hold all of the open ports that were found
open_ports = []

def checksum(data):
	"""
	Calculate the TCP checksum
	
	Args:
		data (byte object): Combined pseudo and TCP header as a byte object
	
	Return:
		byte object: The calculated checksum for the TCP header

	"""
	# Checking if the last pair of bytes is incomplete, if it is then pad the data with an extra byte
	if len(data) % 2 != 0:
		data += b'\x00'

	s = 0
	# loop reading the puesudo header data 2 bytes at a time
	for i in range(0, len(data), 2):
		# Combining 2 bytes into a 16 bit word, then changing the 16 bit word into big endian format
		w = data[i] << 8 | data[i+1]
		s += w
	
	# Combine all of the bytes together, if there is an overflow then wrap the overflow to the lower 16 bits
	s = (s >> 16) + (s & 0xffff)

	# Ensuring the final result fits into a 16 bit format, since the previous line can still produce an overflow
	s += s >> 16
    
	# Inverting all of the bits and return the checksum
	return ~s & 0xffff

# Creating the socket that will send the IP packet
send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

# Creating the socket that will recieve the response to the SYN packet that was sent
recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
recv_sock.settimeout(5)

''' Setting all of the values for the TCP header '''
# Setting the TCP source port by generating a random number between 49152 and 65535, which are used for temporary connections
tcp_src_port = random.randint(49152, 65535)
# Setting the sequence number by generating a random number between 100 and 10000
tcp_seq_num = random.randint(100, 10000)
tcp_ack_num = 0
tcp_off = 5 << 4 # 5 * 4 = 20 bytes, shifting the 5 bits to the left 4 times to get 20
'''Setting all of the TCP flags'''
tcp_fin = 0
tcp_syn = 1 # Only setting the SYN flag because this is a SYN packet
tcp_rst = 0
tcp_psh = 0
tcp_ack = 0
tcp_urg = 0
tcp_ece = 0
tcp_cwr = 0
# Combining all of the TCP flags together
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5) + (tcp_ece << 6) + (tcp_cwr << 7)

tcp_window = socket.htons(5840) # Maximum window size
tcp_checksum_placeholder = 0
tcp_urg_pointer = 0
    
''' Setting all of the values for the IP header '''
ip_ver = (4 << 4) + 5 # Setting the version for IPv4
ip_tos = 0
ip_id = random.randint(100, 10000) # ID of the IP packet
ip_flags_fo = 0
ip_ttl = 64
ip_pro = socket.IPPROTO_TCP # Protocal ID for TCP
ip_checksum = 0
ip_src_addr = socket.inet_aton(src_address)
ip_dst_addr = socket.inet_aton(dst_address)

# Setting the values for the pseudo header to calculate the checksum
pseudo_src_addr = socket.inet_aton(src_address)
pseudo_dst_addr = socket.inet_aton(dst_address)
pseduo_placeholder = 0
pseudo_proto = socket.IPPROTO_TCP

print("----------Starting scan----------")
logger.info("Scan started")

for tcp_dst_port in range(1,1025):

	# Converting all of the TCP header values into byte objects, in order to be sent to the destination
	tcp_header = pack('!HHLLBBHHH', tcp_src_port, tcp_dst_port, tcp_seq_num, tcp_ack_num, tcp_off, tcp_flags, tcp_window, tcp_checksum_placeholder, tcp_urg_pointer)
	# The total byte length of the IP header (20 bytes) + the total length of the TCP header
	ip_length = 20 + len(tcp_header)
	# Converting all of the IP header values into byte objects, in order to be sent to the destination
	ip_header = pack('!BBHHHBBH4s4s', ip_ver, ip_tos, ip_length, ip_id, ip_flags_fo, ip_ttl, ip_pro, ip_checksum, ip_src_addr, ip_dst_addr)

	# Getting the TCP header length after the checksum is calculated
	tcp_len = len(tcp_header)

	# Combining the pseudo header and TCP header, then converting it all to byte objects in order to calculate the TCP checksum
	pseudo_packet = pack('!4s4sBBH', pseudo_src_addr, pseudo_dst_addr, pseduo_placeholder, pseudo_proto, tcp_len)
	pseudo_packet = pseudo_packet + tcp_header

	# Calculating the TCP checksum before sending the packet
	tcp_checksum = checksum(pseudo_packet)
	logger.info(f"Checksum calculated for {dst_address}:{tcp_dst_port} -> {tcp_checksum}")
	tcp_header = pack('!HHLLBBHHH', tcp_src_port, tcp_dst_port, tcp_seq_num, tcp_ack_num, tcp_off, tcp_flags, tcp_window, tcp_checksum, tcp_urg_pointer)
	# Creating the final packet to be sent by combining the IP header and TCP header
	packet = ip_header + tcp_header

	# Sending the packet to the destination IP address and port
	send_sock.sendto(packet, (dst_address, tcp_dst_port))
	logger.info(f"Packet sent to: {dst_address}:{tcp_dst_port}")

	try:
		# Execute the loop until the response is recieved, or the recieving socket times out
		while True:
			# Getting the response to the SYN packet from the response socket
			response = recv_sock.recv(65535)
				
			logger.info(f"Response recieved: {response}")

			# Getting the IP header by splitting the first 20 bytes from the response, and converting the byte value back into numeric and string values
			res_ip_header = response[0:20]
			iph = unpack('!BBHHHBBH4s4s', res_ip_header)

			# Getting the first byte of the response IP header, then getting the length of the IP header to determine where the TCP header starts
			ihl = iph[0] & 0xF
			ip_header_len = ihl * 4

			# Getting the source and destination IP addresses from the response, and converting them into string objects
			res_src_ip = socket.inet_ntoa(iph[8])
			res_dst_ip = socket.inet_ntoa(iph[9])

			# Getting the TCP header by splitting the 20 bytes after the IP header
			tcp_header_start = ip_header_len
			tcp_header = response[tcp_header_start:tcp_header_start+20]

			# Converting the response TCP header into numeric and string values
			tcph = unpack('!HHLLBBHHH', tcp_header)

			# Getting the source port, destination port, and TCP flags from the TCP header
			res_src_port = tcph[0]
			res_dst_port = tcph[1]
			res_flags = tcph[5]

			# Checking if the response has the same source IP address and source port of the sent packet
			if (src_address == res_dst_ip and dst_address == res_src_ip) and (tcp_src_port == res_dst_port and tcp_dst_port == res_src_port):
				# Checking if the SYN and ACK flags in the TCP header are set, if they are it confirms the port is open
				if res_flags & 0x12 == 0x12:
					print(f"Port {tcp_dst_port} - OPEN")
					open_ports.append(tcp_dst_port)
					logger.info(f"Port {dst_address}:{tcp_dst_port} is open")
				# Checking if the RST flag is set, if it is then it confirms the port is closed
				elif res_flags & 0x04:
					print(f"Port {tcp_dst_port} - CLOSED")
					logger.info(f"Port {dst_address}:{tcp_dst_port} is closed")
			break
	# If there is no reponse, then it means the host is not online or it is filtered and did not send a response
	except socket.timeout:
		print(f"Port {tcp_dst_port} - FILTERED or HOST DOWN")
		logger.info(f"Connection to port {dst_address}:{tcp_dst_port} timed out, host is either filtered or down")
# Display all of the open ports from the scan
print("----------Scan completed----------")
print(f"Open ports for {dst_address}: {open_ports}")
logger.info(f"Scan completed, the following ports are open for {dst_address}:{open_ports}")