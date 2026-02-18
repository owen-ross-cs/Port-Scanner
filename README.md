# Port Scanner

## Objective
For this project I created a port scanner in Python from scratch using the socket library. This project is not meant to create a better port scanner than the ones that are widely used in the industry like Nmap, instead it was meant to showcase my knowledge of the port scanning process, that is a vital task of the reconisance phase of pen testing. 

### Skills Learned
- Socket programming in Python
- IP and TCP packet analysis

### Tools Used
- Pyhton
- Wireshark

### Documentation
This script contains several different parts that combine to create a working port scanner. At a high level, this script works the same as other port scanners, where a SYN packet is sent to the desired destination, and if a SYN ACK packet is recieved then that means the port is open. Despite the simple explaination of this script, there is a lot more going on then it seems. I will discuss the different parts of the script and how they function together below.

#### TCP Header
The first part of this script is creating the TCP header. To create the TCP header, I decided to set every value for the header field then convert all of the data into byte objects. A TCP header has around 9 fields which determine the type and function of the packet. Below is a diagram of a TCP header:
![TCP_Header](https://github.com/user-attachments/assets/ef7a3bc2-10d5-46c5-94c0-f2df6e06ea46)
Ref 1. Diagram of TCP header, from: https://www.geeksforgeeks.org/computer-networks/tcp-ip-packet-format/

Since I am creating a port scanner, I needed to create a SYN TCP header. To do this I set the SYN flag bit to 1, while not setting any other flag. If the port is open it will recieve the SYN packet and send a SYN ACK. Below is the code for creating the TCP header:
```python
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
```

#### IP Header
The next part of the script is creating the IP header. This is simliar to creating the TCP header, with some differences. Since IP is a lower laayer than TCP, we need to set some data that wasn't present in the TCP header. The main difference is setting the IP version, the protocol, IP source address, and IP destination address. The TCP header will be combined with the IP header to create a complete IP packet. Below is a diagram of an IP header:
<img width="936" height="427" alt="image" src="https://github.com/user-attachments/assets/1b8e460c-4c04-4674-87c0-753d3d899f53" />
Ref 2. Diagram of IP header, from: https://en.wikipedia.org/wiki/IPv4#/media/File:IPv4_Packet-en.svg

Since it is a SYN packet, the IP header needs to be set with the TCP protocol and have a version of IPv4. Other than this, setting the IP heade is pretty much the same as creating the TCP header. Below is the code to create the IP header:
```python
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
```

#### Checksum
Since I am am using a TCP connection, I need to include the checksum into the TCP header. The checksum is an important part of network communication as this is used to verify data is being sent from a verfied source. To calculate the checksum, we need to create a pseudo header and combine it with the TCP header. The pseduo header is a header that is created for the sole purpose of calculating the checksum, it is not sent to the destination. The pseduo header includes the source IP address, destination IP address, the protocol, the TCP header length, and reserve bits. This is combined with the TCP header to calculate the checksum. Here is the code for creating and combining the headers for the checksum:
```python
# Converting all of the TCP header values into byte objects, in order to be sent to the destination
	tcp_header = pack('!HHLLBBHHH', tcp_src_port, tcp_dst_port, tcp_seq_num, tcp_ack_num, tcp_off, tcp_flags, tcp_window, tcp_checksum_placeholder, tcp_urg_pointer)
	# The total byte length of the IP header (20 bytes) + the total length of the TCP header
	ip_length = 20 + len(tcp_header)
	# Converting all of the IP header values into byte objects, in order to be sent to the destination
	ip_header = pack('!BBHHHBBH4s4s', ip_ver, ip_tos, ip_length, ip_id, ip_flags_fo, ip_ttl, ip_pro, ip_checksum, ip_src_addr, ip_dst_addr)

	tcp_len = len(tcp_header)

	# Combining the pseudo header and TCP header, then converting it all to byte objects in order to calculate the TCP checksum
	pseudo_packet = pack('!4s4sBBH', pseudo_src_addr, pseudo_dst_addr, pseduo_placeholder, pseudo_proto, tcp_len)
	pseudo_packet = pseudo_packet + tcp_header

	# Calculating the TCP checksum before sending the packet
	tcp_checksum = checksum(pseudo_packet)
	tcp_header = pack('!HHLLBBHHH', tcp_src_port, tcp_dst_port, tcp_seq_num, tcp_ack_num, tcp_off, tcp_flags, tcp_window, tcp_checksum, tcp_urg_pointer)
```

The next part of this process is to actually calculate the checksum. For the sake of length I will only give a high overview of the process. The first step is to split the combined TCP and pseudo header into 16 bit words. A extra bit is added if there is an odd number of bytes to ensure all of the bytes are in 16 bit words. The next part is to combine all of the 16 bit words together. If there is an overflow of bytes, then wrap the overflow back to the lower 16 bits. Finally, all the bits in the combined words are inverted to get the final checksum. For more information you can <a href="https://www.geeksforgeeks.org/computer-networks/calculation-of-tcp-checksum/">click here</a>. Here is the function that is used to calculate the checksum:
``` python
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
```
#### Sending and Recieving packets
This is the porton of the script where most of the action actually happens. In order to send and recieve packets, there needs to be two scokets created, one for sending packets, the other for recieving. The reason why I csn't use the same socket for sending and recieving is because, by default the OS will handle the SYN ACK response which means the socket that sends the packet cannot access the reponse. By having a socket that listens to reponses I am able to specifically listen and analyze all of the packets being received by the system. Here is the code for initilizing the sockets:
``` python
# Creating the socket that will send the IP packet
send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

# Creating the socket that will recieve the response to the SYN packet that was sent
recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
recv_sock.settimeout(5)
```

To send the packet, the function sendto() from the socket library is used. This function will send the packet to the desired destination IP address and port. Since this is a port scanner, multiple packets with different destination ports will be sent. The recieve socket then waits for a response from the destination. When a reponse is recieved the IP header is extracted to get the IP header length. This is important because it will be used to find the start of the TCP header. The TCP header is then extracted which will allow us to get the source port, destination port, and flags of the response. Then the source IP address, destination IP address, source port, and destintion port are compared to the ones in the sent packet to ensure this is a response to the same packet that was sent. Then I check if the SYN and ACK flags are set on response packet. If they are then that means the port is open. If the RST flag is set than that merans it is closed. If a response is not recieved in 5 seconds, then that means the reciever did not respond because it is down or has some filtering in place to not respond to SYN packets. After all of the ports have been scanned, a list of all the open ports found will be displayed for the user. The below is the code for this porton of the script:
``` python
logger.info(f"Sending packet to: {dst_address}:{tcp_dst_port}")
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

			logger.info(f"Reponse packet source IP: {res_src_ip}")
			logger.info(f"Reponse packet destination IP: {res_dst_ip}")

			# Getting the TCP header by splitting the 20 bytes after the IP header
			tcp_header_start = ip_header_len
			tcp_header = response[tcp_header_start:tcp_header_start+20]

			# Converting the response TCP header into numeric and string values
			tcph = unpack('!HHLLBBHHH', tcp_header)
			logger.info(f"TCP response header extracted: {tcph}")

			# Getting the source port, destination port, and TCP flags from the TCP header
			res_src_port = tcph[0]
			res_dst_port = tcph[1]
			res_flags = tcph[5]

			logger.info(f"Source port {res_src_port}, Destination port {res_dst_port}, and flags {res_flags} from response TCP header.")

			# Checking if the response has the same source IP address and source port of the sent packet
			if src_address == res_dst_ip and dst_address == res_src_ip and tcp_src_port == res_dst_port and tcp_dst_port == res_src_port:
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
logger.info(f"Scan completed, the following ports are open for {dst_address}: {open_ports}")
```

Here is how a connection to an open port would look like through Wireshark:
<img width="1254" height="200" alt="image" src="https://github.com/user-attachments/assets/9a89dee0-f35e-44be-a16b-8e5a84d84be9" />
Ref 3. A successful SYN and SYN ACK response from an open port using wireshark

### How to Use
In order to use thid script you must have admin priviledges, and you need to execute it in Linux. This script sends numerous packets to a destination, which can cause overload on the destination machine, so it is important to use a destination that is designed to be scanned, like scanme.nmap.org which I use as an example.

#### Step 1
First, since this script manipulates network packets, you will need to have admin/root permissions to execute this script. The most common way to do this is typing the command su root.

#### Step 2
Now that you have the proper permissions, you need to go to the directory where the scanner.py script is located. To do this use the cd command with the directory path.

#### Step 3
Finally, you can execute the code using the command python scanner.py \<destination IP address\>. The IP address you provide must be in IPv4 format, i.e. 1.2.3.4. The script will start and scan all of the high priority ports (ports 1 to 1024) on the destination. The script will display the result after each port is scanned, and create a log file with all of the information gathered during the scan.
