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
