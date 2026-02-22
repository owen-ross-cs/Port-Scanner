# Port Scanner

## Objective
This project uses the socket library in python to create a TCP port scanner from scratch. The goal of this project is not to outpreform industry tools like Nmap, but to demonstrate a deep understanding of trhe port scanning process used during the reconnaissance phase of penetration testing.

### Skills Learned
- Low-level socket programming in Python
- IP and TCP packet analysis
- TCP checksum calculation

### Tools Used
- Pyhton
- Wireshark

### Project Overview
This script performs a SYN scan by manually crafting TCP/IP packets and analyzing the response from the target host. 
At a high level, the scanner sends a TCP SYN packet to each target port:
- If the target responds with SYN ACK, the port is open.
- If the target responds with RST, the port is closed.
- If there is no response then the port is filtered or the host is unreachable.
This process appears simple, but in reality it involves manually building packet headers, calculating checksums, and parsing raw packet responses. 

### Implementation Breakdown
#### TCP Header Construction
The first part of this script constructs the TCP header by manually defining each field before the data is converted into byte objects. 

A TCP header has multiple fields which determine how a packet should be processed. Below is a diagram of a TCP header:
![TCP_Header](https://github.com/user-attachments/assets/ef7a3bc2-10d5-46c5-94c0-f2df6e06ea46)
Ref 1. Diagram of TCP header, from: https://www.geeksforgeeks.org/computer-networks/tcp-ip-packet-format/

Since this scanner performs a SYN scan, only the SYN flag is set while all the other flags are not set. The source port and sequence number are randomized to simulate legitimate connection attempts and avoid reuse patterns. The TCP flags are combined using bit shifting to produce a single flag byte. Below is the code for creating the TCP header:
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

#### IP Header Construction
The IP header is constructed after the TCP header. Unlike the TCP header, the IP header includes routing informaton required to deliver the packet to the target.
Key fields in the IP header include:
- IP version
- Protocol type
- Source IP address
- Destination IP address

Below is a diagram of the IP header:
<img width="936" height="427" alt="image" src="https://github.com/user-attachments/assets/1b8e460c-4c04-4674-87c0-753d3d899f53" />
Ref 2. Diagram of IP header, from: https://en.wikipedia.org/wiki/IPv4#/media/File:IPv4_Packet-en.svg

The IP header is eventually combined with the TCP header to form the complete packet that is sent to the target. Below is the code to create the IP header:
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

#### Checksum Calculation
TCP uses a checksum to ensure packet integrrity during transmission. To checksum is calculated using both the TCP header and a pseudo header. The pseudo header is only used for checksum calculation and it contains the fields:
- Source IP address
- Destination IP address
- Protocol (TCP)
- TCP length
- Reserved bits

The pseduo header and TCP header are combined to calculate the checksum.

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
##### Checksum Algorithm
The algorithm for calculating the checksum is as follows:
1. If the data does not have an even length, then it will pad the data with an extra byte 
2. The data is split into 16 bit words
3. All the 16 bit words are combined together
4. If there are any overflow bits, they are wraped back into the lower 16 bits
5. Invert the final result to get the checksum
The checksum ensures the receving host can verify the integrity of the packet.
For more information you can <a href="https://www.geeksforgeeks.org/computer-networks/calculation-of-tcp-checksum/">click here</a>. Here is the function that is used to calculate the checksum:
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
#### Packet Teansmission and Response Handling
Two raw sockets are used for transmission and response. One socket sends crafted packets, and the other socket listens for incoming TCP responses. Seperate sockets are required because the operating system may handle the TCP responses automatically, preventing manual packet analysis.
``` python
# Creating the socket that will send the IP packet
send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

# Creating the socket that will recieve the response to the SYN packet that was sent
recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
```

##### Response Analysis
After the packet is sent to the target, the scanner listens for a response and preforms the following steps:
1. Extracts the IP header'
2. Determines the IP header length
3. Locate and extract the TCP header
4. Verify the response has the same routing information as the request
5. Analyze the TCP flags to determine the status of the port
``` python
# Getting the first byte of the response IP header, then getting the length of the IP header to determine where the TCP header starts
ihl = iph[0] & 0xF
ip_header_len = ihl * 4
```
Finding the IP header length is required because optional IP fields may change the header size. 

##### Port Response Analysis
The TCP flags of the response header are extracted and analyzed to determine the status of the port. 
| Flags | Status |
|--------------|---------------|
| SYN + ACK | Port Open  |
| RST | Port Closed  |
| No Respoinse | Port Filtered or Host Down  |

Results are displayed during the scan and logged to a file.

``` python
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
			pen_ports.append(tcp_dst_port)
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
```

#### Example Packet Flow
A successful connection attempt produces the following packet exchange:
1. SYN sent to target
2. Target responds with SYN ACK
3. RST sent to target (The handshake is not completed)

Here is how a connection to an open port would look like through Wireshark:
<img width="1254" height="200" alt="image" src="https://github.com/user-attachments/assets/9a89dee0-f35e-44be-a16b-8e5a84d84be9" />
Ref 3. A successful SYN and SYN ACK response from an open port using wireshark

### Usage Instructions
#### Requirements
- Linux operating system
- Root or administrator privleges
Raw sockets require elevated privileges to manipulate network packets.

#### Step 1 - Obtain Root Access
Run:
``` bash
sudo su
```

#### Step 2 - Navigate to Script Directory
``` bash
cd /path/to/script
```

#### Step 3 - Execute Scanner
``` bash
python scanner.py <target IP>
```

Example:
``` bash
python scanner.py 45.33.32.156
```
Note: 45.33.32.156 is the IP address of scanme.nmap.org, which is a website designed to be scanned.

The scanner checks ports 1-1024 and displays the results in real time. A log file is also generated containing detailed scan information.

### Ethical Use Notice
This tool generates large volumes of network traffic and should only be used against systems you have permission to scan. Public test targets such as scaneme.nmap.org are recommended for safe testing.
