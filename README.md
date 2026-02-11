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


