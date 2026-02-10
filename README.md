# Port-Scanner

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

#### IP Header
The first part of this script is creating the IP header. To do this I decided to set all of the IP header values from scratch.
