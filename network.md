# Frame
## Definition
A frame is the basic unit of data transmission at the **Data link layer**(L2) in the OSI model and is responsible for reliable data transfer between two directly connected nodes. 
## Main Components
- Frame Header: Destination MAC Address and Source MAC Address. Type/Length Field, Control Information. Normally, the frame type is Ethernet, so we enter IPv4/IPv6/ARP
- Payload/Data: The actual transmitted data from higher layer.
- FCS, Frame Check Sequence
- Trailer
## Function
- Transmitter: Data link layer receive packet from network layer, and then encapsulate it with Frame Header, and transmit to physical layer.
- Receiver: Data link layer receives frame from physical layer, and then chect it with FCS, and decapsulates to higher layer.
## MTU
MTU(Maximum Transmission Unit) is associated with the Data Link Layer, to defines the maximum size of data packet.
For example, in **Ethernet** the standard MTU is typically 1500 bytes, meaning that the largest IP packet(including headers) that can be transmitted without fragmentation is 1500 bytes. If a packet exceeds the MTU, it must be fragmented at the Network Layer(Layer 3) to fit into smaller frames.


# Packet
## Definition
A packet is the basic unit of data transmission at the **network layer** in the OSI model.
## Main Components
- Header: Source and Desination IP addresses, protocol type(**IP**).
- Payload: The actual data transported
- Trailer
## Function
- Routing: Packets are forwarded through the network from the source to the destination using routers which can determine the best path.
- Fragmentation and Reassembly: Large packers might be split into smaller fragements for transmission across networks with smaller maximum transmission units(**MTUs**)

# Segment
## Definition
- It is basic for data transmission at the **transport layer** in the OSI model, to deal with the transport of data between two systems.
## Main Components
- Header: Contains information like source and destination port numbers, sequence number, acknowledgment number, flags(e.g., SYN, ACK) and window size.
- Payload: The actual data being sent.
## Function
- Data Integrity
- Flow Control
- Error Detection and Correction.


# Socket(tcp udp)
## Definition
- It is an interface or *****endpoint** *****that facilitates establishing and managing a TCP or UCP connection, enabling applications to send and receive data.
## Components
- An IP address
- A port number
## Function
- Establish, manage and terminate TCP connections.
- Applications use sockets to send and receive data over network.

---

> **Notice**: 
> - **TCP Socket** is an interface or endpoint that facilitates establishing and managing a TCP connection, enabling applications to send and receive data.
> - **TCP Segment** is the actual data unit transmitted across the network, containing control information and part of the data being sent.

---


# HTTP Message
## Definition
- In HTTP communications, the data segments within the messages are called message. HTTP messsages come in two primary types: **request messages and response messages**. 
## Request Message 
- Request Line
    - Method(e.g., GET, POST)
    - The request URL

- Request Header
    - Host
    - User-Agent
## Response Message
- Status Line
    - Status code
    - Status phrase
- Response Headers
    - Content-Type
    - Content-Length
    - Server
- **Response Body**
    - HTML page
    - JSON data
    - Image
```bash
curl  https://www.baidu.com 
curl -L -X  -b 'foo=bar' -H  'User-Agent: php/1.0' POST https://www.baidu.com # -H(User-Agent), -b(Cookie) -d(send POST with Request Header) -X(choose method)
```

---

> **Notice**<br>
> Data Encapsulation Process (from higher to lower layers), Higher layer encapsulates lower layer<br>
> <img src="image/5.png" alt="Description of the image" height="400">
> Data decapsulation Process (from lower to higher layers)<br>
> <img src="image/6.png" alt="Description of the image" height="400">

---


# UDP Tunnel
# Definition
udptunnel is used to encapsulate UDP packets within TCP packets and then transmit them over a TCP connection. Specifically, udptunnel encapsualtes UDP packet into a special TCP packet at the source end, and at the destination end, it decapsulates these TCP packets back into original UDP packets. This allows UDP packets to be transmitted over a TCP connection, which help bypass firewall restrictions oor address NAT travesal issues.

# Network Interface/Device
## Ethernet Interface
- Network Interface Card(NIC) for wire network
- Wi-Fi Interface for wireless network
- Fiber Optic Interface
## Virtual Interface
- Virtual Network Interface
- Loopback Interface
- VPN Interface
