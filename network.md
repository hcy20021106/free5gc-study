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

# tun/tap
## definition
tun is L3(network) device, while tap is L2(data link) device. Its function is same with hardware device. 
## Driver
- 字符驱动设备(模拟物理链路的数据接收与发送)
- 网卡驱动
    - 1. 应用程序发起网络请求
    - 2. 进入协议栈后经过路由查询应该走虚拟网卡
    - 3. 数据进入虚拟网卡，处理后发送给应用层程序
    - 4. 数据从程序再次进入协议栈，重新路由到真实网卡
    - 5. 通过真实网卡再把数据发送出去。
## create tun
```bash

int tun_create(char *dev, int flags){
    struct ifreq ifr;
    int fd, err;
    if((fd = open("/dev/net/tun", O_RDWR)) < 0 ){
        return fd;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;
    if(*dev)
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
 if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
  perror("ioctl(TUNSETIFF)");
  close(fd);
  return err;
 }
 strcpy(dev, ifr.ifr_name);
 return fd; 
}
int main(int argc, char *argv[])
{
 char buffer[BUFSIZ], veth_name[IFNAMSIZ] = "tunveth1";
 int i, tun_fd, nread;
 struct ethhdr *eth;
 struct iphdr *iph;
 struct in_addr saddr, daddr; 
 tun_fd = tun_create(veth_name, IFF_TUN | IFF_NO_PI);
 if (tun_fd < 0) {
  perror("Creating interface");
  exit(1);
 }
 while(1) {
  memset(buffer, 0, sizeof(buffer));
  nread = read(tun_fd, buffer, sizeof(buffer));
  if (nread < 0) {
   perror("Reading from interface");
   close(tun_fd);
   exit(1);
  }
  iph = (struct iphdr*)buffer;

  if (iph->version ==4) {  
   printf("\nRead %d bytes from device %s\n", nread, veth_name);
   memcpy(&saddr.s_addr, &iph->saddr, 4);
   memcpy(&daddr.s_addr, &iph->daddr, 4);
   printf("Source host:%s\n", inet_ntoa(saddr));
   printf("Dest host:%s\n", inet_ntoa(daddr));
  }
 }
 return 0;
}



```
