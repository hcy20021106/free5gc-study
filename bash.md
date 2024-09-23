# ip
```bash
ip route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.1 dev eth0
ip route del -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.1 dev eth0
ip addr show
ip addr add 192.168.1.100/24 dev eth0
ip link show 
ip link add name upfgtp type gtp5g
ip link set upfgtp mtu 1000
ip link set upfgtp up
ip link set dev eth0 up
ip route show
ip rule
netstat -tuln (-t tcp -u ucp -l listenning -n number)
netstat -an | grep :80
ip netns add mynamespace
ip link add veth0 type veth peer name veth1
ip link set veth1 netns mynamespace

```
# sysctl
```bash
sysctl -w net.ipv4.ip_forward = 1


```

# kernel
```bash
\\查看当前内核加载的模块信息
lsmod 
\\modinfo + 模块名
modinfo hello
\\rmmod + 模块名
rmmod hello
```

# tcpdump
```bash
tcpdump -u {interface name}
tcpdump host {host ip}
tcpdump port {port number}
// write out capture result to PCAP file
tcpdump -i {interface name} -w {XXX}.pcap


```


# iptables
```bash
iptable
-t, --table     table必须是raw,nat,filter,mangle中的一个，默认是filter表
-p 指定要匹配的数据包协议类型
-A 指定规则链名
-s --source
-d --destination
-i --in-interface       指定数据包的来自网络接口（只对INPUT，FORWARD，PREROUTING这三个链起作用）
-o --out-interface      指定数据包出去的网络接口（只对OUTPUT，FORWARD，POSTROUTING三个链起作用）
-L --list       列出链chain上面的所有规则，如果没有指定链，则列出表上所有链的所有规则
-j, --jump target <制定目标>: 即满足某条件时该执行什么样的动作。target可以是内置的目标，比如ACCEPT

```
filter定义允许或者不允许，只能做在三个链上：INPUT，FORWARD，OUTPUT
nat定义地址转换的，也只能做在3个链上：PREROUTING，OUTPUT，POSTROUTING
mangle功能：修改报文原数据，是5个链都可以做：PREROUTING，INPUT，FORWARD，OUTPUT，POSTROUTING

**链名包括**
- INPUT: 处理输入数据包
- OUTPUT: 处理输出数据包
- FORWARD: 处理转发数据包
- PREROUTING: 用于目标地址转换（DNAT）
- POSTOUTING: 用于源地址转换
**动作包括**
- ACCEPT: 接收数据包
- DROP: 丢弃数据包
- REDIRECT: 重定向、映射、透明代理
- SNAT: 源地址转换
- DNAT: 目标地址转换
- MASQUERADE: IP伪装(NAT), 用于ADSL
- LOG: 日志记录

EXAMPLE
```bash
//清空所有的防火墙规则
iptables -F
//允许ssh端口连接
iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT
//设置默认的不让进
iptables -P INPUT DROP
//设置默认的不允许转发
iptables -P OUTPUT ACCEPT
//允许web访问
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
//启动网络转发规则
iptables -t nat -A POSTROUTING -s 192.168.188.0/24 -j SNAT --to-source 210.14.67.127
//端口映射
iptables -t nat -A PREROUTING -d 210.14.67.127 -p tcp --dport 2222 -j DNAT --to-dest 192.168.188.115
```