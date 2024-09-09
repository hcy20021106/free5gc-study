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


