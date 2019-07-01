# Build SIMPLE_DPDK_APP

```
git clone https://github.com/tudang/SIMPLE_DPDK_APP.git $HOME/SIMPLE_DPDK_APP
mkdir -p $HOME/build/SIMPLE_DPDK_APP
cd $HOME/build/SIMPLE_DPDK_APP
cmake $HOME/SIMPLE_DPDK_APP
make
```

# Run SIMPLE_DPDK_APP

node96:

```
sudo $HOME/build/icmp/main 192.168.4.96:12345
```


node95:

configure IP address

```
sudo ifconfig eth2 192.168.4.95
```

Try `ping`

```
ping 192.168.4.96
```

Try simple Python client

```
# File udp_client.py
import socket

UDP_IP = "192.168.4.96"
UDP_PORT = 12345
MESSAGE = "Hello, World!"

print "UDP target IP:", UDP_IP
print "UDP target port:", UDP_PORT
print "message:", MESSAGE

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))

data, addr = sock.recvfrom(13)
print "received message:", data
```


```
python udp_client.py
```
