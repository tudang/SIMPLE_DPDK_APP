# Build SIMPLE_DPDK_APP

```
git clone https://github.com/tudang/SIMPLE_DPDK_APP.git $HOME/SIMPLE_DPDK_APP
cmake $HOME/SIMPLE_DPDK_APP
meson build
ninja -C build
```

# Setup for DPDK
The PCI address of NIC intented to run the DPDK program is 86:00.0. 
Use `setup_dpdk.sh` as a reference.


# Run SIMPLE_DPDK_APP

node6:

```
sudo $HOME/build/ping_dpdk 192.168.50.6:12345
```


node5:

configure IP address

```
sudo ifconfig eth2 192.168.50.5
```

Try `ping`

```
ping 192.168.50.6
```

Try simple Python client

```
# File udp_client.py
import socket

UDP_IP = "192.168.50.6"
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
