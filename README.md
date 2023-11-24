# Introduction 

We built this project as a part of final project submission for the CS307-system practicum course at IIT Mandi.It was a group project. 
NATOO is a simple network analysis tool which have following features : 
* Host discovery  -- Implemented by me
* Port scanning -- Dhruv Pindawala
* OS detection -- Pongthangamba
* Packet sniffing -- Divyansh Vinayak, Akash Karnatak. 
* ARP poisoning -- Atul Jain

# Build instructions
```sh
make -j4
```
### Host discovery
In order to scan for host in a subnet, run the following command,

```sh
$ ./natoo -H <subnet>
# example
# ./natoo -H 192.168.1.0/24
```

### Port scanning
Scan ports of an IP address using the following command,

```sh
$ ./natoo -P <ip-addr>
# example
# ./natoo -P 192.168.1.123
```

### OS detection
OS of an IP address can also be detected using the following command

```sh
$ ./natoo -Dp <port> <ip-addr>
# example
# ./natoo -Dp 80 192.168.1.123
```

### Packet sniffing
Inspect incoming packets on a network interface using the following command,

```sh
$ ./natoo -Sn <num-packets> -i <interface>
# example
# ./natoo -Sn 100 -i wlan0
```

### ARP poisoning
ARP poisoning attack can be launched using the following command,

```sh
$ ./natoo -A <gateway-ip> -i <interface> -m <mac-addr>
# example
# ./natoo -A 192.168.1.1 -i wlan0 -m aa:bb:cc:dd:ee:ff
```


## DEMO(Youtube link)
[![NATOO_DEMO](https://img.youtube.com/vi/VnPW55QBpJ4/0.jpg)](https://www.youtube.com/watch?v=VnPW55QBpJ4)
