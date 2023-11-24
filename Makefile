all: port_scanner os_det arp_poisoner packet_sniffer

port_scanner:
	g++ -pthread port_scanner.cpp -o port_scanner

os_det:
	gcc -pthread -lpcap os_det.c -o os_det

arp_poisoner:
	gcc arp_poisoner.c -o arp_poisoner

packet_sniffer:
	gcc packet_sniffer.c -o packet_sniffer

clean:
	rm os_det arp_poisoner packet_sniffer port_scanner
