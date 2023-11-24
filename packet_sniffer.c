#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

void parse_packet(unsigned char *, int);
void print_ether_header(unsigned char *);
void print_ip_header(unsigned char *);
void print_ipv6_header(unsigned char *);
void print_tcp_header(unsigned char *);
void print_udp_header(unsigned char *);
void print_icmp_header(unsigned char *);
void print_arp_header(unsigned char *);
void print_tcp_packet(unsigned char *, int, bool);
void print_udp_packet(unsigned char *, int, bool);
void print_icmp_packet(unsigned char *, int, bool);
void print_arp_packet(unsigned char *, int);
void print_data(unsigned char *, int);

// arguments
int npackets = 0;
int promiscuous = 0;
int dump = 0;
int verbosity = 0;
char *interface = NULL;

int tcp = 0, udp = 0, icmp = 0, arp = 0, others = 0, total = 0;

void usage(char *prog)
{
    fprintf(stderr, "usage: %s <-i interface> <-n number of packets> <-p promiscuous mode> <-v verbosity> <-d dump packet data>\n", prog);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    // input args
    char ch;
    while ((ch = getopt(argc, argv, "n:i:p:d:v:")) != -1)
    {
        switch (ch)
        {
        case 'n':
            npackets = atoi(optarg);
            break;
        case 'i':
            interface = strdup(optarg);
            break;
        case 'p':
            promiscuous = atoi(optarg);
            break;
        case 'd':
            dump = atoi(optarg);
            break;
        case 'v':
            verbosity = atoi(optarg);
            break;
        default:
            usage(argv[0]);
        }
    }

    int saddr_size, data_size;
    struct sockaddr saddr;
    struct in_addr in;

    unsigned char *buffer = (unsigned char *)malloc(65536);

    // Create a raw socket that shall sniff
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    if (interface != NULL)
    {
        strncpy((char *)ifr.ifr_name, interface, IF_NAMESIZE - 1);
        if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1)
        {
            perror("ioctl");
            exit(EXIT_FAILURE);
        }
    }

    // Enable promiscuous mode
    struct packet_mreq mr;
    if (promiscuous)
    {
        memset(&mr, 0, sizeof(struct packet_mreq));
        mr.mr_ifindex = ifr.ifr_ifindex;
        mr.mr_type = PACKET_MR_PROMISC;
        if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(struct packet_mreq)) == -1)
        {
            perror("setsockopt");
            exit(EXIT_FAILURE);
        }
    }

    printf("Packet sniffer initialized. Waiting for incoming packets. Press Ctrl-C to abort...\n");

    for (int i = 1; i <= npackets; ++i)
    {
        saddr_size = sizeof saddr;
        // Receive a packet
        data_size = recvfrom(sock, buffer, 65536, 0, &saddr, &saddr_size);
        if (data_size == -1)
        {
            perror("recvform");
            exit(EXIT_FAILURE);
        }
        printf("\n[>] Packet #%d sniffed:\n", i);
        // Now parse the packet
        parse_packet(buffer, data_size);
    }

    close(sock);

    return 0;
}

void parse_packet(unsigned char *buffer, int size)
{
    ++total;
    struct ether_header *etherh = (struct ether_header *)buffer;
    unsigned int ether_type = ntohs(etherh->ether_type);
    if (ether_type == 0x0800) // IPv4 packet
    {
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ether_header));
        switch (iph->protocol)
        {
        case 1: // ICMP protocol
            ++icmp;
            print_icmp_packet(buffer, size, true);
            break;

        case 6: // TCP protocol
            ++tcp;
            print_tcp_packet(buffer, size, true);
            break;

        case 17: // UDP protocol
            ++udp;
            print_udp_packet(buffer, size, true);
            break;

        default: // Some other IP protocol
            ++others;
            break;
        }
    }
    else if (ether_type == 0x86dd) // IPv6 packet
    {
        struct ipv6hdr *ipv6h = (struct ipv6hdr *)(buffer + sizeof(struct ether_header));
        switch (ipv6h->nexthdr)
        {
        case 58: // ICMP protocol for IPv6
            ++icmp;
            print_icmp_packet(buffer, size, false);
            break;

        case 6: // TCP protocol
            ++tcp;
            print_tcp_packet(buffer, size, false);
            break;

        case 17: // UDP protocol
            ++udp;
            print_udp_packet(buffer, size, false);
            break;

        default: // Some other IP protocol
            ++others;
            break;
        }
    }
    else if (ether_type == 0x0806) // ARP packet
    {
        ++arp;
        print_arp_packet(buffer, size);
    }
    else
    {
        ++others;
    }
    printf("\nTCP: %4d   UDP: %4d   ICMP: %4d   ARP: %4d   Others: %4d   Total: %4d   \n", tcp, udp, icmp, arp, others, total);
}

void print_ether_header(unsigned char *buffer)
{
    struct ether_header *etherh = (struct ether_header *)buffer;
    printf("\nEthernet Header\n");
    printf("   |-Source MAC Address         : %s\n", ether_ntoa((struct ether_addr *)etherh->ether_shost));
    printf("   |-Destination MAC Address    : %s\n", ether_ntoa((struct ether_addr *)etherh->ether_dhost));
    printf("   |-Packet Type                : %04hx\n", ntohs(etherh->ether_type));
    printf("\n");
}

void print_ip_header(unsigned char *buffer)
{
    struct iphdr *iph = (struct iphdr *)buffer;
    struct sockaddr_in source, dest;

    memset(&source, 0, sizeof source);
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof dest);
    dest.sin_addr.s_addr = iph->daddr;

    printf("\nIPv4 Header\n");
    printf("   |-IP Version       : %d\n", (unsigned int)iph->version);
    printf("   |-IP Header Length : %d bytes\n", ((unsigned int)(iph->ihl)) * 4);
    printf("   |-Type of Service  : %d\n", (unsigned int)iph->tos);
    printf("   |-IP Total Length  : %d bytes\n", ntohs(iph->tot_len));
    printf("   |-Identification   : %d\n", ntohs(iph->id));
    printf("   |-TTL              : %d\n", (unsigned int)iph->ttl);
    printf("   |-Protocol         : %d\n", (unsigned int)iph->protocol);
    printf("   |-Checksum         : %d\n", ntohs(iph->check));
    printf("   |-Source IP        : %s\n", inet_ntoa(source.sin_addr));
    printf("   |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));
    printf("\n");
}

void print_ipv6_header(unsigned char *buffer)
{
    struct ipv6hdr *ipv6h = (struct ipv6hdr *)buffer;

    struct in6_addr saddr = ipv6h->saddr;
    struct in6_addr daddr = ipv6h->daddr;

    char saddrc[INET6_ADDRSTRLEN];
    char daddrc[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &saddr, saddrc, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &daddr, daddrc, INET6_ADDRSTRLEN);

    printf("\nIPv6 Header\n");
    printf("   |-IP Version       : %d\n", (unsigned int)ipv6h->version);
    printf("   |-Priority         : %d\n", (unsigned int)ipv6h->priority);
    printf("   |-Payload Length   : %d bytes\n", ntohs(ipv6h->payload_len));
    printf("   |-Hop Limit        : %d\n", (unsigned int)ipv6h->hop_limit);
    printf("   |-Protocol         : %d\n", (unsigned int)ipv6h->nexthdr);
    printf("   |-Source IP        : %s\n", saddrc);
    printf("   |-Destination IP   : %s\n", daddrc);
    printf("\n");
}

void print_tcp_header(unsigned char *buffer)
{
    struct tcphdr *tcph = (struct tcphdr *)(buffer);
    printf("\nTCP Header\n");
    printf("   |-Source Port            : %u\n", ntohs(tcph->source));
    printf("   |-Destination Port       : %u\n", ntohs(tcph->dest));
    printf("   |-Sequence Number        : %u\n", ntohl(tcph->seq));
    printf("   |-Acknowledgement Number : %u\n", ntohl(tcph->ack_seq));
    printf("   |-Header Length          : %d bytes\n", (unsigned int)tcph->doff * 4);
    printf("   |-Urgent Flag            : %d\n", (unsigned int)tcph->urg);
    printf("   |-Acknowledgement Flag   : %d\n", (unsigned int)tcph->ack);
    printf("   |-Push Flag              : %d\n", (unsigned int)tcph->psh);
    printf("   |-Reset Flag             : %d\n", (unsigned int)tcph->rst);
    printf("   |-Synchronise Flag       : %d\n", (unsigned int)tcph->syn);
    printf("   |-Finish Flag            : %d\n", (unsigned int)tcph->fin);
    printf("   |-Window                 : %d\n", ntohs(tcph->window));
    printf("   |-Checksum               : %d\n", ntohs(tcph->check));
    printf("   |-Urgent Pointer         : %d\n", ntohs(tcph->urg_ptr));
    printf("\n");
}

void print_udp_header(unsigned char *buffer)
{
    struct udphdr *udph = (struct udphdr *)(buffer);
    printf("\nUDP Header\n");
    printf("   |-Source Port      : %d\n", ntohs(udph->source));
    printf("   |-Destination Port : %d\n", ntohs(udph->dest));
    printf("   |-UDP Length       : %d\n", ntohs(udph->len));
    printf("   |-UDP Checksum     : %d\n", ntohs(udph->check));
    printf("\n");
}

void print_arp_header(unsigned char *buffer)
{
    struct ether_arp *arph = (struct ether_arp *)(buffer);
    struct sockaddr_in source, dest;

    memset(&source, 0, sizeof source);
    source.sin_addr.s_addr = arph->arp_spa;

    memset(&dest, 0, sizeof dest);
    dest.sin_addr.s_addr = arph->arp_tpa;

    printf("\nARP Header\n");
    printf("   |-Sender MAC Address     : %s\n", ether_ntoa((struct ether_addr *)arph->arp_sha));
    printf("   |-Sender IP Address      : %s\n", inet_ntoa(source.sin_addr));
    printf("   |-Target MAC Address     : %s\n", ether_ntoa((struct ether_addr *)arph->arp_tha));
    printf("   |-Target IP Address      : %s\n", inet_ntoa(dest.sin_addr));
    printf("\n");
}

void print_icmp_header(unsigned char *buffer)
{
    struct icmphdr *icmph = (struct icmphdr *)(buffer);
    printf("\nICMP Header\n");
    printf("   |-Type : %d\n", (unsigned int)(icmph->type));
    printf("   |-Code : %d\n", (unsigned int)(icmph->code));
    printf("   |-Checksum : %d\n", ntohs(icmph->checksum));
    printf("\n");
}

void print_tcp_packet(unsigned char *buffer, int size, bool isIpv4)
{
    printf("\n******************************   TCP Packet   ******************************\n");

    unsigned short iphdrlen = 0;

    print_ether_header(buffer);
    if (isIpv4)
    {
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ether_header));
        iphdrlen = iph->ihl * 4;
        print_ip_header(buffer + sizeof(struct ether_header));
    }
    else
    {
        iphdrlen = 40;
        print_ipv6_header(buffer + sizeof(struct ether_header));
    }
    print_tcp_header(buffer + sizeof(struct ether_header) + iphdrlen);

    if (dump)
    {
        printf("                                 Data Dump                                 \n");

        printf("\nEthernet Header\n");
        print_data(buffer, sizeof(struct ether_header));

        printf("\nIP Header\n");
        print_data(buffer + sizeof(struct ether_header), iphdrlen);

        printf("\nTCP Header\n");
        print_data(buffer + sizeof(struct ether_header) + iphdrlen, sizeof(struct tcphdr));

        printf("\nData Payload\n");
        print_data(buffer + sizeof(struct ether_header) + iphdrlen + sizeof(struct tcphdr), size - iphdrlen - sizeof(struct tcphdr));
    }

    printf("\n############################################################################\n");
}

void print_udp_packet(unsigned char *buffer, int size, bool isIpv4)
{
    printf("\n******************************   UDP Packet   ******************************\n");

    unsigned short iphdrlen = 0;

    print_ether_header(buffer);
    if (isIpv4)
    {
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ether_header));
        iphdrlen = iph->ihl * 4;
        print_ip_header(buffer + sizeof(struct ether_header));
    }
    else
    {
        iphdrlen = 40;
        print_ipv6_header(buffer + sizeof(struct ether_header));
    }
    print_udp_header(buffer + sizeof(struct ether_header) + iphdrlen);

    if (dump)
    {
         printf("                                 Data Dump                                 \n");
        printf("\nEthernet Header\n");
        print_data(buffer + sizeof(struct ether_header), sizeof(struct ether_header));

        printf("\nIP Header\n");
        print_data(buffer + sizeof(struct ether_header), iphdrlen);

        printf("\nUDP Header\n");
        print_data(buffer + sizeof(struct ether_header) + iphdrlen, sizeof(struct udphdr));

        printf("\nData Payload\n");
        print_data(buffer + iphdrlen + sizeof(struct udphdr), size - iphdrlen - sizeof(struct udphdr));
    }

    printf("\n############################################################################\n");
}

void print_arp_packet(unsigned char *buffer, int size)
{
    printf("\n******************************   ARP Packet   ******************************\n");

    print_ether_header(buffer);
    print_arp_header(buffer + sizeof(struct ether_header));

    if (dump)
    {
         printf("                                 Data Dump                                 \n");

        printf("\nEthernet Header\n");
        print_data(buffer, sizeof(struct ether_header));

        printf("\nARP Header\n");
        print_data(buffer + sizeof(struct ether_header), sizeof(struct arphdr));

        printf("\nData Payload\n");
        print_data(buffer + sizeof(struct ether_header) + sizeof(struct arphdr), size - sizeof(struct ether_header) - sizeof(struct arphdr));
    }

    printf("\n############################################################################\n");
}

void print_icmp_packet(unsigned char *buffer, int size, bool isIpv4)
{
    printf("\n******************************   ICMP Packet   *****************************\n");

    unsigned short iphdrlen = 0;

    print_ether_header(buffer);
    if (isIpv4)
    {
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ether_header));
        iphdrlen = iph->ihl * 4;
        print_ip_header(buffer + sizeof(struct ether_header));
    }
    else
    {
        iphdrlen = 40;
        print_ipv6_header(buffer + sizeof(struct ether_header));
    }
    print_icmp_header(buffer + sizeof(struct ether_header) + iphdrlen);

    if (dump)
    {
        printf("                                 Data Dump                                 \n");

        printf("\nEthernet Header\n");
        print_data(buffer, sizeof(struct ether_header));

        printf("\nIP Header\n");
        print_data(buffer + sizeof(struct ether_header), iphdrlen);

        printf("\nData Payload\n");
        print_data(buffer + sizeof(struct ether_header) + iphdrlen + sizeof(struct icmphdr), size - sizeof(struct icmphdr) - iphdrlen);
    }

    printf("\n############################################################################\n");
}

void print_data(unsigned char *data, int size)
{
    for (int i = 0; i < size; i++)
    {
        if (i != 0 && i % 16 == 0)
        {
            printf("         ");
            for (int j = i - 16; j < i; j++)
            {
                if (data[j] > 32 && data[j] < 127)
                {
                    printf("%c", (unsigned char)data[j]); // if its a printable character
                }
                else
                {
                    printf("."); // otherwise print a dot
                }
            }
            printf("\n");
        }
        if (i % 16 == 0)
        {
            printf("   ");
        }
        printf(" %02X", (unsigned int)data[i]);
        if (i == size - 1) // print the last spaces
        {
            for (int j = 0; j < 15 - i % 16; j++)
            {
                printf("   "); // extra spaces
            }
            printf("         ");
            for (int j = i - i % 16; j <= i; j++)
            {
                if (data[j] >= 32 && data[j] <= 128)
                {
                    printf("%c", (unsigned char)data[j]);
                }
                else
                {
                    printf(".");
                }
            }
            printf("\n");
        }
    }
}
