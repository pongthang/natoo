/*
	Packet sniffer using libpcap library
*/
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset

#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <libnet.h>
#include <sys/socket.h>

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);
void print_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *  , int );
void * send_http_request();

#define KNOWN_OS 10
#define MAX_LIMIT 50
// OS database

struct os_prop
{
    char name[100];
    float score;
};


struct os_prop os_matrix[KNOWN_OS];


struct os_prop os;

char dist_ip[20]; //="172.16.11.85";
int port__;
void initialize_os_matrix()
{
    
    strcpy(os_matrix[0].name, "Windows");
    strcpy(os_matrix[1].name, "Windows");
    strcpy(os_matrix[2].name, "Windows");
    strcpy(os_matrix[3].name, "Linux");
    strcpy(os_matrix[4].name, "FreeBSD");
    strcpy(os_matrix[5].name, "Mac OS");

    strcpy(os_matrix[6].name, "Symbian");
    strcpy(os_matrix[7].name, "Palm OS");
    strcpy(os_matrix[8].name, "NetBSD");
    strcpy(os_matrix[9].name, "Open BSD");
    
    

}//end initialize_os_matrix



//Filters
struct bpf_program filter;


pthread_t request_thread;

FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;	

int main(int argc, char **argv)
{
	pcap_if_t *alldevsp , *device;
	pcap_t *handle; //Handle of the device that shall be sniffed

	char errbuf[100] , *devname , devs[100][100];
	int count = 1 , n;
	
	//First get the list of available devices
	// printf("Finding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		// printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	// printf("Done");
	
	//Print the available devices
	// printf("\nAvailable Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		// printf("%d. %s - %s\n" , count , device->name , device->description);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}
	
	//Ask user which device to sniff
	// printf("Enter the number of the device you want to sniff : ");
	// scanf("%d" , &n);
  n = 1;
	devname = devs[n];

    

    // printf("Enter the port for os detection : ");
	// scanf("%d" , &port__);
    port__=atoi(argv[2]);
    char pport[20];

    sprintf(pport, "%d", port__);

    // char str[20] = "172.16.11.85";
    // printf("Dist IP : ");
    // scanf("%[^\n]%*c", str);
    strcpy(dist_ip,argv[1]);

    char p[MAX_LIMIT] = "src ";
    strcat(p,dist_ip);
    // char and[] = " and dst port ";

    // strcat(p,and);

    // strcat(p,pport);
   
    


	// printf("Opening device %s for sniffing ... " , devname);
	handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
	
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
		exit(1);
	}
	// printf("Done\n");
	
	logfile=fopen("log.txt","w");
	if(logfile==NULL) 
	{
		printf("Unable to create file.");
	}
	
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;		/* The IP of our sniffing device */

    if (pcap_lookupnet(devname, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", devname);
        net = 0;
        mask = 0;
    }

    if (pcap_compile(handle, &filter, p, 0, net) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    initialize_os_matrix();
    ///////////////////////////
    /////thread
    pthread_create(&request_thread, NULL, send_http_request, NULL);
	//Put the device in sniff loop
	pcap_loop(handle , 1 , process_packet , NULL);

    // printf("OS detection: \n");
    float score_max=0;
    int index=0;
    for(int i=0;i<10;i++){
        if(os_matrix[i].score>=score_max){
            score_max=os_matrix[i].score;
            index=i;

        }else score_max=score_max;

        

    }
 
    printf("\nOs detected --> %s \n",os_matrix[index].name);
    
	
	return 0;	
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
	
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		case 1:  //ICMP Protocol
			++icmp;
			//print_icmp_packet( buffer , size);
			break;
		
		case 2:  //IGMP Protocol
			++igmp;
			break;
		
		case 6:  //TCP Protocol
			++tcp;
			print_tcp_packet(buffer , size);
			break;
		
		case 17: //UDP Protocol
			++udp;
			//print_udp_packet(buffer , size);
			break;
		
		default: //Some Other Protocol like ARP etc.
			++others;
			break;
	}
    
    
	printf("\rTCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d", tcp , udp , icmp , igmp , others , total);
}


void print_ip_header(const u_char * Buffer, int Size)
{
  
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
    unsigned int TTL=(unsigned int)iph->ttl;
    if (TTL>=0 &&TTL<=64){
        os_matrix[3].score+=0.5;
        os_matrix[4].score+=0.5;
        os_matrix[5].score+=0.5;
        os_matrix[8].score+=0.5;
        os_matrix[9].score+=0.5;
    }else if(TTL>=64 && TTL<=128){
        os_matrix[0].score+=0.5;
        os_matrix[1].score+=0.5;
        os_matrix[2].score+=0.5;
    }else if(TTL>=128 && TTL<=255){
        os_matrix[6].score+=0.5;
        os_matrix[7].score+=0.5;
        
    }
    if(Size==44){
        os_matrix[6].score+=1;
        os_matrix[7].score+=1;
    }else if(Size==48){
        os_matrix[0].score+=1;
        
    }else if(Size==52){
        os_matrix[1].score+=1;
        os_matrix[2].score+=1;
    }else if(Size==60){
        os_matrix[3].score+=1;
        os_matrix[4].score+=1;
    }else if(Size==64){
        os_matrix[8].score+=1;
        os_matrix[9].score+=1;
    }
    


}

void print_tcp_packet(const u_char * Buffer, int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
			
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
		
		
	print_ip_header(Buffer,Size);
    
	uint16_t win= ntohs(tcph->window);
  if (win) {
    ++os_matrix[0].score;
    ++os_matrix[1].score;
    ++os_matrix[2].score;
  }

    if(win>=2920 && win<=584014600){
        os_matrix[3].score+=1;
    } else if(win==65550){
        os_matrix[4].score+=1;
    }

    unsigned int ACK = (unsigned int)tcph->ack;

    if(ACK){
        os_matrix[0].score+=1;
        os_matrix[1].score+=1;
        os_matrix[2].score+=1;
        os_matrix[3].score+=1;
        os_matrix[4].score+=1;
        os_matrix[9].score+=1;
    }else{
        os_matrix[5].score+=1;
        os_matrix[6].score+=1;
        os_matrix[7].score+=1;
        os_matrix[8].score+=1;
    }
	
}


void * send_http_request() {
    for(int i=0;i<1;i++){
    int sock = 0, valread;
	struct sockaddr_in serv_addr;
	char* hello = ((char*)("GET / HTTP/1.0\n\n"));
	char buffer[1024] = { 0 };
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("\n Socket creation error \n");
		
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port__);

	// Convert IPv4 and IPv6 addresses from text to binary
	// form
	if (inet_pton(AF_INET, dist_ip, &serv_addr.sin_addr) <= 0) {
		printf("\nInvalid address/ Address not supported \n");
		
	}

	if (connect(sock, (struct sockaddr*)&serv_addr,sizeof(serv_addr))< 0) {
		printf("\nConnection Failed \n");
		
	}
	send(sock, hello, strlen(hello), 0);
	//printf("Hello message sent\n");
	valread = read(sock, buffer, 1024);
	//printf("%s\n", buffer);
    
    sleep(1);
    }
    
}
