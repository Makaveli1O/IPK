/* *** *** *** *** *** *** *** */
/* IPK - proj2 Packet sniffer  */
/* 	 Samuel Líška (xliska20)   */
/* *** *** *** *** *** *** *** */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> //getopt
#include <string.h>
#include <getopt.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include<netinet/udp.h> //used this library to hande UDP packets(to try both methods out)
#include<sys/time.h>
#include<stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
/*IP sniffing defines*/
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
/*tcp sniffer defines*/
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;
struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_payload(const u_char *payload, int len);

void print_hex(const u_char *payload, int len, int offset);
void print_hostname(char *addr);

void print_hostname(char *addr){
    struct sockaddr_in sa;
    char node[NI_MAXHOST];
 
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
     
    inet_pton(AF_INET, addr, &sa.sin_addr);
 
    int res = getnameinfo((struct sockaddr*)&sa, sizeof(sa),
                          node, sizeof(node),
                          NULL, 0, NI_NAMEREQD);
     
    if (res) {
        printf("%s",addr);
    }
    else
        printf("%s", node);
     
    return ;
}

void print_hex(const u_char *payload, int len, int offset){

	int i;
	int gap;
	const u_char *ch;

	// print offset in hex numeric system
	printf("0x%04x   ", offset);

	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		//space every 8th character (according to desired output)
		if (i == 7)
			printf(" ");
	}
	// print for less than 8 bytes 
	if (len < 8)
		printf(" ");
	
	// fill gap with spaces if not full line
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	// ascii 
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}


void print_payload(const u_char *payload, int len){

	int len_rem = len;
	int line_width = 16;			
	int line_len;
	int offset = 0;					
	const u_char *ch = payload;

	if (len <= 0)
		return;

	// check whenever data fits one line
	if (len <= line_width){
		print_hex(ch, len, offset);
		return;
	}

	// multiple lines
	while(true){
		//current LL
		line_len = line_width % len_rem;
		print_hex(ch, line_len, offset);
		//remaining
		len_rem = len_rem - line_len;
		// shift pointer to remaining bytes to print 
		ch = ch + line_len;
		offset = offset + line_width;
		// check if we have line width chars
		if (len_rem <= line_width) {
			print_hex(ch, len_rem, offset);
			break;
		}
	}

return;
}

int only_TCP=0;
int only_UDP=0;
int port = 0;

/*
 * dissect/print packet
 */
int counter = 0;
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	//set time
	struct tm *time_str_tm;
	struct timeval time_now;
	gettimeofday(&time_now, NULL);
	time_str_tm = gmtime(&time_now.tv_sec);
	
	// declare pointers to packet headers 
	const struct sniff_ethernet *ethernet;  
	const struct sniff_ip *ip;              
	const struct sniff_tcp *tcp;            
	const u_char *payload;                   

	int size_ip;
	int size_tcp;
	int size_udp;
	int size_payload;
	
	
	//ethernet header
	ethernet = (struct sniff_ethernet*)(packet);
	
	//offset
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	//determine whenever TCP or UDP is catched
	switch(ip->ip_p){
		case IPPROTO_UDP:
			only_UDP = 1;
			only_TCP = 0;
			break;
		case IPPROTO_TCP:
			only_TCP = 1;
			only_UDP = 0;
			break;
	}

	/* forced to use strdup to save string, since inet_ntoa() returns the dots-and-numbers string
	 in a static buffer that is overwritten with each call to the function.*/
	char *ip_src=strdup(inet_ntoa(ip->ip_src));
	char *ip_dst=strdup(inet_ntoa(ip->ip_dst));

//TCP PACKET
	if(only_TCP == 1){
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		/*if (size_tcp < 20) {
			printf("Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}*/
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		
		/* tcp payload size */
		size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
		//this is often 0 
		//format output
		//čas IP|FQDN : port > IP|FQDN : port
		/*TIME*/
		printf("%02i:%02i:%02i.%06i ",time_str_tm->tm_hour+2, time_str_tm->tm_min, time_str_tm->tm_sec, time_now.tv_usec);
		/*IP's info*/
		print_hostname(ip_src);
		printf(" : %d > ",ntohs(tcp->th_sport));
		print_hostname(ip_dst);
		printf(" : %d\n\n",ntohs(tcp->th_dport));
		print_payload(payload, size_payload);
		printf("\n");
			
		return;
	}else if(only_UDP){
		/*UDP OFFSET*/
    	struct udphdr *udph = (struct udphdr*)(packet + size_ip  + SIZE_ETHERNET);
    	size_udp =  SIZE_ETHERNET + size_ip + sizeof udph;
    	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
    	size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
		printf("%02i:%02i:%02i.%06i ",time_str_tm->tm_hour+2, time_str_tm->tm_min, time_str_tm->tm_sec, time_now.tv_usec);
		/*IP's info*/
		print_hostname(ip_src);
		printf(" : %d > ",ntohs(udph->uh_sport));
		print_hostname(ip_dst);
		printf(" : %d\n\n",ntohs(udph->uh_dport));
		print_payload(payload, size_payload);
		printf("\n");
	}
	free(ip_src);
	free(ip_dst);
}

int main(int argc, char **argv){
	char c; 		//input arguments of program
	char *interface; //give interface
	interface[0] = '\0';
	int display_packets = 0;
	char *ptr;
	char errbuf[PCAP_ERRBUF_SIZE];
	bool n_used=false;
	char port_str[4];

	static struct option long_options[] =
	{
	    {"i", required_argument, NULL, 'i'},
	    {"p", required_argument, NULL, 'p'},
	    {"tcp", no_argument, NULL, 't'},
	    {"udp", no_argument, NULL, 'u'},
	    {"n", required_argument, NULL, 'n'},
	    {NULL, 0, NULL, 0}
	};

	while ((c = getopt_long(argc, argv, "i:p:tun:", long_options, NULL)) != -1)
	{
	    // check to see if a single character or long option came through
	    switch (c)
	    {
	        case 'i':
	        	strcpy(interface, optarg);
	            break;
	        case 'p':
	        	port = strtoul(optarg, &ptr, 10);
	        	if (ptr[0] != '\0'){
	        		fprintf(stderr, "ERROR: Wrong input arguments.\n");
	        		exit(1);
	        	}
	        	strcpy(port_str, optarg);
	            break;
	        case 't':
	            only_TCP = 1;
	            break;
	        case 'u':
	            only_UDP = 1;
	            break;
	        case 'n':
	            display_packets = strtoul(optarg, &ptr, 10);
	            n_used = true;
	        	if (ptr[0] != '\0'){
	        		fprintf(stderr, "ERROR: Wrong input arguments.\n");
	        		exit(1);
	        	}
	            break;
	    }
	}

		/*if none interface was given*/
	if (interface[0] == '\0'){
		pcap_if_t *interfaces,*temp;
		int i = 0;
		printf("No device was inputed through the command line. List of available devices: \n");
		if(pcap_findalldevs(&interfaces,errbuf)==-1){
        	fprintf(stderr,"ERROR:Error in pcap findall devs.\n");
        	exit(EXIT_FAILURE);    
    	}
		for(temp=interfaces;temp;temp=temp->next)
        	printf("%d  :  %s\n",i++,temp->name);
    	exit(0);
	}

	if (!n_used)
		display_packets = 1;
	/*This will specify what we are looking for*/
	//if neither used, both are 1
	if ((only_TCP == 0 && only_UDP == 0) || (only_UDP == 1 && only_TCP == 1)){
		only_TCP = 0;
		only_UDP = 0;
		if (port != 0){
			strcpy(ptr, "tcp port ");
			strcat(ptr,port_str);
			strcat(ptr, " or udp port ");
			strcat(ptr,port_str);
		}else{
			strcpy(ptr, "ip");
		}
	}else if(only_UDP == 1 && only_TCP == 0){
		strcpy(ptr, "udp");
		if (port != 0){
			strcat(ptr, " port ");
			strcat(ptr, port_str);
		}
	}else if(only_UDP == 0 && only_TCP == 1){
		strcpy(ptr, "tcp");
		if (port != 0){
			strcat(ptr, " port ");
			strcat(ptr, port_str);
		}
	}

	pcap_t *handle;					//capture packet
	char *filter_exp;
	filter_exp = (char*)malloc(100*sizeof(char));
	strcpy(filter_exp, ptr);
	struct bpf_program fp;			//compiled filter program
	bpf_u_int32 mask;				//subnet mask
	bpf_u_int32 net;				// ip adress
	
	/* get network and mask for interface (ifconfig) */
	if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1){
		fprintf(stderr, "ERROR: Error getting mask and network.\n");
		net = 0;
		mask = 0; //not useful now
	}
	//seg ffault using -u here wtf
	// open capture interface
	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL){
		fprintf(stderr, "Device %s cant be opened. ERROR: %s\n", interface, errbuf);
		exit(EXIT_FAILURE);
	}
	//compile filter expression
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
		fprintf(stderr, "Unable to parse filter %s: %s\n",filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	// apply the compiled filter 
	if (pcap_setfilter(handle, &fp) == -1){
		fprintf(stderr, "ERROR: Set filter returned negative.Filter: %s ERROR: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	/* loop through the packets*/

	pcap_loop(handle, display_packets, got_packet, NULL);

	free(filter_exp);
	pcap_freecode(&fp);
	pcap_close(handle);
	
	return 0;
}


