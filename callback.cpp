#pragma once

#include <string>
#include <iostream>
#include "callback.h"

using namespace std;
vector<int> mas_prot;
vector<in_addr> source_ip;
vector<in_addr> destination_ip;
int packetCount = 0;
int count_p = 1;
int count_sm = 1;
bool flag=1;
bool flag_sm=1;
bool flag_dm=1;
bool flag_si=1;
bool flag_di=1;
int chcnt = 0;

void callback(u_char *useless, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *ep;
    struct ip *iph;
    struct tcphdr *tcp;
    unsigned short ether_type;
    int len = header->len;
    int i;

    // Get Ethernet header.
    ep = (struct ether_header *)packet;

    // Get upper protocol type.
    ether_type = ntohs(ep->ether_type);

    printf("Packet # %i\n", ++packetCount);
    printf("Packet size: %d bytes\n", header->len);
    if(header->len != header->caplen)
        printf("\nCapture size different than packet size %ld bytes\n", header->len);
    printf("Epoch time: %d:%d seconds\n", header->ts.tv_sec, header->ts.tv_usec);

    //printf("ether_type = %hu\n", ether_type);
    //print_number(ether_type, 16);

    //if (ether_type == ETHERTYPE_IP)
    //{
        cout << "ETHERNET II" << endl;
        printf("ETHER Source Address = ");
        for (i=0; i<ETH_ALEN; ++i)
            printf("%.2X ", ep->ether_shost[i]);
        printf("\n");
        printf("ETHER Dest Address = ");
        for (i=0; i<ETH_ALEN; ++i)
            printf("%.2X ", ep->ether_dhost[i]);
        printf("\n");

        cout  << endl << "###############" << endl;
        cout << "INTERNET PROTOCOL VERSION 4" << endl;

        // сдвигаем указатель на уровень выше
        packet += sizeof(struct ether_header);
        iph = (struct ip *)packet;
        printf("IP Ver = %d\n", iph->ip_v);
        printf("IP Header len = %d\n", iph->ip_hl<<2);
        printf("IP Source Address = %s\n", inet_ntoa(iph->ip_src));
        printf("IP Dest Address = %s\n", inet_ntoa(iph->ip_dst));
        printf("Protocols = %d\n", iph->ip_p);
        cout << "Protocols_Name = " << protocols_p(iph->ip_p) << endl;
        printf("IP Packet size = %d\n", len-16);
        printf("packet2 = %hu\n", packet);


        source_ip.push_back(iph->ip_src);
        destination_ip.push_back(iph->ip_dst);

        if(flag==1) {
            mas_prot.push_back(iph->ip_p);
        }
        for (int i = 0; i < count_p; i++) {
            if(mas_prot[i]==iph->ip_p)
            {
                flag=1;
                break;
            }
        }
        if(flag==0) {
            mas_prot.push_back(iph->ip_p);
            count_p++;
        }
        flag = 0;

        cout << endl << "###############" << endl;
        cout << "TRANSMISSION CONTROL PROTOCOL" << endl;
        if(iph->ip_p == 6)
        {
            packet += sizeof(struct ip);  // сдвигаем указатель на уровень выше
            tcp = (struct tcphdr *)packet;
            printf("Source port = %hu\n", tcp->th_sport);
            printf("Dest port = %hu\n", tcp->th_dport);
            printf("packet3 = %hu\n", packet);
        }

    /*}
    else if(ether_type == ETHERTYPE_ARP)
    {
        cout << "\tARP protocol" << endl;
        printf("ETHER Source Address = ");
        for (i=0; i<ETH_ALEN; ++i)
            printf("%.2X ", ep->ether_shost[i]);
        printf("\n");
        printf("ETHER Dest Address = ");
        for (i=0; i<ETH_ALEN; ++i)
            printf("%.2X ", ep->ether_dhost[i]);
        printf("\n");
    }
    else
    {
        printf("ETHER Source Address = ");
        for (i=0; i<ETH_ALEN; ++i)
            printf("%.2X ", ep->ether_shost[i]);
        printf("\n");
        printf("ETHER Dest Address = ");
        for (i=0; i<ETH_ALEN; ++i)
            printf("%.2X ", ep->ether_dhost[i]);
        printf("\n");

        // Move packet pointer for upper protocol header.
        packet += sizeof(struct ether_header);
        iph = (struct ip *)packet;
        printf("IP Ver = %d\n", iph->ip_v);
        printf("IP Header len = %d\n", iph->ip_hl<<2);
        printf("IP Source Address = %s\n", inet_ntoa(iph->ip_src));
        printf("IP Dest Address = %s\n", inet_ntoa(iph->ip_dst));
        printf("Protocols = %d\n", iph->ip_p);
        printf("IP Packet size = %d\n", len-16);
    }*/
    printf("\n-------------------------------------------------------------------\n");
    chcnt++;
}