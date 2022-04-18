#include <stdio.h>
#include <pcap.h>
#include <jsoncpp/json/json.h>
#include <fstream>
#include <iostream>
#include <arpa/inet.h>

#include <set>
#include <unordered_set>
#include "structures.h"

using namespace std;

class Filter {
private:
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip;               /* The IP header */
    const struct sniff_tcp *tcp;           /* The TCP header */
    struct arp_head *arp;
    const u_char *payload;                   /* Packet payload */

    int size_ethernet;
    int size_ip;
    int size_tcp;

    unordered_set<string> source_mac;
    unordered_set<string> destination_mac;
    unordered_set<string> source_ip;
    unordered_set<string> destination_ip;
    unordered_set<string> proto;
    struct ether_addr smac;
    struct ether_addr dmac;
    int countPacket;
    u_short ftype;

public:
    Filter();
    ~Filter();

    void to_json(); // запись в файл
    void callback(u_char *useless, pcap_pkthdr *header, const u_char *packet); // обработка пакетов
};