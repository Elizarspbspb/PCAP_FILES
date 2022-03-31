#include <string>
#include <iostream>
#include <fstream>
#include <pcap.h>

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "formjson.h"
#include "protocols.h"

extern std::vector<int> mas_prot;
//extern std::vector<const char *> source_mac;
extern std::vector<in_addr> source_ip;
//extern std::vector<string> destination_mac;
extern std::vector<in_addr> destination_ip;

extern int count_p;
extern int count_sm;
extern int packetCount;

void callback(u_char *useless, const struct pcap_pkthdr *header, const u_char *packet);