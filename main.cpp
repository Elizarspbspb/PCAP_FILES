#include <stdio.h>
#include <pcap.h>
#include <jsoncpp/json/json.h>
#include <fstream>
#include <iostream>
#include <cstring>

#include <set>
#include <unordered_set>

#include <netinet/ether.h>

using namespace std;

/* Ethernet header 6 byte*/
struct sniff_ethernet
{
    struct ether_addr ether_dhost;
    struct ether_addr ether_shost;
    u_short ether_type;					/* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip
{
    u_char ip_vhl;				   /* version << 4 | header length >> 2 */
    u_char ip_tos;				   /* type of service */
    u_short ip_len;				   /* total length */
    u_short ip_id;				   /* identification */
    u_short ip_off;				   /* fragment offset field */
#define IP_RF 0x8000			   /* reserved fragment flag */
#define IP_DF 0x4000			   /* don't fragment flag */
#define IP_MF 0x2000			   /* more fragments flag */
#define IP_OFFMASK 0x1fff		   /* mask for fragmenting bits */
    u_char ip_ttl;				   /* time to live */
    u_char ip_p;				   /* protocol */
    u_short ip_sum;				   /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;
struct sniff_tcp
{
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    tcp_seq th_seq;	  /* sequence number */
    tcp_seq th_ack;	  /* acknowledgement number */
    u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
};
#define SIZE_ETHERNET 14

/*UDP header*/
struct sniff_udp
{
    u_short udp_sport;
    u_short udp_dport;
    u_short udp_len;
    u_short udp_sum;
};

/*arp*/
struct arp_head
{
    u_char hardware_type[2];
    u_char protocol_type[2];
    u_char hardware_size;
    u_char protocol_size;
    u_char opcode[2];
    u_char  send_mac[6];
    struct in_addr  send_ip;
    u_char  target_mac[6];
    struct in_addr  target_ip;

}__attribute__((packed));

class Filter
{
public:
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip;			   /* The IP header */
    const struct sniff_tcp *tcp;		   /* The TCP header */
    struct arp_head *arp;
    const u_char *payload;				   /* Packet payload */

    int size_ethernet;
    int size_ip;
    int size_tcp;

    unordered_set <string> source_mac;
    unordered_set <string> destination_mac;
    unordered_set <string> source_ip;
    unordered_set <string> destination_ip;
    set <u_short> protocols_ethernet;
    unordered_set <string> proto;
    struct ether_addr smac;
    struct ether_addr dmac;
    int countPacket;
    u_short ftype;

    Filter(){
        size_ethernet = sizeof(struct sniff_ethernet);
        size_ip = sizeof(struct sniff_ip);
        size_tcp = sizeof(struct sniff_tcp);
        countPacket = 0;
        ftype = 0;
    };

    ~Filter()
    {
        source_mac.clear();
        destination_mac.clear();
        source_ip.clear();
        destination_ip.clear();
        protocols_ethernet.clear();
        proto.clear();
        countPacket = 0;
    }

    void json()
    {
        // root
        Json::Value root;

        // array form
        for ( auto it = source_mac.begin(); it != source_mac.end(); ++it ) {
            std::cout << " " << *it;
            root["src_mac"].append(*it);
        }
        for ( auto it = destination_mac.begin(); it != destination_mac.end(); ++it ) {
            std::cout << " " << *it;
            root["dst_mac"].append(*it);
        }

        for ( auto it = source_ip.begin(); it != source_ip.end(); ++it ) {
            std::cout << " " << *it;
            root["src_ip"].append(*it);
        }
        for ( auto it = destination_ip.begin(); it != destination_ip.end(); ++it ) {
            std::cout << " " << *it;
            root["dst_ip"].append(*it);
        }

        for ( auto it = proto.begin(); it != proto.end(); ++it ) {
            std::cout << " " << *it;
            root["proto"].append(*it);
        }

        cout << "StyledWriter:" << endl;
        Json::StyledWriter sw;
        //cout << sw.write(root) << endl << endl;

        // output to a file
        ofstream os;
        os.open("demo.json");
        os << sw.write(root);
        os.close();
    }

}filter;

void callback(u_char *useless, const struct pcap_pkthdr *header, const u_char *packet)
{
    filter.ethernet = (struct sniff_ethernet *)(packet);
    filter.ip = (struct sniff_ip *)(packet + filter.size_ethernet);
    filter.tcp = (struct sniff_tcp *)(packet + filter.size_ethernet + filter.size_ip);
    filter.arp = (struct arp_head *)(packet + filter.size_ethernet);
    filter.payload = (u_char *)(packet + filter.size_ethernet + filter.size_ip + filter.size_tcp);

    char ether_smac[256];
    char ether_dmac[256];

    cout << "Packet number: " << filter.countPacket++ << endl;
    cout << "Packet size: " << header->len << " bytes" << endl;
    cout << endl;

    filter.ftype=ntohs(filter.ethernet->ether_type);
    cout << "Packet type = " << filter.ftype << endl;

    filter.smac=filter.ethernet->ether_shost;
    sprintf(ether_smac,"%02x:%02x:%02x:%02x:%02x:%02x",filter.smac.ether_addr_octet[0],filter.smac.ether_addr_octet[1],filter.smac.ether_addr_octet[2],filter.smac.ether_addr_octet[3],filter.smac.ether_addr_octet[4],filter.smac.ether_addr_octet[5]);
    cout << "Source MAC: " << ether_smac << endl;
    filter.source_mac.insert(ether_smac);

    filter.dmac=filter.ethernet->ether_dhost;
    sprintf(ether_dmac,"%02x:%02x:%02x:%02x:%02x:%02x",filter.dmac.ether_addr_octet[0],filter.dmac.ether_addr_octet[1],filter.dmac.ether_addr_octet[2],filter.dmac.ether_addr_octet[3],filter.dmac.ether_addr_octet[4],filter.dmac.ether_addr_octet[5]);
    cout << "Destination MAC: " << ether_dmac << endl;
    filter.destination_mac.insert(ether_dmac);

    cout << endl;
    switch(filter.ftype){
        case 0x0800:
            cout << endl;
            cout << "IP Version = " << (filter.ip->ip_vhl) << endl;
            cout << "IP Source Address = " << inet_ntoa(filter.ip->ip_src) << endl;
            cout << "IP Dest Address = " << inet_ntoa(filter.ip->ip_dst) << endl;

            cout << "TCP source port = " << ntohs(filter.tcp->th_sport) << endl;
            cout << "TCP dest port = " << ntohs(filter.tcp->th_dport) << endl;
            //cout << "Packet handled = " << (char *)payload << endl;

            filter.source_ip.insert(inet_ntoa(filter.ip->ip_src));
            filter.destination_ip.insert(inet_ntoa(filter.ip->ip_dst));
            filter.proto.insert("IPv4");

            switch (filter.ip->ip_p) //Check the Protocol and do accordingly...
            {
                case 1:  //ICMP Protocol
                    filter.proto.insert("ICMP");
                    break;
                case 2:  //IGMP Protocol
                    filter.proto.insert("IGMP");
                    break;
                case 6:  //TCP Protocol
                    filter.proto.insert("TCP");
                    break;
                case 17: //UDP Protocol
                    filter.proto.insert("UDP");
                    break;
                default: //Some Other Protocol like ARP etc.
                    filter.proto.insert("Some Other Protocol");
                    break;
            }
            break;

        case 0x0806:
            cout << endl;

            filter.proto.insert("ARP");
            filter.source_ip.insert(inet_ntoa(filter.arp->send_ip));
            filter.destination_ip.insert(inet_ntoa(filter.arp->target_ip));
            break;

        case 0x8100:
            filter.proto.insert("8021Q");
            filter.source_ip.insert(inet_ntoa(filter.arp->send_ip));
            filter.destination_ip.insert(inet_ntoa(filter.arp->target_ip));
            break;

        case 0x86dd:
            filter.proto.insert("IPV6");
            filter.source_ip.insert(inet_ntoa(filter.arp->send_ip));
            filter.destination_ip.insert(inet_ntoa(filter.arp->target_ip));
            break;

        case 0x880b:
            filter.proto.insert("PPP");
            filter.source_ip.insert(inet_ntoa(filter.arp->send_ip));
            filter.destination_ip.insert(inet_ntoa(filter.arp->target_ip));
            break;

        case 0x8863:
            filter.proto.insert("PPPOED");
            filter.source_ip.insert(inet_ntoa(filter.arp->send_ip));
            filter.destination_ip.insert(inet_ntoa(filter.arp->target_ip));
            break;

        default:
            cout << "EEROR TYPE FRAME" << endl;
    }
    cout << endl << "--------------------------------------" << endl;
}

int main(int argc, char *argv[]) {

    std::string file = argv[1];
    bpf_u_int32 net = 0;            // IP устройства
    bpf_u_int32 mask = 0;           // сетевая маска
    pcap_if_t *alldevs;
    pcap_t *adhandle;           // descriptor live session
    struct bpf_program fcode;   // Скомпилированный фильтр

    char *dev, errbuff[PCAP_ERRBUF_SIZE];

    pcap_t *pcap = pcap_open_offline_with_tstamp_precision(file.c_str(), PCAP_TSTAMP_PRECISION_MICRO, errbuff);
    struct pcap_pkthdr *header;
    const u_char *data;

    /*dev = pcap_lookupdev(errbuff); // ald version
    if(pcap_lookupnet(dev, &net, &mask, errbuff) < 0) // получает номер/маску сети
    {
        fprintf(stderr, "Cant get netmask for device %s\n", dev);
        cout << "Cant get netmask for device " << dev << endl;
        net = 0;
        mask = 0;
        //return -2;
    }
    cout << "Device live interface = " << dev << endl;*/

    /*net_addr.s_addr = net;
    net_s = inet_ntoa(net_addr);
    printf("NET : %s\n", net_s);

    mask_addr.s_addr = mask;
    mask_s = inet_ntoa(mask_addr);
    printf("MASK : %s\n", mask_s);*/

    cout << endl << "________________" << endl;

    /*if(pcap_compile(pcap, &fcode, "", 1, net) < 0) // компиляция фильтра заданным регулярным выражением
    {
        fprintf(stderr, "\nunable syntax: %s\n", pcap_geterr(pcap));
        cout << "unable syntax: " << pcap_geterr(pcap) << endl; // информация об ошибке
        pcap_freealldevs(alldevs);
    }

    if(pcap_setfilter(pcap, &fcode) < 0) // применение фильтра
    {
        fprintf(stderr, "\nerror in setting filter: %s\n", pcap_geterr(pcap));
        cout << "error in setting filter: " << pcap_geterr(pcap) << endl;  // информация об ошибке
        pcap_freealldevs(alldevs);
    }*/

    pcap_loop(pcap, 0, callback, NULL);

    pcap_close(pcap);

    filter.json();

    cout << "FINISH" << endl;
    return (0);
}