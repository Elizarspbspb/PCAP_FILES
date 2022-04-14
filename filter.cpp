#include "filter.h"

void Filter::to_json() {
    // root
    Json::Value root;
    // array form
    for (auto it = source_mac.begin(); it != source_mac.end(); ++it) {
        std::cout << " " << *it;
        root["src_mac"].append(*it);
    }
    for (auto it = destination_mac.begin(); it != destination_mac.end(); ++it) {
        std::cout << " " << *it;
        root["dst_mac"].append(*it);
    }
    for (auto it = source_ip.begin(); it != source_ip.end(); ++it) {
        std::cout << " " << *it;
        root["src_ip"].append(*it);
    }
    for (auto it = destination_ip.begin(); it != destination_ip.end(); ++it) {
        std::cout << " " << *it;
        root["dst_ip"].append(*it);
    }
    for (auto it = proto.begin(); it != proto.end(); ++it) {
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

void Filter::callback(u_char *useless, pcap_pkthdr *header, const u_char *packet) {
    ethernet = (struct sniff_ethernet *)(packet);
    ip = (struct sniff_ip *)(packet + size_ethernet);
    tcp = (struct sniff_tcp *)(packet + size_ethernet + size_ip);
    arp = (struct arp_head *)(packet + size_ethernet);
    payload = (u_char *)(packet + size_ethernet + size_ip + size_tcp);

    char ether_smac[256];
    char ether_dmac[256];

    cout << "Packet number: " << countPacket++ << endl;
    //cout << "Packet size: " << header->len << " bytes" << endl;
    cout << endl;

    ftype=ntohs(ethernet->ether_type);
    cout << "Packet type = " << ftype << endl;

    smac=ethernet->ether_shost;
    sprintf(ether_smac,"%02x:%02x:%02x:%02x:%02x:%02x",smac.ether_addr_octet[0],smac.ether_addr_octet[1],smac.ether_addr_octet[2],smac.ether_addr_octet[3],smac.ether_addr_octet[4],smac.ether_addr_octet[5]);
    cout << "Source MAC: " << ether_smac << endl;
    source_mac.insert(ether_smac);

    dmac=ethernet->ether_dhost;
    sprintf(ether_dmac,"%02x:%02x:%02x:%02x:%02x:%02x",dmac.ether_addr_octet[0],dmac.ether_addr_octet[1],dmac.ether_addr_octet[2],dmac.ether_addr_octet[3],dmac.ether_addr_octet[4],dmac.ether_addr_octet[5]);
    cout << "Destination MAC: " << ether_dmac << endl;
    destination_mac.insert(ether_dmac);

    cout << endl;
    switch(ftype){
        case 0x0800:
            cout << endl;
            cout << "IP Version = " << (ip->ip_vhl) << endl;
            cout << "IP Source Address = " << inet_ntoa(ip->ip_src) << endl;
            cout << "IP Dest Address = " << inet_ntoa(ip->ip_dst) << endl;

            cout << "TCP source port = " << ntohs(tcp->th_sport) << endl;
            cout << "TCP dest port = " << ntohs(tcp->th_dport) << endl;
            //cout << "Packet handled = " << (char *)payload << endl;

            source_ip.insert(inet_ntoa(ip->ip_src));
            destination_ip.insert(inet_ntoa(ip->ip_dst));
            proto.insert("IPv4");

            switch (ip->ip_p) //Check the Protocol and do accordingly...
            {
                    case 1:  //ICMP Protocol
                        proto.insert("ICMP");
                        break;
                    case 2:  //IGMP Protocol
                        proto.insert("IGMP");
                        break;
                    case 6:  //TCP Protocol
                        proto.insert("TCP");
                        break;
                    case 17: //UDP Protocol
                        proto.insert("UDP");
                        break;
                    default: //Some Other Protocol like ARP etc.
                        proto.insert("Some Other Protocol");
                        break;
            }
            break;

        case 0x0806:
            proto.insert("ARP");
            source_ip.insert(inet_ntoa(arp->send_ip));
            destination_ip.insert(inet_ntoa(arp->target_ip));
            break;

        case 0x8100:
            proto.insert("8021Q");
            source_ip.insert(inet_ntoa(arp->send_ip));
            destination_ip.insert(inet_ntoa(arp->target_ip));
            break;

        case 0x86dd:
            proto.insert("IPV6");
            source_ip.insert(inet_ntoa(arp->send_ip));
            destination_ip.insert(inet_ntoa(arp->target_ip));
            break;

        case 0x880b:
            proto.insert("PPP");
            source_ip.insert(inet_ntoa(arp->send_ip));
            destination_ip.insert(inet_ntoa(arp->target_ip));
            break;

        case 0x8863:
            proto.insert("PPPOED");
            source_ip.insert(inet_ntoa(arp->send_ip));
            destination_ip.insert(inet_ntoa(arp->target_ip));
            break;

        default:
            cout << "EEROR TYPE FRAME" << endl;
    }
    cout << endl << "--------------------------------------" << endl;
}