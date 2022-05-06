#include "filter.h"

Filter::Filter() {
    size_ethernet = sizeof(struct sniff_ethernet);
    size_ip = sizeof(struct sniff_ip);
    size_tcp = sizeof(struct sniff_tcp);
    countPacket = 0;
    ftype = 0;
}

Filter::~Filter() {
    source_mac.clear();
    destination_mac.clear();
    source_ip.clear();
    destination_ip.clear();
    proto.clear();
    unic_ipport.clear();
    session_ip.clear();
    countPacket = 0;
}

void Filter::to_json() {
    // root
    Json::Value root;
    // array form
    for (auto it = source_mac.begin(); it != source_mac.end(); ++it) {
        //std::cout << " " << *it;
        root["src_mac"].append(*it);
    }
    for (auto it = destination_mac.begin(); it != destination_mac.end(); ++it) {
        //std::cout << " " << *it;
        root["dst_mac"].append(*it);
    }

    for (auto it = source_ip.begin(); it != source_ip.end(); ++it) {
        //std::cout << " " << *it;
        root["src_ip"].append(*it);
    }
    for (auto it = destination_ip.begin(); it != destination_ip.end(); ++it) {
        //std::cout << " " << *it;
        root["dst_ip"].append(*it);
    }

    for (auto it = proto.begin(); it != proto.end(); ++it) {
        //std::cout << " " << *it;
        root["proto"].append(*it);
    }

    for (auto it = src_port.begin(); it != src_port.end(); ++it) {
        //std::cout << " " << *it;
        root["src_port"].append(ntohs(*it));
    }
    for (auto it = dst_port.begin(); it != dst_port.end(); ++it) {
        //std::cout << " " << *it;
        root["dst_port"].append(ntohs(*it));
    }

    for (auto it = unic_ipport.begin(); it != unic_ipport.end(); ++it) {
        //std::cout << " " << *it;
        root["unic_ip+port"].append(*it);
    }

    for (auto it = session_ip.begin(); it != session_ip.end(); ++it) {
        //std::cout << " " << *it;
        root["session_ip"].append(*it);
    }

    for (auto it = session_mac.begin(); it != session_mac.end(); ++it) {
        //std::cout << " " << *it;
        root["session_mac"].append(*it);
    }

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

    u_char ether_smac[17];
    u_char ether_dmac[17];

    std::string str1;
    std::string str2;
    std::string str3;

    cout << "Packet number: " << countPacket++ << endl;
    cout << "Packet size: " << header->len << " bytes" << endl;
    cout << endl;

    ftype=ntohs(ethernet->ether_type);
    cout << "Packet type = " << ftype << endl;

/*    sprintf(reinterpret_cast<char *>(ether_smac),"%02x:%02x:%02x:%02x:%02x:%02x",ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
    cout << "Source MAC: " << ether_smac << endl;
    source_mac.insert(reinterpret_cast<char *>(ether_smac));*/
    sprintf(reinterpret_cast<char *>(ether_smac),"%02x:%02x:%02x:%02x:%02x:%02x",ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
    cout << "Source MAC: " << ether_smac << endl;
    source_mac.insert(reinterpret_cast<char *>(ether_smac));

    sprintf(reinterpret_cast<char *>(ether_dmac),"%02x:%02x:%02x:%02x:%02x:%02x",ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
    cout << "Destination MAC: " << ether_dmac << endl;
    destination_mac.insert(reinterpret_cast<char *>(ether_dmac));

    str1 = reinterpret_cast<char *>(ether_smac);
    str2 = reinterpret_cast<char *>(ether_dmac);
    str3 = str1+" - "+str2;
    session_mac.insert(str3);

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

            src_port.insert(tcp->th_sport);
            dst_port.insert(tcp->th_dport);

            str1 = inet_ntoa(ip->ip_dst);
            str2 = to_string(ntohs(tcp->th_dport));
            str3 = str1+":"+str2;
            unic_ipport.insert(str3);

            str1 = inet_ntoa(ip->ip_src);
            str2 = to_string(ntohs(tcp->th_sport));
            str3 = str1+":"+str2;
            unic_ipport.insert(str3);

            str2 = inet_ntoa(ip->ip_dst);
            str3 = str1+" - "+str2;
            session_ip.insert(str3);

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

            str1 = inet_ntoa(arp->send_ip);
            str2 = inet_ntoa(arp->target_ip);
            unic_ipport.insert(str1);
            unic_ipport.insert(str2);

            str3 = str1+" - "+str2;
            session_ip.insert(str3);

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
            break;
    }
    cout << endl << "--------------------------------------" << endl;
}