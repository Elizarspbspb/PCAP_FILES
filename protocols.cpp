#pragma once

#include <string>
#include "protocols.h"

std::string protocols_p(int prot)
{
    std::string IP_PROTO_IP1 = "DUMMY FOR IP"; /* Пусто */
std::string IP_PROTO_HOPOPTS = " + IP_PROTO_IP"; /* IPv6 hop-by-hop options */
std::string IP_PROTO_ICMP1 = "ICMP"; /* ICMP */
std::string IP_PROTO_IGMP1 = "IGMP"; /* IGMP */
std::string IP_PROTO_GGP1 = "GGP" ;/* протокол шлюз-шлюз */
std::string IP_PROTO_IPIP1 = "IPIP"; /* IP в IP */
std::string IP_PROTO_ST1 = "ST" ;/* Режим дейтаграмм ST */
std::string IP_PROTO_TCP1 = "TCP"; /* TCP */
std::string IP_PROTO_CBT1 = "CBT"; /* ТОС */
std::string IP_PROTO_EGP1 = "EGP"; /* протокол внешнего шлюза */
std::string IP_PROTO_IGP1 = "IGP"; /* протокол внутреннего шлюза */
std::string IP_PROTO_BBNRCC1 = "BBNRCC"; /* Мониторинг ПКР ББН */
std::string IP_PROTO_NVP1 = "NVP" ;/* Сетевой голосовой протокол */
std::string IP_PROTO_PUP1 = "PUP" ;/* универсальный пакет PARC */
std::string IP_PROTO_ARGUS1 = "ARGUS"; /* ARGUS */
std::string IP_PROTO_EMCON1 = "EMCON"; /* EMCON */
std::string IP_PROTO_XNET1 = "XNET"; /* Межсетевой отладчик */
std::string IP_PROTO_CHAOS1 = "CHAOS"; /* Хаос */
std::string IP_PROTO_UDP1 = "UDP"; /* UDP */
std::string IP_PROTO_MUX1 = "MUX"; /* мультиплексирование */

std::string IP_PROTO_UNKNOW = "UNKNOW"; /* неизвестный протокол */

std::string IP_PROTO_DCNMEAS = "DCN";	/* DCN measurement */
std::string IP_PROTO_HMP = " Host Monitoring Protocol";		/* Host Monitoring Protocol */
std::string IP_PROTO_PRM = "Packet Radio Measurement";		/* Packet Radio Measurement */
std::string	IP_PROTO_IDP = "Xerox NS IDP";		/* Xerox NS IDP */
std::string IP_PROTO_TRUNK1 = "Trunk-1";	/* Trunk-1 */
std::string IP_PROTO_TRUNK2	= "Trunk-2";		/* Trunk-2 */
std::string IP_PROTO_LEAF1 = "Leaf-1";		/* Leaf-1 */
std::string IP_PROTO_LEAF2 = "Leaf-2 ";		/* Leaf-2 */
std::string IP_PROTO_RDP = "Reliable Datagram proto";		/* "Reliable Datagram" proto */
std::string IP_PROTO_IRTP		= "Inet Reliable Transaction";		/* Inet Reliable Transaction */
std::string	IP_PROTO_TP		="ISO TP class 4"; 		/* ISO TP class 4 */
std::string IP_PROTO_NETBLT		="Bulk Data Transfer";		/* Bulk Data Transfer */
std::string IP_PROTO_MFPNSP		=" MFE Network Services";		/* MFE Network Services */
std::string IP_PROTO_MERITINP	="Merit Internodal Protocol";		/* Merit Internodal Protocol */
std::string IP_PROTO_SEP		="Sequential Exchange proto";		/* Sequential Exchange proto */
std::string IP_PROTO_3PC		="Third Party Connect proto";		/* Third Party Connect proto */
std::string IP_PROTO_IDPR		="Interdomain Policy Route";		/* Interdomain Policy Route */
std::string IP_PROTO_XTP		="Xpress Transfer Protocol";		/* Xpress Transfer Protocol */
std::string IP_PROTO_DDP		="Datagram Delivery Proto";		/* Datagram Delivery Proto */
std::string IP_PROTO_CMTP		="IDPR Ctrl Message Trans";		/* IDPR Ctrl Message Trans */
std::string IP_PROTO_TPPP		="TP++ Transport Protocol ";		/* TP++ Transport Protocol */
std::string IP_PROTO_IL		="IL Transport Protocol ";		/* IL Transport Protocol */
std::string IP_PROTO_IPV6		="IPv6";		/* IPv6 */
std::string IP_PROTO_SDRP		="Source Demand Routing";		/* Source Demand Routing */
std::string IP_PROTO_ROUTING	="IPv6 routing header";		/* IPv6 routing header */
std::string IP_PROTO_FRAGMENT	="IPv6 fragmentation header";		/* IPv6 fragmentation header */
std::string IP_PROTO_RSVP		="Reservation protocol";		/* Reservation protocol */
std::string	IP_PROTO_GRE		="General Routing Encap";		/* General Routing Encap */
std::string IP_PROTO_MHRP		="Mobile Host Routing";		/* Mobile Host Routing */
std::string IP_PROTO_ENA		="ENA";		/* ENA */
std::string	IP_PROTO_ESP		="Encap Security Payload";		/* Encap Security Payload */
std::string	IP_PROTO_AH		="Authentication Header";		/* Authentication Header */
std::string IP_PROTO_INLSP		="Integated Net Layer Sec";		/* Integated Net Layer Sec */
std::string IP_PROTO_SWIPE		="SWIPE";		/* SWIPE */
std::string IP_PROTO_NARP		="NBMA Address Resolution";		/* NBMA Address Resolution */
std::string	IP_PROTO_MOBILE		="Mobile IP, RFC 2004";		/* Mobile IP, RFC 2004 */
std::string IP_PROTO_TLSP		="Transport Layer Security";		/* Transport Layer Security */
std::string IP_PROTO_SKIP		="SKIP";		/* SKIP */
std::string IP_PROTO_ICMPV6		="ICMP for IPv6 ";		/* ICMP for IPv6 */
std::string IP_PROTO_NONE		="IPv6 no next header";		/* IPv6 no next header */
std::string IP_PROTO_DSTOPTS	="IPv6 destination options";		/* IPv6 destination options */
std::string IP_PROTO_ANYHOST	="Any host internal proto";		/* any host internal proto */
std::string IP_PROTO_CFTP		="CFTP";		/* CFTP */
std::string IP_PROTO_ANYNET		="any local network";		/* any local network */
std::string IP_PROTO_EXPAK		="SATNET and Backroom EXPAK";		/* SATNET and Backroom EXPAK */
std::string IP_PROTO_KRYPTOLAN	="Kryptolan";		/* Kryptolan */
std::string IP_PROTO_RVD		="MIT Remote Virtual Disk";		/* MIT Remote Virtual Disk */
std::string IP_PROTO_IPPC		="Inet Pluribus Packet Core";		/* Inet Pluribus Packet Core */
std::string IP_PROTO_DISTFS		="any distributed fs";		/* any distributed fs */
std::string IP_PROTO_SATMON		="SATNET Monitoring";		/* SATNET Monitoring */
std::string IP_PROTO_VISA		="VISA Protocol";		/* VISA Protocol */
std::string IP_PROTO_IPCV		="Inet Packet Core Utility";		/* Inet Packet Core Utility */
std::string IP_PROTO_CPNX		="Comp Proto Net Executive";		/* Comp Proto Net Executive */
std::string IP_PROTO_CPHB		="Comp Protocol Heart Beat";		/* Comp Protocol Heart Beat */
std::string IP_PROTO_WSN		="Wang Span Network";		/* Wang Span Network */
std::string IP_PROTO_PVP		="Packet Video Protocol ";		/* Packet Video Protocol */
std::string IP_PROTO_BRSATMON	="Backroom SATNET Monitor";		/* Backroom SATNET Monitor */
std::string IP_PROTO_SUNND		="SUN ND Protocol";		/* SUN ND Protocol */
std::string IP_PROTO_WBMON		="WIDEBAND Monitoring";		/* WIDEBAND Monitoring */
std::string IP_PROTO_WBEXPAK	="WIDEBAND EXPAK";		/* WIDEBAND EXPAK */
std::string	IP_PROTO_EON		="ISO CNLP";		/* ISO CNLP */
std::string IP_PROTO_VMTP		="Versatile Msg Transport";		/* Versatile Msg Transport*/
std::string IP_PROTO_SVMTP		="Secure VMTP";		/* Secure VMTP */
std::string IP_PROTO_VINES		="Secure VMTP";		/* Secure VMTP */
std::string IP_PROTO_TTP		="TTP";		/* TTP */
std::string IP_PROTO_NSFIGP		="NSFNET-IGP";		/* NSFNET-IGP */
std::string IP_PROTO_DGP		="Dissimilar Gateway Proto";		/* Dissimilar Gateway Proto */
std::string IP_PROTO_TCF		="TCF";		/* TCF */
std::string IP_PROTO_EIGRP		="EIGRP";		/* EIGRP */
std::string IP_PROTO_OSPF		="Open Shortest Path First";		/* Open Shortest Path First */
std::string IP_PROTO_SPRITERPC	="Sprite RPC Protocol";		/* Sprite RPC Protocol */
std::string IP_PROTO_LARP		="Locus Address Resolution";		/* Locus Address Resolution */
std::string IP_PROTO_MTP		="Multicast Transport Proto";		/* Multicast Transport Proto */
std::string IP_PROTO_AX25		="AX.25 Frames";		/* AX.25 Frames */
std::string IP_PROTO_IPIPENCAP	="yet-another IP encap";		/* yet-another IP encap */
std::string IP_PROTO_MICP		="Mobile Internet Ctrl";		/* Mobile Internet Ctrl */
std::string IP_PROTO_SCCSP		="Semaphore Comm Sec Proto";		/* Semaphore Comm Sec Proto */
std::string IP_PROTO_ETHERIP	="Ethernet in IPv4";		/* Ethernet in IPv4 */
std::string	IP_PROTO_ENCAP		="encapsulation header";		/* encapsulation header */
std::string IP_PROTO_ANYENC		="private encryption scheme";		/* private encryption scheme */
std::string IP_PROTO_GMTP		="GMTP";		/* GMTP */
std::string IP_PROTO_IFMP		="Ipsilon Flow Mgmt Proto";		/* Ipsilon Flow Mgmt Proto */
std::string IP_PROTO_PNNI		="PNNI over IP";		/* PNNI over IP */
std::string IP_PROTO_PIM		="Protocol Indep Multicast";		/* Protocol Indep Multicast */
std::string IP_PROTO_ARIS		="ARIS";		/* ARIS */
std::string IP_PROTO_SCPS		="SCPS";		/* SCPS */
std::string IP_PROTO_QNX		="QNX";		/* QNX */
std::string IP_PROTO_AN		="Active Networks";		/* Active Networks */
std::string IP_PROTO_IPCOMP		="IP Payload Compression";		/* IP Payload Compression */
std::string IP_PROTO_SNP		="Sitara Networks Protocol";		/* Sitara Networks Protocol */
std::string IP_PROTO_COMPAQPEER	="Compaq Peer Protocol";		/* Compaq Peer Protocol */
std::string IP_PROTO_IPXIP		="IPX in IP";		/* IPX in IP */
std::string IP_PROTO_VRRP		="Virtual Router Redundancy";		/* Virtual Router Redundancy */
std::string IP_PROTO_PGM		="PGM Reliable Transport";		/* PGM Reliable Transport */
std::string IP_PROTO_ANY0HOP	="0-hop protocol ";		/* 0-hop protocol */
std::string IP_PROTO_L2TP		="Layer 2 Tunneling Proto";		/* Layer 2 Tunneling Proto */
std::string IP_PROTO_DDX		="D-II Data Exchange (DDX)";		/* D-II Data Exchange (DDX) */
std::string IP_PROTO_IATP		="Interactive Agent Xfer";		/* Interactive Agent Xfer */
std::string IP_PROTO_STP		="Schedule Transfer Proto";		/* Schedule Transfer Proto */
std::string IP_PROTO_SRP		="SpectraLink Radio Proto";		/* SpectraLink Radio Proto */
std::string IP_PROTO_UTI		="UTI";		/* UTI */
std::string IP_PROTO_SMP		="Simple Message Protocol";		/* Simple Message Protocol */
std::string IP_PROTO_SM		="SM";		/* SM */
std::string IP_PROTO_PTP		="Performance Transparency";		/* Performance Transparency */
std::string IP_PROTO_ISIS		="ISIS over IPv4";		/* ISIS over IPv4 */
std::string IP_PROTO_FIRE		="FIRE";		/* FIRE */
std::string IP_PROTO_CRTP		="Combat Radio Transport";		/* Combat Radio Transport */
std::string IP_PROTO_CRUDP		="Combat Radio UDP";		/* Combat Radio UDP */
std::string IP_PROTO_SSCOPMCE	="SSCOPMCE";		/* SSCOPMCE */
std::string IP_PROTO_IPLT		="IPLT";		/* IPLT */
std::string IP_PROTO_SPS		=" Secure Packet Shield ";		/* Secure Packet Shield */
std::string IP_PROTO_PIPE		="Private IP Encap in IP";		/* Private IP Encap in IP */
std::string IP_PROTO_SCTP		=" Stream Ctrl Transmission";		/* Stream Ctrl Transmission */
std::string IP_PROTO_FC		="Fibre Channel ";		/* Fibre Channel */
std::string IP_PROTO_RSVPIGN	="RSVP-E2E-IGNORE ";		/* RSVP-E2E-IGNORE */
std::string IP_ETHERNET         ="IP ETHERNET";
std::string	IP_PROTO_RAW		=" Raw IP packets";		/* Raw IP packets */
std::string IP_PROTO_RESERVED	="Reserved";	/* Reserved */
std::string	IP_PROTO_MAX		="IP_PROTO_MAX";

    switch(prot)
    {
        case 0: return IP_PROTO_IP1+IP_PROTO_HOPOPTS;
        case 1: return IP_PROTO_ICMP1;
        case 2: return IP_PROTO_IGMP1;
        case 3: return IP_PROTO_GGP1;
        case 4: return IP_PROTO_IPIP1;
        case 5: return IP_PROTO_ST1;
        case 6: return IP_PROTO_TCP1;
        case 7: return IP_PROTO_CBT1;
        case 8: return IP_PROTO_EGP1;
        case 9: return IP_PROTO_IGP1;
        case 10: return IP_PROTO_BBNRCC1;
        case 11: return IP_PROTO_NVP1;
        case 12: return IP_PROTO_PUP1;
        case 13: return IP_PROTO_ARGUS1;
        case 14: return IP_PROTO_EMCON1;
        case 15: return IP_PROTO_XNET1;
        case 16: return IP_PROTO_CHAOS1;
        case 17: return IP_PROTO_UDP1;
        case 18: return IP_PROTO_MUX1;

        case 19: return IP_PROTO_DCNMEAS;
        case 20: return IP_PROTO_HMP;
        case 21: return IP_PROTO_PRM;
        case 22: return IP_PROTO_IDP;
        case 23: return IP_PROTO_TRUNK1;
        case 24: return IP_PROTO_TRUNK2;
        case 25: return IP_PROTO_LEAF1;
        case 26: return IP_PROTO_LEAF2;
        case 27: return IP_PROTO_RDP;
        case 28: return IP_PROTO_IRTP;
        case 29: return IP_PROTO_TP;
        case 30: return IP_PROTO_NETBLT;
        case 31: return IP_PROTO_MFPNSP;
        case 32: return IP_PROTO_MERITINP;
        case 33: return IP_PROTO_SEP;
        case 34: return IP_PROTO_3PC;
        case 35: return IP_PROTO_IDPR;
        case 36: return IP_PROTO_XTP;
        case 37: return IP_PROTO_DDP;

        case 38: return IP_PROTO_CMTP;
        case 39: return IP_PROTO_TPPP;
        case 40: return IP_PROTO_IL;
        case 41: return IP_PROTO_IPV6;
        case 42: return IP_PROTO_SDRP;
        case 43: return IP_PROTO_ROUTING;
        case 44: return IP_PROTO_FRAGMENT;
        case 45: return IP_PROTO_RSVP;
        case 46: return IP_PROTO_RSVP;
        case 47: return IP_PROTO_GRE;
        case 48: return IP_PROTO_MHRP;
        case 49: return IP_PROTO_ENA;
        case 50: return IP_PROTO_ESP;
        case 51: return IP_PROTO_AH;
        case 52: return IP_PROTO_INLSP;
        case 53: return IP_PROTO_SWIPE;
        case 55: return IP_PROTO_MOBILE;
        case 56: return IP_PROTO_TLSP;
        case 57: return IP_PROTO_SKIP;

        case 58: return IP_PROTO_ICMPV6;
        case 59: return IP_PROTO_NONE;
        case 60: return IP_PROTO_DSTOPTS;
        case 61: return IP_PROTO_ANYHOST;
        case 62: return IP_PROTO_CFTP;
        case 63: return IP_PROTO_ANYNET;
        case 64: return IP_PROTO_EXPAK;
        case 65: return IP_PROTO_KRYPTOLAN;
        case 66: return IP_PROTO_RVD;
        case 67: return IP_PROTO_IPPC;
        case 68: return IP_PROTO_DISTFS;
        case 69: return IP_PROTO_SATMON;
        case 70: return IP_PROTO_VISA;
        case 71: return IP_PROTO_IPCV;
        case 72: return IP_PROTO_CPNX;
        case 73: return IP_PROTO_CPHB;
        case 74: return IP_PROTO_WSN;
        case 75: return IP_PROTO_PVP;
        case 76: return IP_PROTO_BRSATMON;

        case 77: return IP_PROTO_SUNND;
        case 78: return IP_PROTO_WBMON;
        case 79: return IP_PROTO_WBEXPAK;
        case 80: return IP_PROTO_EON;
        case 81: return IP_PROTO_VMTP;
        case 82: return IP_PROTO_SVMTP;
        case 83: return IP_PROTO_VINES;
        case 84: return IP_PROTO_TTP;
        case 85: return IP_PROTO_NSFIGP;
        case 86: return IP_PROTO_DGP;
        case 87: return IP_PROTO_TCF;
        case 88: return IP_PROTO_EIGRP;
        case 89: return IP_PROTO_OSPF;
        case 90: return IP_PROTO_SPRITERPC;
        case 91: return IP_PROTO_LARP;
        case 92: return IP_PROTO_MTP;
        case 93: return IP_PROTO_AX25;
        case 94: return IP_PROTO_IPIPENCAP;
        case 95: return IP_PROTO_MICP;

        case 96: return IP_PROTO_SCCSP;
        case 97: return IP_PROTO_ETHERIP;
        case 98: return IP_PROTO_ENCAP;
        case 99: return IP_PROTO_ANYENC;
        case 100: return IP_PROTO_GMTP;
        case 101: return IP_PROTO_IFMP;
        case 102: return IP_PROTO_PNNI;
        case 103: return IP_PROTO_PIM;
        case 104: return IP_PROTO_ARIS;
        case 105: return IP_PROTO_SCPS;
        case 106: return IP_PROTO_QNX;
        case 107: return IP_PROTO_AN;
        case 108: return IP_PROTO_IPCOMP;
        case 109: return IP_PROTO_SNP;
        case 110: return IP_PROTO_COMPAQPEER;
        case 111: return IP_PROTO_IPXIP;
        case 112: return IP_PROTO_VRRP;
        case 113: return IP_PROTO_PGM;
        case 114: return IP_PROTO_ANY0HOP;

        case 115: return IP_PROTO_L2TP;
        case 116: return IP_PROTO_DDX;
        case 117: return IP_PROTO_IATP;
        case 118: return IP_PROTO_STP;
        case 119: return IP_PROTO_SRP;
        case 120: return IP_PROTO_UTI;
        case 121: return IP_PROTO_SMP;
        case 122: return IP_PROTO_SM;
        case 123: return IP_PROTO_PTP;
        case 124: return IP_PROTO_ISIS;
        case 125: return IP_PROTO_FIRE;
        case 126: return IP_PROTO_CRTP;
        case 127: return IP_PROTO_CRUDP;
        case 128: return IP_PROTO_SSCOPMCE;
        case 129: return IP_PROTO_IPLT;
        case 130: return IP_PROTO_SPS;
        case 131: return IP_PROTO_PIPE;
        case 132: return IP_PROTO_SCTP;
        case 133: return IP_PROTO_FC;

        case 134: return IP_PROTO_RSVPIGN;

        case 143: return IP_ETHERNET;

        case 225: return IP_PROTO_RAW;
        case 226: return IP_PROTO_MAX;

        default: return IP_PROTO_RESERVED;
    }
}
