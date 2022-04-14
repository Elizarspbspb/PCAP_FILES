#include <stdio.h>
#include <iostream>
#include <cstring>

#include "filter.h"

using namespace std;

int main(int argc, char *argv[])
{
    Filter filter;

    std::string file = argv[1];
    bpf_u_int32 net = 0;            // IP устройства
    bpf_u_int32 mask = 0;           // сетевая маска
    pcap_if_t *alldevs;
    pcap_t *adhandle;           // descriptor live session
    struct bpf_program fcode;   // Скомпилированный фильтр

    char *dev, errbuff[PCAP_ERRBUF_SIZE];

    pcap_t *pcap = pcap_open_offline_with_tstamp_precision(file.c_str(), PCAP_TSTAMP_PRECISION_MICRO, errbuff);

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

    u_char *useless;
    struct pcap_pkthdr *header;
    const u_char *packet;

    //pcap_loop(pcap, 0, filter.callback(), NULL);
    while (pcap_next_ex(pcap, &header, &packet) >= 0) // чтение пакетов
    {
        filter.callback(useless, header, packet); // обработка пакетов
    }

    cout << "Close" << endl;
    pcap_close(pcap);
    cout << "Write" << endl;

    filter.to_json();  // запись в файл

    cout << "FINISH" << endl;
    return(0);
}