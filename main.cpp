#include <stdio.h>
#include <iostream>
#include <cstring>
#include <thread>
#include <future>
#include <pthread.h>
#include <string.h>
#include "filter.h"

#define MAXLEN 1500
#define TIMEOUT 1
#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

using namespace std;
char *online="online";

int main(int argc, char *argv[])
{
    char param[3];
    char file_check[3] = "-f";
    char setings_reg[3] = "-s";
    sscanf(argv[1], "%s", param);

    Filter filter;

    bpf_u_int32 netp = 0;            // IP устройства
    bpf_u_int32 maskp = 0;           // сетевая маска
    pcap_if_t *alldevs;
    pcap_if_t *iface;
    ushort count_interface = 0;
    pcap_t *adhandle;           // descriptor live session
    struct bpf_program fcode;   // Скомпилированный фильтр
    struct in_addr net_addr, mask_addr;

    char *dev, *net, *mask, errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;  // packet caputre descriptor.
    u_char *useless;
    struct pcap_pkthdr *header;
    const u_char *packet;

    if(strcmp(param, file_check)==0) {

        std::ifstream pcap_file(argv[2]);
        if (pcap_file.is_open())
        {
            //std::thread thread1{[&]() {
            std::thread thread1([&pcap, &argv, &errbuff]()
            {
                std::string file = argv[2];

                //pcap_t *pcap = std::async(std::launch::async, pcap_open_offline_with_tstamp_precision, file.c_str(), PCAP_TSTAMP_PRECISION_MICRO, errbuff);
                pcap = pcap_open_offline_with_tstamp_precision(file.c_str(), PCAP_TSTAMP_PRECISION_MICRO, errbuff);
                cout << "first thread! " << endl;

                //pcap_t *pcap = pcap_open_offline_with_tstamp_precision(file.c_str(), PCAP_TSTAMP_PRECISION_MICRO, errbuff);  // first version
            });
            //}};
            thread1.join();
            //std::thread thread2{[&]()
            std::thread thread2([&filter, &pcap, &header, &packet, &useless]()
            {
                cout << "second thread! " << endl;
                while (pcap_next_ex(pcap, &header, &packet) >= 0)
                {
                    filter.callback(useless, header, packet); // обработка пакетов
                    filter.to_json();  // запись в файл}// чтение пакетов
                }
                cout << "Close" << endl;
                pcap_close(pcap);
                cout << "Write" << endl;
            //}};
            });
            thread2.join();
        }
        else {
            cout << "Error open .pcap_file" << endl;
        }
    }
    else if(strcmp(param, setings_reg)==0) {

        /*dev = pcap_lookupdev(errbuff);   // ald version
        if (dev == NULL)
        {
            printf("%s\n", errbuff);
            exit(1);
        }
        printf("DEV : %s\n", dev);*/

        if (pcap_findalldevs(&alldevs, errbuff) == -1 || !alldevs) // список сетевых устройств
        {
            fprintf(stderr, "No network devices are currently connected\n");
            mask = net = 0;
            return 1;
        }
        /* Print the list */
        for(iface = alldevs; iface; iface = iface->next)
        {
            count_interface++;
            cout << count_interface << ". " << iface->name;
            if (iface->description)
                cout << "(" << iface->description << ")" << endl;
            else
                cout << "(No description available)" << endl;
        }

        ushort select = 0;
        cout << "There is a number opposite the interfaces" << endl;
        cin>>select;
        while(select<=0 || select>count_interface)
        {
            cout<<"ERROR, Enter number again"<<std::endl;
            cin.clear();
            cin.ignore(std::numeric_limits<std::streamsize>::max(),'\n');
            cin>>select;
        }
        for(ushort i=1; i < select; i++)
            alldevs = alldevs->next;

        cout << "selected device - " << alldevs->name << endl;

        // Get netmask
        if (pcap_lookupnet(alldevs->name, &netp, &maskp, errbuff) == -1)  // получает номер/маску сети
        {
            fprintf(stderr, "%s\n", errbuff);
            return 1;
        }

        net_addr.s_addr = netp;
        net = inet_ntoa(net_addr);
        cout << "NET : " << net << endl;
        mask_addr.s_addr = maskp;
        mask = inet_ntoa(mask_addr);
        cout << "MASK : " << mask << endl;

        // Get packet capture descriptor.
        //alldevs = alldevs->next;
        pcap = pcap_open_live(alldevs->name, BUFSIZ, NONPROMISCUOUS, 1, errbuff);
        if (pcap == NULL) {
            fprintf(stderr, "%s\n", errbuff);
            return 1;
        }

/*        switch (pcap_datalink(pcap)) {
            case DLT_EN10MB:
                cout << "DLT_EN10MB -  " << endl;
                break;
            case DLT_IEEE802:
                cout << "DLT_IEEE802 -  " << endl;
                break;
            case DLT_FDDI:
                cout << "DLT_FDDI -  " << endl;
                break;
            case DLT_NULL:
                cout << "DLT_NULL -  " << endl;
                break;
            case DLT_RAW:
                cout << "DLT_RAW -  " << endl;
                break;
            default:
                fprintf(stderr, "\n%s bad datalink type", pcap);
                break;
        }*/

        // Set compile option.
        if (pcap_compile(pcap, &fcode, argv[2], 0, netp) == -1) {
            fprintf(stderr, "compile error\n");
            return 1;
        }

        // Set packet filter role by compile option.
        if (pcap_setfilter(pcap, &fcode) == -1) {
            fprintf(stderr, "set filter error\n");
            return 1;
        }

        std::thread thread3([&filter, &pcap, &header, &packet, &useless]()
        {
            while (pcap_next_ex(pcap, &header, &packet) >= 0) // чтение пакетов
            {
                //filter.callback(useless, header, packet); // обработка пакетов
                //filter.to_json();  // запись в файл

                thread thread4(&Filter::callback, &filter, useless, header, packet); // обработка пакетов
                thread4.join();
                thread thread5(&Filter::to_json, &filter); // обработка пакетов
                thread5.join();
            }
        });
        thread3.join();
        printf("\n-------------------------------------------------------------------\n");
    }
    else
    {
        cout << "Invalid argument program" << endl;
        cout << "Available arguments: -t or -s" << endl;
    }

    cout << "FINISH" << endl;
    return(0);
}