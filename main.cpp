#include "main.h"

typedef struct pcap pcap_t;
int prot_c=0, src_mac_c=0, dst_mac_c=0, src_ip_c=0, dst_ip_c=0;

int main(int argc, char *argv[])
{
    std::ifstream pcap_file(argv[1]);
    if (!pcap_file.is_open()) {
        cout << "Error open .pcap_file" << endl;
        return -1;
    }
    pcap_file.close();

    std::string file = argv[1];

    int num, inum, i=0;
    pcap_if_t *alldevs;
    pcap_t *adhandle;           // descriptor live session
    struct bpf_program fcode;   // Скомпилированный фильтр
    bpf_u_int32 net;            // IP устройства
    bpf_u_int32 mask;           // сетевая маска
    char *net_s;
    char *mask_s;
    const u_char *packet;
    struct in_addr net_addr, mask_addr;
    struct ip *iph;
    struct ether_header *ep;

    char *dev;                  // буфер с назавнием интерфейса

    char errbuff[PCAP_ERRBUF_SIZE]; // буфер для записи ошибок

    pcap_t * pcap = pcap_open_offline_with_tstamp_precision(file.c_str(), PCAP_TSTAMP_PRECISION_MICRO, errbuff);

    struct pcap_pkthdr *header;

    const u_char *data;

    dev = pcap_lookupdev(errbuff); // ald version
    if(pcap_lookupnet(dev, &net, &mask, errbuff) < 0) // получает номер/маску сети
    {
        fprintf(stderr, "Cant get netmask for device %s\n", dev);
        cout << "Cant get netmask for device " << dev << endl;
        net = 0;
        mask = 0;
        return -2;
    }
    cout << "Device live interface = " << dev << endl;


    /*if (pcap_findalldevs(&alldevs, errbuff) == -1 || !alldevs) // список сетевых устройств
    {
		fprintf(stderr, "No network devices are currently connected\n");
        net = 0;
        mask = 0;
        cout << "ERROR" << endl;
		return -1;
	}*/

    if((adhandle = pcap_open_live(dev, MAXLEN, 1, TIMEOUT, errbuff)) == NULL)
    {
        cout << "Cant open device: " << errbuff << endl;
        exit(0);
    }
    cout << "live interface descriptor = " << adhandle << endl;
    cout << ".pcap file interface descriptor =  " << pcap_get_selectable_fd(pcap) << endl;

    if (pcap_datalink(adhandle) != DLT_EN10MB) // проверка пддердки заголовков канального уровня
    {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers -not  supported\n", dev);
        cout << "Device " << dev << " doesn't provide Ethernet headers -not  supported"  << endl;
        return(2);
    }

    net_addr.s_addr = net;
    net_s = inet_ntoa(net_addr);
    printf("NET : %s\n", net_s);

    mask_addr.s_addr = mask;
    mask_s = inet_ntoa(mask_addr);
    printf("MASK : %s\n", mask_s);

    cout << endl << "________________" << endl;

    if(pcap_compile(pcap, &fcode, "", 1, net) < 0) // компиляция фильтра заданным регулярным выражением
    {
        fprintf(stderr, "\nunable syntax: %s\n", pcap_geterr(pcap));
        cout << "unable syntax: " << pcap_geterr(pcap) << endl; // информация об ошибке
        pcap_freealldevs(alldevs);
        return -1;
    }

    if(pcap_setfilter(pcap, &fcode) < 0) // применение фильтра
    {
        fprintf(stderr, "\nerror in setting filter: %s\n", pcap_geterr(pcap));
        cout << "error in setting filter: " << pcap_geterr(pcap) << endl;  // информация об ошибке
        pcap_freealldevs(alldevs);
        return -1;
    }

    pcap_loop(pcap, 0, callback, NULL); // цикл обработки захватываемых пакетов

    pcap_close(pcap);
    pcap_close(adhandle);
    pcap_file.close();

    writeFileJson(mas_prot, src_mac_c, dst_mac_c, source_ip, destination_ip); // Запись в json файл

    return 0;
}