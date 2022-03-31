#pragma once

#include <string>
#include <iostream>
#include "formjson.h"

using namespace std;

string src_ip;
std::vector<string> src_ip_mas;
int flag_ip_src=1;

string dst_ip;
std::vector<string> dst_ip_mas;
int flag_ip_dst=1;

// Save the information in JSON format
void writeFileJson(std::vector<int> prot_c, int src_mac_c, int dst_mac_c, std::vector<in_addr> src_ip_c, std::vector<in_addr> dst_ip_c)
{
    // root
    Json::Value root;

    // array form
    for(int i =0; i<prot_c.size();i++)
        root["protocols"].append(protocols_p(prot_c[i]));

    for(int i =0; i<src_ip_c.size();i++) {
        src_ip = inet_ntoa(src_ip_c[i]);

        for (int j1 = 0; j1 < src_ip_mas.size(); j1++)
        {
            if(src_ip == src_ip_mas[j1])
            {
                flag_ip_src=0;
                break;
            }
        }
        if(flag_ip_src==1) {
            src_ip_mas.push_back(src_ip);
            root["src_ip"].append(src_ip);
        }
        flag_ip_src=1;
    }

    for(int i =0; i<dst_ip_c.size();i++) {
        dst_ip = inet_ntoa(dst_ip_c[i]);

        for (int j1 = 0; j1 < dst_ip_mas.size(); j1++)
        {
            if(dst_ip == dst_ip_mas[j1])
            {
                flag_ip_dst=0;
                break;
            }
        }
        if(flag_ip_dst==1) {
            dst_ip_mas.push_back(dst_ip);
            root["dst_ip"].append(dst_ip);
        }
        flag_ip_dst=1;
    }

    string src_mac = "-.-.-.-.-.-";
    string dst_mac = "-.-.-.-.-.-";

    for(int i=0; i<2; i++)
    {
        root["src_mac"].append(src_mac);
        root["dst_mac"].append(dst_mac);
    }

    // direct output
    //cout << endl << endl << "FastWriter:" << endl;
    //Json::FastWriter fw;
    //cout << fw.write(root) << endl << endl;

    // indent output
    cout << "StyledWriter:" << endl;
    Json::StyledWriter sw;
    cout << sw.write(root) << endl << endl;

    // output to a file
    ofstream os;
    os.open("demo.json");
    os << sw.write(root);
    os.close();
}


