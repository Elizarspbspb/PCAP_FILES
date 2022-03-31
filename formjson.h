#pragma once

#include <string>
#include <iostream>
#include <fstream>
#include <jsoncpp/json/json.h>
#include "protocols.h"
#include <netinet/in.h>
#include <arpa/inet.h>

void writeFileJson(std::vector<int> prot_c, int src_mac_c, int dst_mac_c, std::vector<in_addr> src_ip_c, std::vector<in_addr> dst_ip_c);
