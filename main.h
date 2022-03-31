#pragma once

#include <string>
#include <pcap.h>
#include <iostream>

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
#include "callback.h"

using namespace std;

#define MAXLEN 1500
#define TIMEOUT 1

int main(int argc, char *argv[]);