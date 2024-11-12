#pragma once
#include <pcap.h>

class Packet {
    pcap_pkthdr header;
    const u_char *pkt_data;
    
    char timeString[16];
public:
    Packet(pcap_pkthdr *header, const u_char *pkt_data);
    ~Packet();
};
