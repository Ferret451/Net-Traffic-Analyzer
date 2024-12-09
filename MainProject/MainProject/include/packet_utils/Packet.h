#pragma once
#include <pcap.h>

class Packet {
    pcap_pkthdr header;
    const u_char *pktData;
    int linkType;
    
    wchar_t timeString[16];
    unsigned int length;
public:
    Packet(pcap_pkthdr *header, const u_char *pktData, pcap_t *adHandle);

    pcap_pkthdr GetHeader();
    const u_char *GetData();
    int GetLinkType();

    wchar_t *GetTimeString();
    int GetLength();
    
    ~Packet();
};
