#include "../../include/packet_utils/Packet.h"

#include <ctime>
#include <new>

Packet::Packet(pcap_pkthdr *header, const u_char *pktData, pcap_t *adHandle) {
    this->header = *header;
    this->pktData = new u_char[header->len];
    if (pktData == nullptr) {
        throw std::bad_alloc();
    }
    memcpy((void*)this->pktData, pktData, header->len);

    // Getting time and converting it to string
    tm ltime;
    time_t local_tv_sec;
    char timeStr[24]; 

    local_tv_sec = header->ts.tv_sec;
    (void)localtime_s(&ltime, &local_tv_sec);
    sprintf_s(timeStr, "%02d:%02d:%02d.%06ld", ltime.tm_hour, ltime.tm_min, ltime.tm_sec, header->ts.tv_usec);
    MultiByteToWideChar(CP_ACP, 0, timeStr, -1, timeString, 256);  

    // Getting length
    length = header->len;

    // Getting link type
    linkType = pcap_datalink(adHandle);
}

pcap_pkthdr Packet::GetHeader() {
    return header;
}

const u_char *Packet::GetData() {
    return pktData;
}

int Packet::GetLinkType() {
    return linkType;
}

wchar_t *Packet::GetTimeString() {
    return timeString;
}

int Packet::GetLength() {
    return header.len;
}

Packet::~Packet() {
    delete pktData;
}
