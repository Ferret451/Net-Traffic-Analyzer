#include "../../include/packet_utils/Packet.h"

#include <ctime>
#include <new>

Packet::Packet(): header(), pktData(nullptr), linkType(0), timeString{}, length(0) { }

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

void Packet::Serialize(std::ostream &out) {
    out.write(reinterpret_cast<const char *>(&header), sizeof(header));
    if (pktData && header.len > 0) {
        out.write(reinterpret_cast<const char *>(pktData), header.len);
    }
    out.write(reinterpret_cast<const char *>(&linkType), sizeof(linkType));
    out.write(reinterpret_cast<const char *>(timeString), sizeof(timeString));
    out.write(reinterpret_cast<const char *>(&length), sizeof(length));
}

void Packet::Deserialize(std::istream &in) {
    in.read(reinterpret_cast<char *>(&header), sizeof(header));
    delete[] pktData;
    pktData = new u_char[header.len];
    if (!pktData) {
        throw std::bad_alloc();
    }
    in.read(reinterpret_cast<char *>(const_cast<u_char *>(pktData)), header.len);
    in.read(reinterpret_cast<char *>(&linkType), sizeof(linkType));
    in.read(reinterpret_cast<char *>(timeString), sizeof(timeString));
    in.read(reinterpret_cast<char *>(&length), sizeof(length));
}

Packet::~Packet() {
    delete pktData;
}
