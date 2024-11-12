#include "../include/Packet.h"

#include <ctime>
#include <new>

Packet::Packet(pcap_pkthdr *header, const u_char *pkt_data) {
    this->header = *header;
    this->pkt_data = new u_char[header->len];
    if (pkt_data == nullptr) {
        throw std::bad_alloc();
    }
    memcpy((void*)this->pkt_data, pkt_data, header->len);

    tm ltime;
    time_t local_tv_sec;

    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime(timeString, sizeof timeString, "%H:%M:%S", &ltime);
}

Packet::~Packet() {
    delete pkt_data;
}
