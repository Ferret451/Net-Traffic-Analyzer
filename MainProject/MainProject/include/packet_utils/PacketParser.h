#pragma once

#include <string>
#include "../../help/NetUtils.h"
#include "Packet.h"

class PacketParser {
private:
    void ParseIPv4(const u_char* ip_data, int packet_length, ParsedPacket& parsed);
    std::wstring FormatIPv6Address(const u_short* segments);
    void ParseIPv6(const u_char* ip_data, int packet_length, ParsedPacket& parsed);
    unsigned short combineTwoBytes(unsigned short high, unsigned short low);
    int getWifiHeaderLength(const u_char* pkt_data);
public:
    ParsedPacket ParsePacket(int index, Packet& packet);
};

