#pragma once

#include <string>
#include "../../help/NetUtils.h"
#include "Packet.h"

class PacketParser {
private:
    void ParseIPv4(const u_char* ip_data, ParsedPacket& parsed);
    std::wstring FormatIPv6Address(const uint8_t* ip);
    void ParseIPv6(const u_char* ip_data, ParsedPacket& parsed);
    std::wstring GetEthernetHeaderDetails(const u_char* ethernet_data);
    std::wstring GetWiFiHeaderDetails(const u_char* wifi_data);
    std::wstring GetIPv4HeaderDetails(const u_char* ipv4_data);
    std::wstring GetIPv6HeaderDetails(const u_char* ipv6_data);
    std::wstring GetTCPHeaderDetails(const u_char* tcp_data);
    std::wstring GetUDPHeaderDetails(const u_char* udp_data);
    unsigned short combineTwoBytes(unsigned short high, unsigned short low);
    int getWifiHeaderLength(const u_char* pkt_data);
public:
    ParsedPacket ParsePacket(int index, Packet& packet);
    std::wstring GetPacketDetails(Packet& packet);
};

