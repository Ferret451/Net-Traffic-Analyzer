#include "../../include/packet_utils/PacketParser.h"

// Parsing ipv4
void PacketParser::ParseIPv4(const u_char* ip_data, int packet_length, ParsedPacket& parsed) {
    ipv4_header* ih = (ipv4_header*)ip_data;

    parsed.srcIp = std::to_wstring(ih->saddr.byte1) + L"." +
                   std::to_wstring(ih->saddr.byte2) + L"." +
                   std::to_wstring(ih->saddr.byte3) + L"." +
                   std::to_wstring(ih->saddr.byte4);

    parsed.destIp = std::to_wstring(ih->daddr.byte1) + L"." +
                    std::to_wstring(ih->daddr.byte2) + L"." +
                    std::to_wstring(ih->daddr.byte3) + L"." +
                    std::to_wstring(ih->daddr.byte4);

    parsed.protocol = (ih->proto == 6) ? L"TCP" : (ih->proto == 17) ? L"UDP" : L"Other";
    parsed.length = std::to_wstring(packet_length);
}

// Formatting ipv6 addr
std::wstring PacketParser::FormatIPv6Address(const u_short* segments) {
    std::wstring address;
    for (int i = 0; i < 8; ++i) {
        if (i > 0) address += L":";
        address += std::to_wstring(segments[i]);
    }
    return address;
}

// Parsing ipv6
void PacketParser::ParseIPv6(const u_char* ip_data, int packet_length, ParsedPacket& parsed) {
    ipv6_header* ih6 = (ipv6_header*)ip_data;

    parsed.srcIp = FormatIPv6Address(ih6->saddr.segments);
    parsed.destIp = FormatIPv6Address(ih6->daddr.segments);

    parsed.protocol = (ih6->next_header == 6) ? L"TCP" : (ih6->next_header == 17) ? L"UDP" : L"Other";
    parsed.length = std::to_wstring(packet_length);
}

// Combining two bytes into unsigned short
unsigned short PacketParser::combineTwoBytes(unsigned short high, unsigned short low) {
    return (u_short)(high << 8 | low);
}

// Getting the length of the Wi-Fi header, because it can be 24 or 30 bytes
int PacketParser::getWifiHeaderLength(const u_char* pkt_data) {
    const wifi_header* wh = reinterpret_cast<const wifi_header*>(pkt_data);

    uint16_t frame_control = wh->frame_control; 
    uint8_t high_byte = frame_control >> 8 & 0xFF; 
    uint8_t low_byte = frame_control & 0xFF; 
    uint16_t combined = combineTwoBytes(high_byte, low_byte);
    
    int type = (combined & 0x0C) >> 2;
    if (type == 2) { 
        bool hasAddr4 = combined & 0x03;
        return hasAddr4 ? 30 : 24;
    }
    
    return 24;
}

// Parsing packet
ParsedPacket PacketParser::ParsePacket(int index, Packet& packet) {
    ParsedPacket parsed;
    parsed.index = std::to_wstring(index);
    parsed.time = packet.GetTimeString();

    const u_char* data = packet.GetData();
    int link_type = packet.GetLinkType();
    const u_char* ip_data = nullptr;
    u_short eth_type = 0;

    // Data link layer processing
    if (link_type == DLT_EN10MB) {  // Ethernet
        eth_type = combineTwoBytes(data[12], data[13]);
        ip_data = data + 14;
    } else if (link_type == DLT_IEEE802_11) {  // Wi-Fi
        int wifi_header_len = getWifiHeaderLength(data);
        eth_type = combineTwoBytes(data[wifi_header_len], data[wifi_header_len + 1]);
        ip_data = data + wifi_header_len + 2;
    }

    // Network layer processing
    if (eth_type == 0x0800) {  // IPv4
        ParseIPv4(ip_data, packet.GetLength(), parsed);
    } else if (eth_type == 0x86DD) {  // IPv6
        ParseIPv6(ip_data, packet.GetLength(), parsed);
    } else {
        parsed.srcIp = L"N/A";
        parsed.destIp = L"N/A";
        parsed.protocol = L"N/A";
        parsed.length = std::to_wstring(packet.GetLength());
    }

    return parsed;
}