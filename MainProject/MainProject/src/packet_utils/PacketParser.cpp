#include "../../include/packet_utils/PacketParser.h"

#include <codecvt>
#include <iomanip>
#include <sstream>

// Parsing ipv4
#include <ws2tcpip.h>
#include <string>
#include <locale>
#include <codecvt>

void PacketParser::ParseIPv4(const u_char* ip_data, ParsedPacket& parsed) {
    ipv4_header* ih = (ipv4_header*)ip_data;
    
    in_addr src_addr;
    src_addr.s_addr = ih->src_ip;

    in_addr dest_addr;
    dest_addr.s_addr = ih->dest_ip;
    
    char src_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_addr, src_ip_str, sizeof(src_ip_str));

    char dest_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dest_addr, dest_ip_str, sizeof(dest_ip_str));
    
    parsed.srcIp = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(src_ip_str);
    parsed.destIp = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(dest_ip_str);
    
    switch (ih->protocol) {
    case 6:  parsed.protocol = L"TCP"; break;
    case 17: parsed.protocol = L"UDP"; break;
    default: parsed.protocol = L"Other"; break;
    }
}


// Formatting ipv6 addr
std::wstring PacketParser::FormatIPv6Address(const uint8_t* ip) {
    char str[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, ip, str, INET6_ADDRSTRLEN) == nullptr) {
        return L"Invalid IPv6";
    }
   
    return std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(str);
}


// Parsing ipv6
void PacketParser::ParseIPv6(const u_char* ip_data, ParsedPacket& parsed) {
    ipv6_header* ih6 = (ipv6_header*)ip_data;

    parsed.srcIp = FormatIPv6Address(ih6->src_ip);
    parsed.destIp = FormatIPv6Address(ih6->dest_ip);

    // Определяем протокол
    switch (ih6->next_header) {
    case 6:  parsed.protocol = L"TCP"; break;
    case 17: parsed.protocol = L"UDP"; break;
    default: parsed.protocol = L"Other"; break;
    }
}

std::wstring PacketParser::GetEthernetHeaderDetails(const u_char* ethernet_data) {
    ethernet_header* eth = (ethernet_header*)ethernet_data;

    std::wstringstream details;
    details << L"Ethernet Header:\n";
    details << L"  Destination MAC: " 
            << std::hex << std::setfill(L'0') 
            << std::setw(2) << eth->dest_mac[0] << L":" 
            << std::setw(2) << eth->dest_mac[1] << L":" 
            << std::setw(2) << eth->dest_mac[2] << L":" 
            << std::setw(2) << eth->dest_mac[3] << L":" 
            << std::setw(2) << eth->dest_mac[4] << L":" 
            << std::setw(2) << eth->dest_mac[5] << L"\n";

    details << L"  Source MAC: " 
            << std::hex << std::setfill(L'0') 
            << std::setw(2) << eth->src_mac[0] << L":" 
            << std::setw(2) << eth->src_mac[1] << L":" 
            << std::setw(2) << eth->src_mac[2] << L":" 
            << std::setw(2) << eth->src_mac[3] << L":" 
            << std::setw(2) << eth->src_mac[4] << L":" 
            << std::setw(2) << eth->src_mac[5] << L"\n";

    details << L"  EtherType: 0x" << std::hex << ntohs(eth->ether_type) << L"\n";

    return details.str();
}

std::wstring PacketParser::GetWiFiHeaderDetails(const u_char* wifi_data) {
    wifi_header* wifi = (wifi_header*)wifi_data;

    std::wstringstream details;
    details << L"Wi-Fi Header:\n";
    
    uint16_t frame_control = (wifi->frame_control[0] << 8) | wifi->frame_control[1];
    details << L"  Frame Control: 0x" << std::hex << frame_control << L"\n";
    
    uint16_t duration = (wifi->duration[0] << 8) | wifi->duration[1];
    details << L"  Duration: " << std::dec << duration << L"\n";
    
    details << L"  Address 1: " 
            << std::hex << std::setfill(L'0') 
            << std::setw(2) << wifi->addr1[0] << L":" 
            << std::setw(2) << wifi->addr1[1] << L":" 
            << std::setw(2) << wifi->addr1[2] << L":" 
            << std::setw(2) << wifi->addr1[3] << L":" 
            << std::setw(2) << wifi->addr1[4] << L":" 
            << std::setw(2) << wifi->addr1[5] << L"\n";
    
    details << L"  Address 2: " 
            << std::hex << std::setfill(L'0') 
            << std::setw(2) << wifi->addr2[0] << L":" 
            << std::setw(2) << wifi->addr2[1] << L":" 
            << std::setw(2) << wifi->addr2[2] << L":" 
            << std::setw(2) << wifi->addr2[3] << L":" 
            << std::setw(2) << wifi->addr2[4] << L":" 
            << std::setw(2) << wifi->addr2[5] << L"\n";
    
    details << L"  Address 3: " 
            << std::hex << std::setfill(L'0') 
            << std::setw(2) << (int)wifi->addr3[0] << L":" 
            << std::setw(2) << (int)wifi->addr3[1] << L":" 
            << std::setw(2) << (int)wifi->addr3[2] << L":" 
            << std::setw(2) << (int)wifi->addr3[3] << L":" 
            << std::setw(2) << (int)wifi->addr3[4] << L":" 
            << std::setw(2) << (int)wifi->addr3[5] << L"\n";
    
    uint16_t seq_control = (wifi->seq_control[0] << 8) | wifi->seq_control[1];
    details << L"  Sequence Control: 0x" << std::hex << seq_control << L"\n";

    return details.str();
}

std::wstring PacketParser::GetIPv4HeaderDetails(const u_char* ipv4_data) {
    ipv4_header* ipv4 = (ipv4_header*)ipv4_data;

    std::wstring details = L"IPv4 Header:\n";
    details += L"  Version: " + std::to_wstring((ipv4->version_ihl >> 4) & 0xF) + L"\n";
    details += L"  Header Length: " + std::to_wstring((ipv4->version_ihl & 0xF) * 4) + L" bytes\n";
    details += L"  Total Length: " + std::to_wstring(ntohs(ipv4->total_length)) + L"\n";
    details += L"  Protocol: " + std::to_wstring(ipv4->protocol) + L"\n";
    
    in_addr src_addr;
    src_addr.s_addr = ipv4->src_ip;

    in_addr dest_addr;
    dest_addr.s_addr = ipv4->dest_ip;

    char src_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_addr, src_ip_str, sizeof(src_ip_str));

    char dest_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dest_addr, dest_ip_str, sizeof(dest_ip_str));
    
    details += L"  Source IP: " + std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(src_ip_str) + L"\n";
    details += L"  Destination IP: " + std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(dest_ip_str) + L"\n";

    return details;
}


std::wstring PacketParser::GetIPv6HeaderDetails(const u_char* ipv6_data) {
    ipv6_header* ipv6 = (ipv6_header*)ipv6_data;

    std::wstringstream details;
    details << L"IPv6 Header:\n";
    details << L"  Version: " << ((ntohl(ipv6->version_traffic_class_flow_label) >> 28) & 0xF) << L"\n";
    details << L"  Payload Length: " << ntohs(ipv6->payload_length) << L"\n";
    details << L"  Next Header: " << ipv6->next_header << L"\n";
    details << L"  Hop Limit: " << ipv6->hop_limit << L"\n";

    details << L"  Source IP: ";
    for (int i = 0; i < 16; ++i) {
        if (i > 0 && i % 2 == 0) details << L":";
        details << std::hex << std::setfill(L'0') << std::setw(2) << (int)ipv6->src_ip[i];
    }
    details << L"\n  Destination IP: ";
    for (int i = 0; i < 16; ++i) {
        if (i > 0 && i % 2 == 0) details << L":";
        details << std::hex << std::setfill(L'0') << std::setw(2) << (int)ipv6->dest_ip[i];
    }
    details << L"\n";

    return details.str();
}


std::wstring PacketParser::GetTCPHeaderDetails(const u_char* tcp_data) {
    tcp_header* th = (tcp_header*)tcp_data;

    std::wstring details = L"TCP Header:\n";
    details += L"  Source Port: " + std::to_wstring(ntohs(th->src_port)) + L"\n";
    details += L"  Destination Port: " + std::to_wstring(ntohs(th->dest_port)) + L"\n";
    details += L"  Sequence Number: " + std::to_wstring(ntohl(th->seq_number)) + L"\n";
    details += L"  Acknowledgment Number: " + std::to_wstring(ntohl(th->ack_number)) + L"\n";
    details += L"  Data Offset: " + std::to_wstring(th->data_offset) + L"\n";
    details += L"  Flags: 0x" + std::to_wstring(th->flags) + L"\n";
    details += L"  Window Size: " + std::to_wstring(ntohs(th->window)) + L"\n";
    details += L"  Checksum: 0x" + std::to_wstring(ntohs(th->checksum)) + L"\n";
    details += L"  Urgent Pointer: " + std::to_wstring(ntohs(th->urgent_pointer)) + L"\n";

    return details;
}

std::wstring PacketParser::GetUDPHeaderDetails(const u_char* udp_data) {
    udp_header* uh = (udp_header*)udp_data;

    std::wstring details = L"UDP Header:\n";
    details += L"  Source Port: " + std::to_wstring(ntohs(uh->src_port)) + L"\n";
    details += L"  Destination Port: " + std::to_wstring(ntohs(uh->dest_port)) + L"\n";
    details += L"  Length: " + std::to_wstring(ntohs(uh->length)) + L"\n";
    details += L"  Checksum: 0x" + std::to_wstring(ntohs(uh->checksum)) + L"\n";

    return details;
}

// Combining two bytes into unsigned short
unsigned short PacketParser::combineTwoBytes(unsigned short high, unsigned short low) {
    return (u_short)(high << 8 | low);
}

// Getting the length of the Wi-Fi header, because it can be 24 or 30 bytes
int PacketParser::getWifiHeaderLength(const u_char* pkt_data) {
    const wifi_header* wh = reinterpret_cast<const wifi_header*>(pkt_data);

    // Собираем frame_control из двух байтов
    uint16_t frame_control = (wh->frame_control[0] << 8) | wh->frame_control[1]; 

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

    // Length of packet
    parsed.length = std::to_wstring(packet.GetLength());

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
        ParseIPv4(ip_data, parsed);

        // Extract transport layer information
        uint8_t protocol = ip_data[9];  // Protocol field in IPv4 header
        const u_char* transport_data = ip_data + (ip_data[0] & 0x0F) * 4;  // Skip IPv4 header

        if (protocol == 6 || protocol == 17) { 
            parsed.srcPort = std::to_wstring(combineTwoBytes(transport_data[0], transport_data[1]));
            parsed.destPort = std::to_wstring(combineTwoBytes(transport_data[2], transport_data[3]));
        } else {
            parsed.srcPort = L"N/A";
            parsed.destPort = L"N/A";
        }
    } else if (eth_type == 0x86DD) {  // IPv6
        ParseIPv6(ip_data, parsed);

        // Extract transport layer information
        uint8_t next_header = ip_data[6];  // Next header field in IPv6 header
        const u_char* transport_data = ip_data + 40;  // IPv6 header is always 40 bytes

        if (next_header == 6 || next_header == 17) { 
            parsed.srcPort = std::to_wstring(combineTwoBytes(transport_data[0], transport_data[1]));
            parsed.destPort = std::to_wstring(combineTwoBytes(transport_data[2], transport_data[3]));
        } else {
            parsed.srcPort = L"N/A";
            parsed.destPort = L"N/A";
        }
    } else {
        parsed.srcIp = L"N/A";
        parsed.destIp = L"N/A";
        parsed.protocol = L"N/A";
        parsed.length = std::to_wstring(packet.GetLength());
        parsed.srcPort = L"N/A";
        parsed.destPort = L"N/A";
    }

    return parsed;
}

std::wstring PacketParser::GetPacketDetails(Packet& packet) {
    std::wstringstream packet_details;
    
    const u_char* data = packet.GetData();
    int link_type = packet.GetLinkType();
    const u_char* ip_data = nullptr;
    u_short eth_type = 0;

    // Length of packet
    packet_details << L"Length: " << std::to_wstring(packet.GetLength()) << L"\n";

    // Data link layer processing
    if (link_type == DLT_EN10MB) {  // Ethernet
        eth_type = combineTwoBytes(data[12], data[13]);
        ip_data = data + 14;
        packet_details << GetEthernetHeaderDetails(data);
    } else if (link_type == DLT_IEEE802_11) {  // Wi-Fi
        int wifi_header_len = getWifiHeaderLength(data);
        eth_type = combineTwoBytes(data[wifi_header_len], data[wifi_header_len + 1]);
        ip_data = data + wifi_header_len + 2;
        packet_details << GetWiFiHeaderDetails(data);
    }

    // Network layer processing (IPv4 or IPv6)
    if (eth_type == 0x0800) {  // IPv4
        packet_details << GetIPv4HeaderDetails(ip_data);
        uint8_t protocol = ip_data[9];  // Protocol field in IPv4 header
        const u_char* transport_data = ip_data + (ip_data[0] & 0x0F) * 4;  // Skip IPv4 header
        
        // Transport layer (TCP/UDP)
        if (protocol == 6) {  // TCP
            packet_details << GetTCPHeaderDetails(transport_data);
        } else if (protocol == 17) {  // UDP
            packet_details << GetUDPHeaderDetails(transport_data);
        }
    } else if (eth_type == 0x86DD) {  // IPv6
        packet_details << GetIPv6HeaderDetails(ip_data);
        uint8_t protocol = ip_data[6];  // Next Header field in IPv6 header
        const u_char* transport_data = ip_data + 40;  // Skip IPv6 header
        
        // Transport layer (TCP/UDP)
        if (protocol == 6) {  // TCP
            packet_details << GetTCPHeaderDetails(transport_data);
        } else if (protocol == 17) {  // UDP
            packet_details << GetUDPHeaderDetails(transport_data);
        }
    }

    return packet_details.str();
}

