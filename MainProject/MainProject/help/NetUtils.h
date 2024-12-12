#pragma once
#include <cstdint>

struct ethernet_header {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
};

struct wifi_header {
    uint8_t frame_control[2];
    uint8_t duration[2];
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint8_t seq_control[2];
};

struct ipv4_address {
    uint8_t byte1;
    uint8_t byte2;
    uint8_t byte3;
    uint8_t byte4;
};

struct ipv4_header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
};

struct ipv6_address {
    uint16_t segments[8]; 
};

struct ipv6_header {
    uint32_t version_traffic_class_flow_label;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;  
    uint8_t src_ip[16];
    uint8_t dest_ip[16];  
};

struct tcp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t data_offset : 4;
    uint8_t reserved : 4;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

struct udp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

struct ParsedPacket {
    std::wstring index;
    std::wstring time;
    std::wstring srcIp;
    std::wstring destIp;
    std::wstring protocol;
    std::wstring length;
    std::wstring srcPort;
    std::wstring destPort;
};
