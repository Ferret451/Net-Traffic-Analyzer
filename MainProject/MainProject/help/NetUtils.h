#pragma once
#include <cstdint>

struct wifi_header {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[6]; 
    uint8_t addr2[6]; 
    uint8_t addr3[6]; 
};

struct ipv4_address {
    uint8_t byte1;
    uint8_t byte2;
    uint8_t byte3;
    uint8_t byte4;
};

struct ipv4_header {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t tlen;
    uint16_t identification;
    uint16_t flags_fo;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t crc;
    ipv4_address saddr;
    ipv4_address daddr;
    uint32_t op_pad;
};

struct ipv6_address {
    uint16_t segments[8]; 
};

struct ipv6_header {
    uint32_t ver_tc_flow;  
    uint16_t payload_len;  
    uint8_t  next_header;   
    uint8_t  hop_limit;    
    ipv6_address saddr;    
    ipv6_address daddr;   
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
