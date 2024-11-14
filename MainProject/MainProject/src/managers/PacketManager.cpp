#include "../../include/managers/PacketManager.h"

PacketManager::PacketManager() { }

void PacketManager::AddPacket(Packet *packet) {
    if (packetsCount >= MAX_PACKETS_AMOUNT) {
        return;
    }
    
    packets[packetsCount++] = packet;
}

Packet *PacketManager::GetPacket(int index) {
    return packets[index];
}

Packet **PacketManager::GetPackets() {
    return packets;
}

int PacketManager::GetPacketsCount() {
    return packetsCount;
}

void PacketManager::ClearPackets(){
    for (int i = 0; i < packetsCount; i++) {
        delete packets[i];
        packets[i] = NULL;
    }
    
    packetsCount = 0;
}

PacketManager::~PacketManager() {
    for (int i = 0; i < packetsCount; i++) {
        delete packets[i];
    }
}