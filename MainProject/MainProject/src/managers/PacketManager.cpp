#include "../../include/managers/PacketManager.h"

PacketManager::PacketManager() {
    
}

void PacketManager::AddPacket(Packet packet) {
    *packets[packetsCount++] = packet;
}

Packet *PacketManager::GetPacket(int index) {
    return packets[index];
}

PacketManager::~PacketManager() {
    for (int i = 0; i < packetsCount; i++) {
        delete &packets[i];
    }
}