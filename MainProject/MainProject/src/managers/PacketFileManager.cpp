#include "../../include/managers/PacketFileManager.h"

void PacketFileManager::SaveToFile(PacketManager &packetManager, const std::string &filePath) {
    std::ofstream file(filePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file for saving.");
    }

    int packetsCount = packetManager.GetPacketsCount();
    file.write(reinterpret_cast<const char*>(&packetsCount), sizeof(packetsCount));

    Packet **packets = packetManager.GetPackets();
    for (int i = 0; i < packetsCount; i++) {
        packets[i]->Serialize(file);  
    }

    file.close();
}

void PacketFileManager::LoadFromFile(PacketManager &packetManager, const std::string &filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file for loading.");
    }

    int packetsCount = 0;
    file.read(reinterpret_cast<char*>(&packetsCount), sizeof(packetsCount));

    packetManager.ClearPackets(); 
    for (int i = 0; i < packetsCount; i++) {
        Packet *packet = new Packet();
        packet->Deserialize(file);  
        packetManager.AddPacket(packet);
    }

    file.close();
}

// void PacketFileManager::CreateFileIfNotExists(const std::string &filePath) {
//     if (!std::filesystem(filePath)) {
//         std::ofstream file(filePath, std::ios::binary); 
//         if (!file) {
//             throw std::runtime_error("Failed to create file.");
//         }
//
//         int emptyPacketsCount = 0;
//         file.write(reinterpret_cast<const char*>(&emptyPacketsCount), sizeof(emptyPacketsCount));
//         file.close();
//     }
// }