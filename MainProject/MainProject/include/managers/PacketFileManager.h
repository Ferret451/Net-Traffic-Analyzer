#pragma once

#include <fstream>
#include <stdexcept>

#include <filesystem>
#include "PacketManager.h"
#include "../packet_utils/Packet.h"

class PacketFileManager {
public:
    static void SaveToFile(PacketManager &packetManager, const std::string &filePath);
    static void LoadFromFile(PacketManager &packetManager, const std::string &filePath);
};
