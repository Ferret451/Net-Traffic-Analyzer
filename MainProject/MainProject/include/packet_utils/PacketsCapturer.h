#pragma once
#include <mutex>

#include "../managers/PacketManager.h"

class PacketsCapturer {
    PacketManager *packetManager;
    HWND hwnd;
    
    const char* deviceName;
    std::atomic<bool> isCapturing;
public:
    PacketsCapturer(const char* deviceName, PacketManager *packetManager, HWND hwnd);

    const char* GetDeviceName();
    boolean IsCapturing() const { return isCapturing; };
    
    void StartCapturing(std::string filterExp);
    void StopCapturing();
};
