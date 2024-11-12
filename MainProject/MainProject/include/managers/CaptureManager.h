#pragma once
#include "../PacketsCapturer.h"

class CaptureManager {
    int capturersCount = 0;
    PacketsCapturer *currentCapturer = nullptr;
    PacketsCapturer *packetsCapturer[MAX_DEVICES] = {};
public:
    void AddCapturer(PacketsCapturer *capturer);
    PacketsCapturer *GetCapturer(int index);
    PacketsCapturer *GetCapturer(const char* name); 
    PacketsCapturer *GetCurrentCapturer(); 
    ~CaptureManager();
};
