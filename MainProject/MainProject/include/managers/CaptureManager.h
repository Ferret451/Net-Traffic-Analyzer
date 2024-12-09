#pragma once
#include "../../include/packet_utils/PacketsCapturer.h"

class CaptureManager {
    int capturersCount = 0;
    PacketsCapturer *currentCapturer = nullptr;
    PacketsCapturer *packetsCapturer[MAX_DEVICES] = {};
public:
    void AddCapturer(PacketsCapturer *capturer);
    PacketsCapturer *GetCapturer(int index);
    PacketsCapturer *GetCapturer(const char* name); 
    PacketsCapturer *GetCurrentCapturer();
    void SetCurrentCapturer(PacketsCapturer *capturer);
    ~CaptureManager();
};
