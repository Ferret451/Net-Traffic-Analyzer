#include "../../include/managers/CaptureManager.h"

void CaptureManager::AddCapturer(PacketsCapturer *capturer) {
    packetsCapturer[capturersCount++] = capturer;
}

PacketsCapturer *CaptureManager::GetCapturer(int index) {
    if (index < 0 || index >= capturersCount)
        return nullptr;
        
    return packetsCapturer[index];
}

PacketsCapturer *CaptureManager::GetCapturer(const char* name) {
    for (int i = 0; i < capturersCount; i++) {
        if (strcmp(packetsCapturer[i]->GetDeviceName(), name) == 0) {
            return packetsCapturer[i];
        }
    }
    
    return nullptr;
}

PacketsCapturer *CaptureManager::GetCurrentCapturer() {
    return currentCapturer;
}

void CaptureManager::SetCurrentCapturer(PacketsCapturer *capturer) {
    currentCapturer = capturer;
}

CaptureManager::~CaptureManager() {
    for (int i = 0; i < capturersCount; i++) {
        delete packetsCapturer[i];
    }
}