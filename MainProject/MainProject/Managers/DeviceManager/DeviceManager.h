#pragma once
#include <pcap/pcap.h>
#include <../../MainProject/MainProject/Help/Consts.h>

class DeviceManager {
private:
    int devicesCount = 0;
    pcap_if_t * devicesArray[MAX_DEVICES] = {};
public:
    DeviceManager();
    
    void SetAllDevices();
    pcap_if_t * GetDevice(int index);
};
