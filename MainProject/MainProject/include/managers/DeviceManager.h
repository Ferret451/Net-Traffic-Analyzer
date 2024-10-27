#pragma once
#include <pcap/pcap.h>
#include <../../MainProject/MainProject/help/Consts.h>

class DeviceManager {
private:
    int devicesCount = 0;
    pcap_if_t * devicesArray[MAX_DEVICES] = {};
public:
    DeviceManager();
    
    void FindAllDevices();
    pcap_if_t * GetDevice(int index);
    pcap_if_t ** GetDevicesArray();
};
