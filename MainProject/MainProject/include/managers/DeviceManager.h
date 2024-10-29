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

    int GetDevicesCount();
    pcap_if_t * GetDevice(int index);
    char ** GetDevicesDescriptions();
};
