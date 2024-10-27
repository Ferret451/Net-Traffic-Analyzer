#include "../../include/managers/DeviceManager.h"

#include <iostream>

DeviceManager::DeviceManager() {
    FindAllDevices();
}

void DeviceManager::FindAllDevices() {
    pcap_if_t *allDevs;
    char errBuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&allDevs, errBuf) == -1) {
        std::cerr << "Error when getting devices: " << errBuf << '\n';
        return;
    }

    int index = 0;
    for (pcap_if_t* device = allDevs; device != nullptr && index < MAX_DEVICES; device = device->next) {
        devicesArray[index] = new pcap_if_t;
        std::memcpy(devicesArray[index], device, sizeof(pcap_if_t));
        
        if (device->name != nullptr) {
            devicesArray[index]->name = _strdup(device->name);
        }
        
        if (device->description != nullptr) {
            devicesArray[index]->description = _strdup(device->description);
        }
        
        index++;
    }
    devicesCount = index;

    pcap_freealldevs(allDevs);
}

pcap_if_t* DeviceManager::GetDevice(int index) {
    if (index >= devicesCount || index < 0) {
        return nullptr;
    }
    
    return devicesArray[index];
}

pcap_if_t** DeviceManager::GetDevicesArray() {
    return devicesArray;
}
