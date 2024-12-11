#include "../../include/packet_utils/PacketsCapturer.h"
#include "../../help/Consts.h"
#include "../../include/packet_utils/Packet.h"
#include "../../include/managers/PacketManager.h"

PacketsCapturer::PacketsCapturer(const char* deviceName, PacketManager *packetManager, HWND hwnd) {
    this->deviceName = deviceName;
    this->packetManager = packetManager;
    this->hwnd = hwnd;
}

const char *PacketsCapturer::GetDeviceName() {
    return deviceName;
}

void PacketsCapturer::StartCapturing(std::string filterExp) {
    pcap_t *adHandle;
    char errBuf[PCAP_ERRBUF_SIZE];
    bpf_program filterCode;
    bpf_u_int32 netMask = 0; 
    
    if ((adHandle = pcap_open_live(deviceName, PACKET_SIZE, PCAP_OPENFLAG_PROMISCUOUS, 1000, errBuf)) == NULL) {
        printf("Error opening device: %s\n", errBuf);
        return;
    }
    
    pcap_if_t *device;
    if (pcap_findalldevs(&device, errBuf) == 0) {
        while (device != NULL) {
            if (strcmp(device->name, deviceName) == 0 && device->addresses != NULL) {
                sockaddr_in* netmask_addr = (sockaddr_in*)(device->addresses->netmask);
                if (netmask_addr) {
                    netMask = netmask_addr->sin_addr.s_addr;
                } else {
                    netMask = 0xFFFFFFFF;
                }
                break;
            }
            device = device->next;
        }
        pcap_freealldevs(device);
    }
    
    if (pcap_compile(adHandle, &filterCode, filterExp.c_str(), 1, netMask) == -1) {
        printf("Error compiling filter: %s\n", pcap_geterr(adHandle));
        pcap_close(adHandle);
        return;
    }
    
    if (pcap_setfilter(adHandle, &filterCode) == -1) {
        printf("Error setting filter: %s\n", pcap_geterr(adHandle));
        pcap_freecode(&filterCode);
        pcap_close(adHandle);
        return;
    }

    pcap_freecode(&filterCode);
    
    int res;
    pcap_pkthdr *header;
    const u_char *pkt_data;
    isCapturing = true;

    while (isCapturing) {
        res = pcap_next_ex(adHandle, &header, &pkt_data);

        if (res == 0)
            continue;

        if (res == -1) {
            printf("Error reading packets: %s\n", pcap_geterr(adHandle));
            pcap_close(adHandle);
            return;
        }

        Packet *packet = new Packet(header, pkt_data, adHandle);
        packetManager->AddPacket(packet);

        PostMessage(hwnd, WM_ADD_LISTVIEW_ITEM, 0, 0);
    }

    pcap_close(adHandle);
}

void PacketsCapturer::StopCapturing() {
    isCapturing = false;
}

