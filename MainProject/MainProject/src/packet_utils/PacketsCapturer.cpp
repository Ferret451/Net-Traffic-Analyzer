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

void PacketsCapturer::StartCapturing() {
    pcap_t *adHandle;
    char errBuf[PCAP_ERRBUF_SIZE];
    
    if ((adHandle = pcap_open_live(deviceName, PACKET_SIZE, PCAP_OPENFLAG_PROMISCUOUS, 1000, errBuf ) ) == NULL) {

        //TODO: add printing error
        
        return;
    }

    int res;
    pcap_pkthdr *header;
    const u_char *pkt_data;
    isCapturing = true;
    
    while(isCapturing){
        res = pcap_next_ex(adHandle, &header, &pkt_data);
        
        if (res == 0)
            continue;

        if (res == -1){
            printf("Error reading the packets: %s\n", pcap_geterr(adHandle));

            //TODO: add printing error

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

