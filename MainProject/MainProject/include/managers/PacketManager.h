    #pragma once

    #include "../packet_utils/Packet.h"
    #include "../../help/Consts.h"

    class PacketManager {
        int packetsCount = 0;
        Packet *packets[MAX_PACKETS_AMOUNT] = {};
    public:
        PacketManager();
        
        void AddPacket(Packet *packet);
        Packet *GetPacket(int index);
        Packet **GetPackets();
        int GetPacketsCount();
        void ClearPackets();

        ~PacketManager();
    };
