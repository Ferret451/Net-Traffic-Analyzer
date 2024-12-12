#pragma once

#include <pcap.h>
#include <commctrl.h>
#include "../packet_utils/Packet.h"

class DetailPacketWindow {
    static LRESULT CALLBACK DetailWindowProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
public:
    static void CreateDetailWindow(HWND parent, std::wstring packetDetails, int index);
    static void RegisterDetailWindowClass();
};
