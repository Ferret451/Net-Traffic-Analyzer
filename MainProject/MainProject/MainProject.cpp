#include <iostream>
#include <pcap.h>
#include <commctrl.h>
#include <string>
#include <cstdint>

#include "include/managers/CaptureManager.h"
#include "include/managers/DeviceManager.h"
#include "include/ui/UIButton.h"
#include "include/ui/UIComboBox.h"
#include "include/ui/UILabel.h"
#include "include/ui/UIListView.h"

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR lpCmdLine, int nCmdShow) {
    WNDCLASSEX wcex; HWND hWnd; MSG msg;

    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_DBLCLKS;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInst;
    wcex.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = L"NetTrafficAnalyzer";
    wcex.hIconSm = wcex.hIcon;

    RegisterClassEx(&wcex);
    
    hWnd = CreateWindow(L"NetTrafficAnalyzer", L"Net Traffic Analyzer",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0,
        CW_USEDEFAULT, 0, NULL, NULL, hInst, NULL);
    
    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    InitCommonControls();
    
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return msg.wParam;
}

// Combining two bytes into unsigned short
unsigned short combineTwoBytes(unsigned short high, unsigned short low) {
    return (u_short)(high << 8 | low);
}

// Getting the length of the Wi-Fi header, because it can be 24 or 30 bytes
int getWifiHeaderLength(const u_char* pkt_data) {
    const wifi_header* wh = reinterpret_cast<const wifi_header*>(pkt_data);

    uint16_t frame_control = wh->frame_control; 
    uint8_t high_byte = frame_control >> 8 & 0xFF; 
    uint8_t low_byte = frame_control & 0xFF; 
    uint16_t combined = combineTwoBytes(high_byte, low_byte);
    
    int type = (combined & 0x0C) >> 2;
    if (type == 2) { 
        bool hasAddr4 = combined & 0x03;
        return hasAddr4 ? 30 : 24;
    }
    
    return 24;
}

// Thread function for capturing packets
DWORD WINAPI CaptureThreadFunction(LPVOID lpParam) {
    CaptureManager* captureManager = static_cast<CaptureManager*>(lpParam);

    if (captureManager) {
        captureManager->GetCurrentCapturer()->StartCapturing();
    }

    return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    static HBRUSH hBrush = NULL;
    
    static UILabel lbDevices = UILabel();
    static UIComboBox cbDevices = UIComboBox();
    static UIButton btnStart = UIButton();
    static UIButton btnStop = UIButton();
    static UIListView lvPackets = UIListView();
    
    static DeviceManager deviceManager;
    static CaptureManager captureManager;
    static PacketManager packetManager;

    static HANDLE hCaptureThread = NULL;
    
    switch (message) {
        case WM_CREATE: {
            // Declaring graphic resources
            hBrush = CreateSolidBrush(RGB(255, 255, 255));

            // Devices label
            lbDevices = UILabel(L"STATIC", L"Select Device:",
                WS_CHILD | WS_VISIBLE,
                10, 30, 200, 20, hWnd, (HMENU) id_lb_devices, NULL, NULL);

            // Devices combobox
            cbDevices = UIComboBox(L"COMBOBOX", NULL,
                WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                10, 50, 200, 100, hWnd, (HMENU) id_cb_devices, NULL, NULL);

            char **devices = deviceManager.GetDevicesDescriptions();
            int devicesCount = deviceManager.GetDevicesCount();
            cbDevices.FillWithDevices(devices, devicesCount);

            int scrollbarWidth = GetSystemMetrics(SM_CXVSCROLL);    
            cbDevices.SetBoxWidth(cbDevices.CalcMaxTextWidth() + 1.5 * scrollbarWidth);

            delete [] devices;

            // Start button
            btnStart = UIButton(L"BUTTON", L">",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                250, 30, 30, 30, hWnd, (HMENU) id_btn_start, NULL, NULL);
            EnableWindow(btnStart.GetHWindow(), FALSE);

            // Stop button
            btnStop = UIButton(L"BUTTON", L"0", 
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                295, 30, 30, 30, hWnd, (HMENU) id_btn_stop, NULL, NULL);
            EnableWindow(btnStop.GetHWindow(), FALSE);

            // Packets listview
            lvPackets = UIListView(WC_LISTVIEW, NULL,
                WS_CHILD | WS_VISIBLE | LVS_REPORT,
                250, 80, 750, 370, hWnd, (HMENU) id_lv_packets, NULL, NULL);
                
            const wchar_t* columnsHeaders[] = { L"No.", L"Time", L"Source", L"Destination", L"Protocol", L"Length" };
            lvPackets.AddColumns(columnsHeaders, 6);
                
            break;
        }

        case WM_COMMAND: {
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                if (LOWORD(wParam) == id_cb_devices) {
                    int i = 0;
                    int selectedIndex = SendMessage(cbDevices.GetHWindow(), CB_GETCURSEL, 0, 0);
         
                    if (selectedIndex != CB_ERR) {
                        wchar_t selectedItemWChar[256];
                        char selectedItemChar[256];
                    
                        SendMessage(cbDevices.GetHWindow(), CB_GETLBTEXT, selectedIndex, (LPARAM)selectedItemWChar);
                        WideCharToMultiByte(CP_ACP, 0, selectedItemWChar, -1,
                            selectedItemChar, 256, NULL, NULL);

                        PacketsCapturer* packetsCapturer;
                        if ((packetsCapturer = captureManager.GetCapturer(selectedItemChar)) == nullptr) {
                            pcap_if_t *device = deviceManager.GetDeviceByDescription(selectedItemChar);
                            packetsCapturer = new PacketsCapturer(device->name, &packetManager, hWnd);
                            captureManager.AddCapturer(packetsCapturer);
                            captureManager.SetCurrentCapturer(packetsCapturer);
                        }
                    
                        EnableWindow(btnStart.GetHWindow(), TRUE);
                    }
                }
            }
                
            switch (LOWORD(wParam)) {
                case id_btn_start:
                    if (SendMessage(cbDevices.GetHWindow(), CB_GETCURSEL, 0, 0) == -1)
                        //TODO: add printing error

                        break;
                    
                    packetManager.ClearPackets();
                    ListView_DeleteAllItems(lvPackets.GetHWindow());
                
                    hCaptureThread = CreateThread(
                        NULL,                   
                        0,                      
                        CaptureThreadFunction,  
                        &captureManager,
                        0,                      
                        NULL                    
                    );

                    EnableWindow(btnStart.GetHWindow(), FALSE);
                    EnableWindow(btnStop.GetHWindow(), TRUE);
                    EnableWindow(cbDevices.GetHWindow(), FALSE);
                    break;
                case id_btn_stop:
                    captureManager.GetCurrentCapturer()->StopCapturing();

                    if (hCaptureThread) {
                        CloseHandle(hCaptureThread); 
                    }
                
                    EnableWindow(btnStart.GetHWindow(), TRUE);
                    EnableWindow(btnStop.GetHWindow(), FALSE);
                    EnableWindow(cbDevices.GetHWindow(), TRUE);
                    break;
                default:
                    break;
            }
                
            break;
        }

        case WM_ADD_LISTVIEW_ITEM: {
            int receivedCount = packetManager.GetPacketsCount();
            int displayedCount = ListView_GetItemCount(lvPackets.GetHWindow());
                
            for (int i = displayedCount; i < receivedCount; i++) {
                Packet *packet = packetManager.GetPacket(i);
                const u_char *data = packet->GetData();
                const wchar_t* columnsValues[6];
                
                std::wstring packetIndex = std::to_wstring(i);
                std::wstring timeString = packet->GetTimeString();

                columnsValues[0] = packetIndex.c_str();
                columnsValues[1] = timeString.c_str();
                
                int link_type = packet->GetLinkType();
                const u_char* ip_data = nullptr;
                u_short eth_type = 0;
                
                if (link_type == DLT_EN10MB) {  // Ethernet
                    eth_type = combineTwoBytes(data[12], data[13]);
                    ip_data = data + 14;
                    // // IPv4
                    // if (eth_type == 0x0800) { 
                    //     ip_data = data + 14;
                    // }
                    // // IPv6
                    // else if (eth_type == 0x86DD) { 
                    //     ip_data = data + 14; 
                    // }
                }
                else if (link_type == DLT_IEEE802_11) { // WI-FI
                    int wifi_header_len = getWifiHeaderLength(data); 
                    eth_type = combineTwoBytes(data[wifi_header_len], data[wifi_header_len + 1]);
                }

                std::wstring srcIpStr, destIpStr, protoStr, lengthStr;
                if (eth_type == 0x0800) {  // IPv4
                    ipv4_header* ih = (ipv4_header*)ip_data;

                    srcIpStr = std::to_wstring(ih->saddr.byte1) + L"." +
                               std::to_wstring(ih->saddr.byte2) + L"." +
                               std::to_wstring(ih->saddr.byte3) + L"." +
                               std::to_wstring(ih->saddr.byte4);
    
                    destIpStr = std::to_wstring(ih->daddr.byte1) + L"." +
                                std::to_wstring(ih->daddr.byte2) + L"." +
                                std::to_wstring(ih->daddr.byte3) + L"." +
                                std::to_wstring(ih->daddr.byte4);

                    if (ih->proto == 6) {
                        protoStr = L"TCP";
                    } else if (ih->proto == 17) {
                        protoStr = L"UDP";
                    } else {
                        protoStr = L"Other";
                    }
                    
                    lengthStr = std::to_wstring(packet->GetLength());

                    columnsValues[2] = srcIpStr.c_str();
                    columnsValues[3] = destIpStr.c_str();
                    columnsValues[4] = protoStr.c_str(); 
                    columnsValues[5] = lengthStr.c_str();
                } else if (eth_type == 0x86DD) {  // IPv6
                    ipv6_header* ih6 = (ipv6_header*)ip_data;

                    std::wstring srcIpStr = std::to_wstring(combineTwoBytes(ih6->saddr.segments[0], ih6->saddr.segments[1])) + L":" +
                                            std::to_wstring(combineTwoBytes(ih6->saddr.segments[2], ih6->saddr.segments[3])) + L":" +
                                            std::to_wstring(combineTwoBytes(ih6->saddr.segments[4], ih6->saddr.segments[5])) + L":" +
                                            std::to_wstring(combineTwoBytes(ih6->saddr.segments[6], ih6->saddr.segments[7])) + L":" +
                                            std::to_wstring(combineTwoBytes(ih6->saddr.segments[8], ih6->saddr.segments[9])) + L":" +
                                            std::to_wstring(combineTwoBytes(ih6->saddr.segments[10], ih6->saddr.segments[11])) + L":" +
                                            std::to_wstring(combineTwoBytes(ih6->saddr.segments[12], ih6->saddr.segments[13])) + L":" +
                                            std::to_wstring(combineTwoBytes(ih6->saddr.segments[14], ih6->saddr.segments[15]));

                    std::wstring destIpStr = std::to_wstring(combineTwoBytes(ih6->daddr.segments[0], ih6->daddr.segments[1])) + L":" +
                                             std::to_wstring(combineTwoBytes(ih6->daddr.segments[2], ih6->daddr.segments[3])) + L":" +
                                             std::to_wstring(combineTwoBytes(ih6->daddr.segments[4], ih6->daddr.segments[5])) + L":" +
                                             std::to_wstring(combineTwoBytes(ih6->daddr.segments[6], ih6->daddr.segments[7])) + L":" +
                                             std::to_wstring(combineTwoBytes(ih6->daddr.segments[8], ih6->daddr.segments[9])) + L":" +
                                             std::to_wstring(combineTwoBytes(ih6->daddr.segments[10], ih6->daddr.segments[11])) + L":" +
                                             std::to_wstring(combineTwoBytes(ih6->daddr.segments[12], ih6->daddr.segments[13])) + L":" +
                                             std::to_wstring(combineTwoBytes(ih6->daddr.segments[14], ih6->daddr.segments[15]));

                    if (ih6->next_header == 6) {
                        protoStr = L"TCP";
                    } else if (ih6->next_header == 17) {
                        protoStr = L"UDP";
                    } else {
                        protoStr = L"Other";
                    }
                    
                    std::wstring lengthStr = std::to_wstring(packet->GetLength());

                    columnsValues[2] = srcIpStr.c_str();
                    columnsValues[3] = destIpStr.c_str();
                    columnsValues[4] = protoStr.c_str();
                    columnsValues[5] = lengthStr.c_str();
                } else {
                    columnsValues[2] = L"N/A";
                    columnsValues[3] = L"N/A";
                    columnsValues[4] = L"N/A";
                    columnsValues[5] = L"N/A";
                }

                boolean isScrolledDown = lvPackets.isScrolledDown();
                lvPackets.AddRow(columnsValues);

                if (isScrolledDown) {
                    lvPackets.ScrollDown();
                }
            }
                
            break;        
        }
        
        case WM_CTLCOLORSTATIC: {
            HDC hdcStatic = (HDC)wParam;
            SetBkMode(hdcStatic, TRANSPARENT);
            return (LRESULT)hBrush;
        }
        
        case WM_DESTROY:
            // TODO: ADD DELETING ALL OBJECTS
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
    }

    return 0;
}
