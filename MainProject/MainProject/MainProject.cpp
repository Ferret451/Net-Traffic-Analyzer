#include <iostream>
#include <pcap.h>
#include <commctrl.h>
#include <string>
#include <cstdint>

#include "help/NetUtils.h"
#include "include/managers/CaptureManager.h"
#include "include/managers/DeviceManager.h"
#include "include/packet_utils/PacketParser.h"
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
                
            PacketParser parser;
            for (int i = displayedCount; i < receivedCount; i++) {
                Packet* packet = packetManager.GetPacket(i);
                ParsedPacket parsed = parser.ParsePacket(i, *packet);

                const wchar_t* columnsValues[6] = {
                    parsed.index.c_str(),
                    parsed.time.c_str(),
                    parsed.srcIp.c_str(),
                    parsed.destIp.c_str(),
                    parsed.protocol.c_str(),
                    parsed.length.c_str()
                };

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
