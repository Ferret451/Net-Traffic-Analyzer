#include <iostream>
#include <pcap.h>
#include <commctrl.h>

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

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    static HBRUSH hBrush = NULL;
    static HWND hComboBoxDevices = NULL;
    static HWND hLabelDevices = NULL;
    static HWND hButtonStart = NULL;
    static HWND hButtonStop = NULL;
    static HWND hButtonPause = NULL;
    
    static DeviceManager deviceManager;
    static CaptureManager captureManager;
    static PacketManager packetManager;
    
    switch (message) {
        case WM_CREATE: {
            // Declaring graphic resources
            hBrush = CreateSolidBrush(RGB(255, 255, 255));

            // Devices label
            UILabel lbDevices = UILabel(L"STATIC", L"Select Device^",
                WS_CHILD | WS_VISIBLE,
                10, 30, 200, 20, hWnd, (HMENU) id_lb_devices, NULL, NULL);
            hLabelDevices = lbDevices.GetHWindow();

            // Devices combobox
            UIComboBox cbDevices = UIComboBox(L"COMBOBOX", NULL,
                WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                10, 50, 200, 100, hWnd, (HMENU) id_cb_devices, NULL, NULL);
            hComboBoxDevices = cbDevices.GetHWindow();

            char **devices = deviceManager.GetDevicesDescriptions();
            int devicesCount = deviceManager.GetDevicesCount();
            cbDevices.FillWithDevices(devices, devicesCount);

            int scrollbarWidth = GetSystemMetrics(SM_CXVSCROLL);    
            cbDevices.SetBoxWidth(cbDevices.CalcMaxTextWidth() + 1.5 * scrollbarWidth);

            delete [] devices;

            // Start button
            UIButton btnStart = UIButton(L"BUTTON", L">",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                250, 30, 30, 30, hWnd, (HMENU) id_btn_start, NULL, NULL);

            // Stop button
            UIButton btnStop = UIButton(L"BUTTON", L">||", 
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                295, 30, 30, 30, hWnd, (HMENU) id_btn_stop, NULL, NULL);

            // Pause button
            UIButton btnPause = UIButton(L"BUTTON", L"0", 
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                340, 30, 30, 30, hWnd, (HMENU) id_btn_pause, NULL, NULL);

            // Packets listview
            UIListView lvPackets = UIListView(WC_LISTVIEW, NULL,
                WS_CHILD | WS_VISIBLE | LVS_REPORT,
                250, 80, 750, 300, hWnd, (HMENU) id_lv_packets, NULL, NULL);
                
            const wchar_t* columnsHeaders[] = { L"No.", L"Time", L"Source", L"Destination", L"Protocol", L"Length" };
            lvPackets.AddColumns(columnsHeaders, 6);

            const wchar_t* columnsValues[] = { L"1", L"10:00:00", L"Me", L"You", L"IPV4", L"451", L"Hello" };
            lvPackets.AddRow(columnsValues);
                
            break;
        }

        case WM_COMMAND: {
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                if (LOWORD(wParam) == id_cb_devices) {
                    int i = 0;
                    int selectedIndex = SendMessage(hComboBoxDevices, CB_GETCURSEL, 0, 0);
         
                    if (selectedIndex != CB_ERR) {
                        wchar_t selectedItemWChar[256];
                        char selectedItemChar[256];
                    
                        SendMessage(hComboBoxDevices, CB_GETLBTEXT, selectedIndex, (LPARAM)selectedItemWChar);
                        WideCharToMultiByte(CP_ACP, 0, selectedItemWChar, -1,
                            selectedItemChar, 256, NULL, NULL);

                        PacketsCapturer* packetsCapturer;
                        if ((packetsCapturer = captureManager.GetCapturer(selectedItemChar)) == nullptr) {
                            packetsCapturer = new PacketsCapturer(selectedItemChar, &packetManager, hWnd);
                            captureManager.AddCapturer(packetsCapturer);
                        }

                        //packetsCapturer->StartCapturing(); 
                    
                        MessageBox(hWnd, selectedItemWChar, L"Picked Element", MB_OK);
                    }
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
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
    }

    return 0;
}
