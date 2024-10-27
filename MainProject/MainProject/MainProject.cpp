#include <iostream>
#include <pcap.h>

#include "include/managers/DeviceManager.h"
#include "include/ui/UIComboBox.h"
#include "include/ui/UILabel.h"

DeviceManager deviceManager;

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

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return msg.wParam;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    static HBRUSH hBrush = NULL;
    static HWND hComboBox;
    
    switch (message) {
        case WM_CREATE: {
            deviceManager = DeviceManager();

            hBrush = CreateSolidBrush(RGB(255, 255, 255));

            UILabel lbDevices = UILabel(L"STATIC", L"Select device:",
                WS_CHILD | WS_VISIBLE,
                10, 30, 200, 20, hWnd, NULL, NULL, NULL);

            UIComboBox cbDevices = UIComboBox(L"COMBOBOX", NULL,
                WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                10, 50, 200, 100, hWnd, NULL, NULL, NULL);
            cbDevices.FillWithDevices(deviceManager.GetDevicesArray());
            cbDevices.SetBoxWidth(cbDevices.CalcMaxBoxWidth());
                
            break;
        }
                
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
                
            RECT rect;
            GetClientRect(hWnd, &rect);

            EndPaint(hWnd, &ps);
            break;
        }

         // case WM_COMMAND: {
         //    if (HIWORD(wParam) == CBN_SELCHANGE && LOWORD(wParam) == IDC_COMBOBOX) {
         //        // Получаем индекс выбранного элемента
         //        int selectedIndex = SendMessage(hComboBox, CB_GETCURSEL, 0, 0);
         //
         //        if (selectedIndex != CB_ERR) {
         //            wchar_t selectedItem[256];
         //            // Получаем текст выбранного элемента
         //            SendMessage(hComboBox, CB_GETLBTEXT, selectedIndex, (LPARAM)selectedItem);
         //            // Вывести выбранный элемент
         //            MessageBox(hWnd, selectedItem, L"Выбранный элемент", MB_OK);
         //
         //            
         //        }
         //    }
         //    break;
         // }

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
