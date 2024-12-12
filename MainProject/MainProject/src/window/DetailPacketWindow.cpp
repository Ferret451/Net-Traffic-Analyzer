#include "../../include/window/DetailPacketWindow.h"

#include <iostream>
#include <string>

void DetailPacketWindow::RegisterDetailWindowClass() {
    WNDCLASSEX wcex = { 0 };
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.lpfnWndProc = DetailWindowProc;
    wcex.hInstance = GetModuleHandle(NULL);
    wcex.lpszClassName = L"DetailWindowClass";
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcex.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    if (!RegisterClassEx(&wcex)) {
        DWORD error = GetLastError();
        std::wcerr << L"Failed to register window class. Error: " << error << std::endl;
    }
}

LRESULT CALLBACK DetailPacketWindow::DetailWindowProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    static HBRUSH hBrush = CreateSolidBrush(RGB(255, 255, 255));
    
    switch (message) {
    case WM_CREATE:
    case WM_SIZE: {
        HWND hStatic = FindWindowEx(hWnd, NULL, WC_STATIC, NULL);
        if (hStatic) {
            RECT rect;
            GetClientRect(hWnd, &rect);
            MoveWindow(hStatic, 10, 10, rect.right - 20, rect.bottom - 20, TRUE);
        }

        InvalidateRect(hWnd, NULL, TRUE);
        break;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdcStatic = (HDC)wParam;
        SetBkMode(hdcStatic, TRANSPARENT);
        return (LRESULT)hBrush;
    }
    case WM_GETMINMAXINFO: {
        MINMAXINFO* pMinMax = (MINMAXINFO*)lParam;
        pMinMax->ptMinTrackSize.x = 400;
        pMinMax->ptMinTrackSize.y = 300;
        break;
    }
    case WM_CLOSE:
        DestroyWindow(hWnd);
        break;
    case WM_DESTROY:
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

void DetailPacketWindow::CreateDetailWindow(HWND parent, std::wstring packetDetails, int index) {
    HWND hDetailWnd = CreateWindow(
        L"DetailWindowClass",
        (L"Packet Details - " + std::to_wstring(index + 1)).c_str(),
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 300,
        parent, NULL, GetModuleHandle(NULL), NULL
    );

    if (hDetailWnd) {
        std::wstring packetInfo = L"Source IP: " ;
        
        HWND hStatic = CreateWindow(
            WC_STATIC,
            packetDetails.c_str(),
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX | SS_EDITCONTROL,
            10, 10, 380, 280,
            hDetailWnd, NULL, GetModuleHandle(NULL), NULL
        );
    }
}
