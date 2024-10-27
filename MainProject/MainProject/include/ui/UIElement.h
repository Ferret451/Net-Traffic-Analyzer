#pragma once

#include <pcap.h>

class UIElement {
private:
    HWND hWindow;
    LPCWSTR lpClassName; LPCWSTR lpWindowName;
    DWORD dwStyle;
    int x; int y; int nWidth; int nHeight;
    HWND hWndParent; HMENU hMenu; HINSTANCE hInstance;
    LPVOID lpParam;
public:
    UIElement(LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle,
        int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu,
        HINSTANCE hInstance, LPVOID lpParam);

    HWND GetHWindow() { return hWindow; }
};
