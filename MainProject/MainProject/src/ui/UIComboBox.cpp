#include "../../include/ui/UIComboBox.h"

UIComboBox::UIComboBox(LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle,
    int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu,
    HINSTANCE hInstance, LPVOID lpParam) :
        UIElement(lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam) {
    
}

void UIComboBox::FillWithDevices(pcap_if_t **devicesArray) {
    int i = 0;
    pcap_if_t* device;
    HDC hdc = GetDC(GetHWindow()); 

    while ((device = devicesArray[i++]) != NULL) {
        wchar_t item[256];

        MultiByteToWideChar(CP_ACP, 0, device->description, -1, item, 256);
                
        SendMessage(GetHWindow(), CB_ADDSTRING, 0, (LPARAM)item);
    }

    ReleaseDC(GetHWindow(), hdc); 
}

int UIComboBox::CalcMaxBoxWidth() {
    int maxWidth = 0;
    HDC hdc = GetDC(GetHWindow());
    SIZE textSize;
    wchar_t item[256];

    for (int i = 0; i < SendMessage(GetHWindow(), CB_GETCOUNT, 0, 0); i++) {
        SendMessage(GetHWindow(), CB_GETLBTEXT, i, (LPARAM)item);
        GetTextExtentPoint32(hdc, item, wcslen(item), &textSize);
        if (textSize.cx > maxWidth) {
            maxWidth = textSize.cx;
        }
    }

    ReleaseDC(GetHWindow(), hdc);
    return maxWidth;
}

void UIComboBox::SetBoxWidth(int width) {
    SendMessage(GetHWindow(), CB_SETDROPPEDWIDTH, width, 0);
}