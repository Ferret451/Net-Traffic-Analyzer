#include "../../include/ui/UIComboBox.h"

void UIComboBox::FillWithDevices(char **devices, int devicesCount) {
    HDC hdc = GetDC(GetHWindow()); 

    for (int i = 0; i < devicesCount; i++) {
        wchar_t item[256];
        char* device = devices[i];

        MultiByteToWideChar(CP_ACP, 0, device, -1, item, 256);
                
        SendMessage(GetHWindow(), CB_ADDSTRING, 0, (LPARAM)item);
    }

    ReleaseDC(GetHWindow(), hdc); 
}

int UIComboBox::CalcMaxTextWidth() {
    int maxTextWidth = 0;
    HDC hdc = GetDC(GetHWindow());
    SIZE textSize;
    wchar_t item[256];

    for (int i = 0; i < SendMessage(GetHWindow(), CB_GETCOUNT, 0, 0); i++) {
        SendMessage(GetHWindow(), CB_GETLBTEXT, i, (LPARAM)item);
        GetTextExtentPoint32(hdc, item, wcslen(item), &textSize);
        if (textSize.cx > maxTextWidth) {
            maxTextWidth = textSize.cx;
        }
    }
    
    ReleaseDC(GetHWindow(), hdc);
    return maxTextWidth;
}

void UIComboBox::SetBoxWidth(int width) {
    SendMessage(GetHWindow(), CB_SETDROPPEDWIDTH, width, 0);
}