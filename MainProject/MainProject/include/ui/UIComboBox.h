#pragma once
#include "UIElement.h"
#include "../managers/DeviceManager.h"

class UIComboBox : public UIElement{
public:
    UIComboBox(LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle,
        int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu,
        HINSTANCE hInstance, LPVOID lpParam)
    : UIElement(lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam) {}

    UIComboBox () = default;

    void FillWithDevices(char **devices, int devicesCount);

    int CalcMaxTextWidth();
    void SetBoxWidth(int width);
};
