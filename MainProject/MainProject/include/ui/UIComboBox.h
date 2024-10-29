#pragma once
#include "UIElement.h"
#include "../managers/DeviceManager.h"

class UIComboBox : public UIElement{
public:
    UIComboBox(LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle,
        int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu,
        HINSTANCE hInstance, LPVOID lpParam);

    void FillWithDevices(char **devices, int devicesCount);

    int CalcMaxBoxWidth();
    void SetBoxWidth(int width);
};
