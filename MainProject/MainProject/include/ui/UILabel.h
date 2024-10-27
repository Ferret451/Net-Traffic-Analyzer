#pragma once
#include "UIElement.h"

class UILabel : public UIElement {
public:
    UILabel(LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle,
        int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu,
        HINSTANCE hInstance, LPVOID lpParam);
};
