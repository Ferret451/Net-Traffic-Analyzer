#pragma once
#include "UIElement.h"

class UIButton : public UIElement {
public:
    UIButton(LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle,
        int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu,
        HINSTANCE hInstance, LPVOID lpParam)
    : UIElement(lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam) {}
};
