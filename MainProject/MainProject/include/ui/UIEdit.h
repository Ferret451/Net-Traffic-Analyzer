#pragma once
#include "UIElement.h"

class UIEdit : public UIElement{
public:
    UIEdit(LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle,
        int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu,
        HINSTANCE hInstance, LPVOID lpParam)
    : UIElement(lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam) {}

    UIEdit() = default;

    wchar_t *GetText();
    void SetText(wchar_t *text);
    void Clear();

    boolean IsEmpty();
};
