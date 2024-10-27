#include "../../include/ui/UIElement.h"

UIElement::UIElement(LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle,
    int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam) {
    this->lpClassName = lpClassName;
    this->lpWindowName = lpWindowName;
    this->dwStyle = dwStyle;
    this->x = x;
    this->y = y;
    this->nWidth = nWidth;
    this->nHeight = nHeight;
    this->hWndParent = hWndParent;
    this->hMenu = hMenu;
    this->hInstance = hInstance;
    this->lpParam = lpParam;

    hWindow = CreateWindow(lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight,
        hWndParent, hMenu, hInstance, lpParam);
}