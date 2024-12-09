#pragma once
#include "UIElement.h"
#include "../../help/Consts.h"
#include <commctrl.h>

class UIListView : public UIElement {
private:
    int _columnsCount = 0;
public:
    UIListView(LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle,
        int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu,
        HINSTANCE hInstance, LPVOID lpParam)
    : UIElement(lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam) {}

    UIListView () = default;

    void AddColumns(const wchar_t* columnsHeaders[], int columnsCount);
    void AddRow(const wchar_t* columnsValues[]);
    void ClearColumns();
};
