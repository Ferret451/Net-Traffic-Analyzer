#include "../../include/ui/UIEdit.h"

wchar_t* UIEdit::GetText() {
    int length = GetWindowTextLength(GetHWindow());
    wchar_t* buffer = new wchar_t[length + 1];
    GetWindowText(GetHWindow(), buffer, length + 1);
    return buffer;
}

void UIEdit::SetText(wchar_t* text) {
    SetWindowText(GetHWindow(), text);
}

void UIEdit::Clear() {
    SetWindowText(GetHWindow(), L"");
}

boolean UIEdit::IsEmpty() {
    return GetWindowTextLength(GetHWindow()) == 0;
}
