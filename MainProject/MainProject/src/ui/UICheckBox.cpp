#include "../../include/ui/UICheckBox.h"

boolean UICheckBox::isChecked() {
    return SendMessage(GetHWindow(), BM_GETCHECK, 0, 0) == BST_CHECKED;
}

void UICheckBox::Check() {
    SendMessage(GetHWindow(), BM_SETCHECK, BST_CHECKED, 0);
}

void UICheckBox::Uncheck() {
    SendMessage(GetHWindow(), BM_SETCHECK, BST_UNCHECKED, 0);
}
