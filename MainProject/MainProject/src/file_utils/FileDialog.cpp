#include "../../include/file_utils/FileDialog.h"

#include <commdlg.h>
#include <string>
#include <iostream>

FileDialog::FileDialog(wchar_t *filter, wchar_t *extension) {
    this->filter = filter;
    this->extension = extension;
}

boolean FileDialog::OpenFileDialog() {
    OPENFILENAME ofn;
    wchar_t fileName[MAX_PATH] = L"";
    
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFilter = reinterpret_cast<LPCWSTR>(this->filter);
    ofn.lpstrFile = reinterpret_cast<LPWSTR>(fileName);
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    ofn.lpstrDefExt = extension;

    if (GetOpenFileNameW(&ofn)) {
        std::wstring ws(fileName);
        std::string result(ws.begin(), ws.end());
        lastPath = result;

        return true;
    }

    return false;
}

boolean FileDialog::SaveFileDialog() {
    OPENFILENAME ofn;
    wchar_t fileName[MAX_PATH] = L""; 
    
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr; 
    ofn.lpstrFilter = reinterpret_cast<LPCWSTR>(this->filter);
    ofn.lpstrFile = reinterpret_cast<LPWSTR>(fileName);
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = extension;

    if (GetSaveFileNameW(&ofn)) {
        std::wstring ws(fileName);
        std::string result(ws.begin(), ws.end());
        lastPath = result;
        
        return true;
    }

    return false;
}
