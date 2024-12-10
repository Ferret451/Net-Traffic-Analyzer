#pragma once

#include <string>
#include <windows.h>

class FileDialog {
    wchar_t *filter;
    wchar_t *extension;
    mutable std::string lastPath = "C:\\";
public:
    FileDialog(wchar_t *filter, wchar_t *extension);
    
    boolean OpenFileDialog();
    boolean SaveFileDialog();

    boolean isFileSaved() const { return !lastPath.empty(); }
    std::string GetLastPath() const { return lastPath; }
    void SetFileNotSaved() const { lastPath.clear(); }
};
