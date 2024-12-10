#include <iostream>
#include <pcap.h>
#include <commctrl.h>
#include <string>
#include <cstdint>

#include "help/NetUtils.h"
#include "res/resource.h"
#include "include/file_utils/FileDialog.h"
#include "include/managers/CaptureManager.h"
#include "include/managers/DeviceManager.h"
#include "include/managers/PacketFileManager.h"
#include "include/packet_utils/PacketParser.h"
#include "include/ui/UIButton.h"
#include "include/ui/UIComboBox.h"
#include "include/ui/UILabel.h"
#include "include/ui/UIListView.h"

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR lpCmdLine, int nCmdShow) {
    WNDCLASSEX wcex; HWND hWnd; MSG msg;

    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_DBLCLKS;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInst;
    wcex.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = L"NetTrafficAnalyzer";
    wcex.hIconSm = wcex.hIcon;

    RegisterClassEx(&wcex);
    
    hWnd = CreateWindow(L"NetTrafficAnalyzer", L"Net Traffic Analyzer - ",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0,
        CW_USEDEFAULT, 0, NULL, NULL, hInst, NULL);
    
    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    InitCommonControls();

    HMENU hMenu = LoadMenu(hInst, MAKEINTRESOURCE(main_menu));
    SetMenu(hWnd, hMenu);
    
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return msg.wParam;
}

void UpdateWindowTitle(HWND hwnd, const std::string& filePath) {
    std::wstring title = L"Net Traffic Analyzer - " + std::wstring(filePath.begin(), filePath.end());
    SetWindowTextW(hwnd, title.c_str());
}

std::wstring ConvertToWideString(const std::string& str) {
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], size_needed);
    return wstr;
}

int NotifyForSave() {
    std::wstring message = ConvertToWideString("File is not saved. Do you want to save the changes?");
    std::wstring title = ConvertToWideString("Save Changes");

    int result = MessageBoxW(
        nullptr, 
        message.c_str(), 
        title.c_str(), 
        MB_YESNOCANCEL | MB_ICONWARNING | MB_DEFBUTTON1
    );

    return result;
}

void SavePackets(PacketManager& packetManager, std::string filePath) {
    try {
        PacketFileManager::SaveToFile(packetManager, filePath);
        std::cout << "Packets saved to: " << filePath << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error saving packets: " << e.what() << std::endl;
    }
}

void LoadPackets(PacketManager& packetManager, std::string filePath) {
    
    if (!filePath.empty()) {
        try {
            PacketFileManager::LoadFromFile(packetManager, filePath);
            std::cout << "Packets loaded from: " << filePath << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Error loading packets: " << e.what() << std::endl;
        }
    } else {
        std::cout << "Load operation canceled." << std::endl;
    }
}

// Thread function for capturing packets
DWORD WINAPI CaptureThreadFunction(LPVOID lpParam) {
    CaptureManager* captureManager = static_cast<CaptureManager*>(lpParam);

    if (captureManager) {
        captureManager->GetCurrentCapturer()->StartCapturing();
    }

    return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    static HBRUSH hBrush = NULL;
    
    static UILabel lbDevices;
    static UIComboBox cbDevices;
    static UIButton btnStart;
    static UIButton btnStop;
    static UIButton btnOpen;
    static UIButton btnSave;
    static UIButton btnSaveAs;
    static UIListView lvPackets;
    
    static DeviceManager deviceManager;
    static CaptureManager captureManager;
    static PacketManager packetManager;
    static FileDialog fileDialog(const_cast<wchar_t*>(L"Packet Files (*.cpt)\0*.cpt\0All Files (*.*)\0*.*\0"), const_cast<wchar_t*>(L".cpt"));

    static HANDLE hCaptureThread = NULL;
    
    switch (message) {
        case WM_CREATE: {
            // Declaring graphic resources
            hBrush = CreateSolidBrush(RGB(255, 255, 255));

            // Devices label
            lbDevices = UILabel(L"STATIC", L"Select Device:",
                WS_CHILD | WS_VISIBLE,
                10, 30, 200, 20, hWnd, (HMENU) id_lb_devices, NULL, NULL);

            // Devices combobox
            cbDevices = UIComboBox(L"COMBOBOX", NULL,
                WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                10, 50, 200, 100, hWnd, (HMENU) id_cb_devices, NULL, NULL);

            char **devices = deviceManager.GetDevicesDescriptions();
            int devicesCount = deviceManager.GetDevicesCount();
            cbDevices.FillWithDevices(devices, devicesCount);

            int scrollbarWidth = GetSystemMetrics(SM_CXVSCROLL);    
            cbDevices.SetBoxWidth(cbDevices.CalcMaxTextWidth() + 1.5 * scrollbarWidth);

            delete [] devices;

            // Start button
            btnStart = UIButton(L"BUTTON", L">",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                250, 30, 30, 30, hWnd, (HMENU) id_btn_start, NULL, NULL);
            EnableWindow(btnStart.GetHWindow(), FALSE);

            // Stop button
            btnStop = UIButton(L"BUTTON", L"0", 
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                295, 30, 30, 30, hWnd, (HMENU) id_btn_stop, NULL, NULL);
            EnableWindow(btnStop.GetHWindow(), FALSE);

            // Open button
            btnOpen = UIButton(L"BUTTON", L"OP", 
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                880, 30, 30, 30, hWnd, (HMENU) id_btn_open, NULL, NULL);

            // Save button
            btnSave = UIButton(L"BUTTON", L"S", 
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                925, 30, 30, 30, hWnd, (HMENU) id_btn_save, NULL, NULL);
            EnableWindow(btnSave.GetHWindow(), FALSE);
                
            // Save as button
            btnSaveAs = UIButton(L"BUTTON", L"SA", 
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                970, 30, 30, 30, hWnd, (HMENU) id_btn_save_as, NULL, NULL);
            EnableWindow(btnSaveAs.GetHWindow(), FALSE);
                
            // Packets listview
            lvPackets = UIListView(WC_LISTVIEW, NULL,
                WS_CHILD | WS_VISIBLE | LVS_REPORT,
                250, 80, 750, 370, hWnd, (HMENU) id_lv_packets, NULL, NULL);
                
            const wchar_t* columnsHeaders[] = { L"No.", L"Time", L"Source", L"Destination", L"Protocol", L"Length" };
            lvPackets.AddColumns(columnsHeaders, 6);
                
            break;
        }

        case WM_COMMAND: {
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                if (LOWORD(wParam) == id_cb_devices) {
                    int i = 0;
                    int selectedIndex = SendMessage(cbDevices.GetHWindow(), CB_GETCURSEL, 0, 0);
         
                    if (selectedIndex != CB_ERR) {
                        wchar_t selectedItemWChar[256];
                        char selectedItemChar[256];
                    
                        SendMessage(cbDevices.GetHWindow(), CB_GETLBTEXT, selectedIndex, (LPARAM)selectedItemWChar);
                        WideCharToMultiByte(CP_ACP, 0, selectedItemWChar, -1,
                            selectedItemChar, 256, NULL, NULL);

                        PacketsCapturer* packetsCapturer;
                        if ((packetsCapturer = captureManager.GetCapturer(selectedItemChar)) == nullptr) {
                            pcap_if_t *device = deviceManager.GetDeviceByDescription(selectedItemChar);
                            packetsCapturer = new PacketsCapturer(device->name, &packetManager, hWnd);
                            captureManager.AddCapturer(packetsCapturer);
                            captureManager.SetCurrentCapturer(packetsCapturer);
                        }
                    
                        EnableWindow(btnStart.GetHWindow(), TRUE);
                    }
                }
            }

            boolean isCancelled = false;
            switch (LOWORD(wParam))
            {
            case id_btn_start:
                if (!fileDialog.isFileSaved()) {
                    int result = NotifyForSave();

                    switch (result) {
                    case IDYES:
                        fileDialog.SaveFileDialog();
                        SavePackets(packetManager, fileDialog.GetLastPath());
                            
                        break;
                    case IDNO:
                            
                        break;
                    default:
                        isCancelled = true;
                            
                        break;
                    }
                }

                if (isCancelled) {
                    break;
                }
                    
                if (SendMessage(cbDevices.GetHWindow(), CB_GETCURSEL, 0, 0) == -1) {
                    break;
                }
                    
                packetManager.ClearPackets();
                ListView_DeleteAllItems(lvPackets.GetHWindow());
                
                hCaptureThread = CreateThread(
                    NULL,                   
                    0,                      
                    CaptureThreadFunction,  
                    &captureManager,
                    0,                      
                    NULL                    
                );
                
                fileDialog.SetFileNotSaved();

                EnableWindow(btnStart.GetHWindow(), FALSE);
                EnableWindow(btnStop.GetHWindow(), TRUE);
                EnableWindow(btnOpen.GetHWindow(), FALSE);
                EnableWindow(btnSave.GetHWindow(), FALSE);
                EnableWindow(btnSaveAs.GetHWindow(), FALSE);
                EnableWindow(cbDevices.GetHWindow(), FALSE);
                break;
            case id_btn_stop:
                captureManager.GetCurrentCapturer()->StopCapturing();

                if (hCaptureThread) {
                    CloseHandle(hCaptureThread); 
                }
                
                EnableWindow(btnStart.GetHWindow(), TRUE);
                EnableWindow(btnStop.GetHWindow(), FALSE);
                EnableWindow(btnOpen.GetHWindow(), TRUE);
                EnableWindow(btnSave.GetHWindow(), TRUE);
                EnableWindow(btnSaveAs.GetHWindow(), TRUE);
                EnableWindow(cbDevices.GetHWindow(), TRUE);
                break;
            case id_btn_save:
                if (!fileDialog.isFileSaved()) {
                    isCancelled = !fileDialog.SaveFileDialog();
                }

                if (!isCancelled) {
                    SavePackets(packetManager, fileDialog.GetLastPath());

                    UpdateWindowTitle(hWnd, fileDialog.GetLastPath());

                    EnableWindow(btnSave.GetHWindow(), FALSE);
                }
                
                    break;
                case id_btn_open:
                    if (!fileDialog.isFileSaved()) {
                        int result = NotifyForSave();

                        switch (result) {
                        case IDYES:
                            isCancelled = !fileDialog.SaveFileDialog();

                            if (!isCancelled) {
                                SavePackets(packetManager, fileDialog.GetLastPath());
                            }

                            isCancelled = false;
                            
                            break;
                        case IDNO:
                            
                            break;
                        default:
                            isCancelled = true;
                            
                            break;
                        }
                    }
                
                    if (!isCancelled) {
                        fileDialog.OpenFileDialog();
                        LoadPackets(packetManager, fileDialog.GetLastPath());

                        ListView_DeleteAllItems(lvPackets.GetHWindow());
                        PacketParser parser;
                        for (int i = 0; i < packetManager.GetPacketsCount(); i++) {
                            Packet* packet = packetManager.GetPacket(i);
                            ParsedPacket parsed = parser.ParsePacket(i, *packet);

                            const wchar_t* columnsValues[6] = {
                                parsed.index.c_str(),
                                parsed.time.c_str(),
                                parsed.srcIp.c_str(),
                                parsed.destIp.c_str(),
                                parsed.protocol.c_str(),
                                parsed.length.c_str()
                            };

                            boolean isScrolledDown = lvPackets.isScrolledDown();
                            lvPackets.AddRow(columnsValues);

                            if (isScrolledDown) {
                                lvPackets.ScrollDown();
                            }
                        }
                        
                        UpdateWindowTitle(hWnd, fileDialog.GetLastPath());

                        EnableWindow(btnSave.GetHWindow(), FALSE);
                        EnableWindow(btnOpen.GetHWindow(), TRUE);
                        EnableWindow(btnSaveAs.GetHWindow(), TRUE);
                    }
                        
                    break;
                case id_btn_save_as:
                    fileDialog.SaveFileDialog();
                    SavePackets(packetManager, fileDialog.GetLastPath());
                
                    UpdateWindowTitle(hWnd, fileDialog.GetLastPath());

                    EnableWindow(btnSave.GetHWindow(), FALSE);
                    
                    break;
                case id_btn_quit:
                    if (!fileDialog.isFileSaved()) {
                        int result = NotifyForSave();
                        if (result == IDYES) {
                            isCancelled = !fileDialog.SaveFileDialog();

                            if (!isCancelled) {
                                SavePackets(packetManager, fileDialog.GetLastPath());
                            } else {
                                break; 
                            }
                        } else if (result == IDCANCEL) {
                            break;
                        }
                    }
                    PostQuitMessage(0);
                    break;
                default:
                    break;
            }
                
            break;
        }

        case WM_ADD_LISTVIEW_ITEM: {
            int packetsCount = packetManager.GetPacketsCount();
            int displayedCount = ListView_GetItemCount(lvPackets.GetHWindow());
                
            PacketParser parser;
            for (int i = displayedCount; i < packetsCount; i++) {
                Packet* packet = packetManager.GetPacket(i);
                ParsedPacket parsed = parser.ParsePacket(i, *packet);

                const wchar_t* columnsValues[6] = {
                    parsed.index.c_str(),
                    parsed.time.c_str(),
                    parsed.srcIp.c_str(),
                    parsed.destIp.c_str(),
                    parsed.protocol.c_str(),
                    parsed.length.c_str()
                };

                boolean isScrolledDown = lvPackets.isScrolledDown();
                lvPackets.AddRow(columnsValues);

                if (isScrolledDown) {
                    lvPackets.ScrollDown();
                }
            }
                
            break;
        }
        
        case WM_CTLCOLORSTATIC: {
            HDC hdcStatic = (HDC)wParam;
            SetBkMode(hdcStatic, TRANSPARENT);
            return (LRESULT)hBrush;
        }
        
        case WM_DESTROY:
            // TODO: ADD DELETING ALL OBJECTS
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
    }

    return 0;
}
