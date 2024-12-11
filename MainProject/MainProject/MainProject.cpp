#include <iostream>
#include <pcap.h>
#include <commctrl.h>
#include <string>
#include <cstdint>
#include <regex>

#include "help/NetUtils.h"
#include "res/resource.h"
#include "include/file_utils/FileDialog.h"
#include "include/managers/CaptureManager.h"
#include "include/managers/DeviceManager.h"
#include "include/managers/PacketFileManager.h"
#include "include/packet_utils/PacketParser.h"
#include "include/ui/UIButton.h"
#include "include/ui/UICheckBox.h"
#include "include/ui/UIComboBox.h"
#include "include/ui/UIEdit.h"
#include "include/ui/UILabel.h"
#include "include/ui/UIListView.h"

struct CaptureThreadParams {
    CaptureManager* captureManager;
    std::string filterExp;
};

ACCEL accelTable[] = {
    { FVIRTKEY | FCONTROL, 'O', id_btn_open },
    { FVIRTKEY | FCONTROL, 'S', id_btn_save },
    { FVIRTKEY | FCONTROL | FSHIFT, 'S', id_btn_save_as },
    { FVIRTKEY, VK_F9, id_btn_start },
    { FVIRTKEY, VK_F10, id_btn_stop },
    { FVIRTKEY | FCONTROL, 'Q', id_btn_quit }
};

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
    
    HACCEL hAccel = CreateAcceleratorTable(accelTable, ARRAYSIZE(accelTable));
    
    hWnd = CreateWindow(L"NetTrafficAnalyzer", L"Net Traffic Analyzer - ",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, CW_USEDEFAULT, 0,
        CW_USEDEFAULT, 0, NULL, NULL, hInst, NULL);
    
    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    InitCommonControls();

    HMENU hMenu = LoadMenu(hInst, MAKEINTRESOURCE(id_main_menu));
    SetMenu(hWnd, hMenu);
    
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (!TranslateAccelerator(hWnd, hAccel, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
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
    CaptureThreadParams* params = static_cast<CaptureThreadParams*>(lpParam);
    
    if (params->captureManager) {
        params->captureManager->GetCurrentCapturer()->StartCapturing(params->filterExp);
    }

    delete params;

    return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    static HBRUSH hBrush = NULL;
    
    static UILabel lbDevices;
    static UILabel lbIpSource;
    static UILabel lbIpDest;
    static UILabel lbPortSource;
    static UILabel lbPortDest;
    static UILabel lbNetworkLayer;
    static UILabel lbTransportLayer;
    static UILabel lbCapturingFilters;
    static UIEdit edtIpSource;
    static UIEdit edtIpDest;
    static UIEdit edtPortSource;
    static UIEdit edtPortDest;
    static UIComboBox cbDevices;
    static UICheckBox chbIpv4;
    static UICheckBox chbIpv6;
    static UICheckBox chbTCP;
    static UICheckBox chbUDP;
    static UIButton btnStart;
    static UIButton btnStop;
    static UIButton btnOpen;
    static UIButton btnSave;
    static UIButton btnSaveAs;
    static UIButton btnDefaultFilters;
    static UIListView lvPackets;
    
    static DeviceManager deviceManager;
    static CaptureManager captureManager;
    static PacketManager packetManager;
    static FileDialog fileDialog(const_cast<wchar_t*>(L"Packet Files (*.cpt)\0*.cpt\0All Files (*.*)\0*.*\0"), const_cast<wchar_t*>(L".cpt"));

    static HANDLE hCaptureThread = NULL;

    boolean isCancelled = false;
    std::string filterExp;
    CaptureThreadParams* params = new CaptureThreadParams;
    
    switch (message) {
    case WM_CREATE: {
            // Declaring graphic resources
            hBrush = CreateSolidBrush(RGB(255, 255, 255));

            // Devices label
            lbDevices = UILabel(L"STATIC", L"Select Device:",
                WS_CHILD | WS_VISIBLE,
                10, 10, 200, 20, hWnd, (HMENU) id_lb_devices, NULL, NULL);

            // Devices combobox
            cbDevices = UIComboBox(L"COMBOBOX", NULL,
                WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                10, 30, 200, 100, hWnd, (HMENU) id_cb_devices, NULL, NULL);

            char **devices = deviceManager.GetDevicesDescriptions();
            int devicesCount = deviceManager.GetDevicesCount();
            cbDevices.FillWithDevices(devices, devicesCount);

            int scrollbarWidth = GetSystemMetrics(SM_CXVSCROLL);    
            cbDevices.SetBoxWidth(cbDevices.CalcMaxTextWidth() + 1.5 * scrollbarWidth);

            delete [] devices;

            // Capturing filters label
            lbCapturingFilters = UILabel(L"STATIC", L"Capturing filters:",
                WS_CHILD | WS_VISIBLE,
                10, 60, 200, 20, hWnd, (HMENU) id_lb_capt_filters, NULL, NULL);

            // Source ip label
            lbIpSource = UILabel(L"STATIC", L"Source IP:",
                WS_CHILD | WS_VISIBLE,
                10, 90, 200, 20, hWnd, (HMENU) id_lb_ip_src, NULL, NULL);

            // Source ip edit
            edtIpSource = UIEdit( L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL,
                10, 110, 200, 20, hWnd, (HMENU) id_edt_ip_source, NULL, NULL);

            // Dest ip label
            lbIpDest = UILabel(L"STATIC", L"Destination IP:",
                WS_CHILD | WS_VISIBLE,
                10, 130, 200, 20, hWnd, (HMENU) id_lb_ip_dest, NULL, NULL);

            // Dest ip edit
            edtIpDest = UIEdit( L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL,
                10, 150, 200, 20, hWnd, (HMENU) id_edt_ip_dest, NULL, NULL);

            // Network layer label
            lbNetworkLayer = UILabel(L"STATIC", L"Network layer:",
                WS_CHILD | WS_VISIBLE,
                10, 180, 200, 20, hWnd, (HMENU) id_lb_network_layer, NULL, NULL);

            // Ipv4 check box
            chbIpv4 = UICheckBox(L"BUTTON", L"Ipv4",
                WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                10, 200, 200, 20, hWnd, (HMENU) id_chb_ipv4, NULL, NULL);
            chbIpv4.Check();

            // Ipv6 check box
            chbIpv6 = UICheckBox(L"BUTTON", L"Ipv6",
                WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                10, 220, 200, 20, hWnd, (HMENU) id_chb_ipv6, NULL, NULL);
            chbIpv6.Check();

            // Source port label
            lbPortSource = UILabel(L"STATIC", L"Source Port:",
                WS_CHILD | WS_VISIBLE,
                10, 250, 200, 20, hWnd, (HMENU) id_lb_port_src, NULL, NULL);

            // Source port edit
            edtPortSource = UIEdit( L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL,
                10, 270, 200, 20, hWnd, (HMENU) id_edt_port_source, NULL, NULL);

            // Dest port label
            lbPortDest = UILabel(L"STATIC", L"Destination Port:",
                WS_CHILD | WS_VISIBLE,
                10, 290, 200, 20, hWnd, (HMENU) id_lb_port_dest, NULL, NULL);

            // Dest port edit
            edtPortDest = UIEdit( L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL,
                10, 310, 200, 20, hWnd, (HMENU) id_edt_port_dest, NULL, NULL);

            // Transport layer label
            lbTransportLayer = UILabel(L"STATIC", L"Transport layer:",
                WS_CHILD | WS_VISIBLE,
                10, 340, 200, 20, hWnd, (HMENU) id_lb_transport_layer, NULL, NULL);

            // TCP check box
            chbTCP = UICheckBox(L"BUTTON", L"TCP",
                WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                10, 360, 200, 20, hWnd, (HMENU) id_chb_tcp, NULL, NULL);
            chbTCP.Check();

            // UDP check box
            chbUDP = UICheckBox(L"BUTTON", L"UDP",
                WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                10, 380, 200, 20, hWnd, (HMENU) id_chb_udp, NULL, NULL);
            chbUDP.Check();

            // Default filters button
            btnDefaultFilters = UIButton(L"BUTTON", L"Default",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 413, 200, 30, hWnd, (HMENU) id_btn_start, NULL, NULL);
                
            // Start button
            btnStart = UIButton(L"BUTTON", L">",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                230, 23, 30, 30, hWnd, (HMENU) id_btn_start, NULL, NULL);
            EnableWindow(btnStart.GetHWindow(), FALSE);

            // Stop button
            btnStop = UIButton(L"BUTTON", L"0", 
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                275, 23, 30, 30, hWnd, (HMENU) id_btn_stop, NULL, NULL);
            EnableWindow(btnStop.GetHWindow(), FALSE);

            // Open button
            btnOpen = UIButton(L"BUTTON", L"OP", 
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                860, 23, 30, 30, hWnd, (HMENU) id_btn_open, NULL, NULL);

            // Save button
            btnSave = UIButton(L"BUTTON", L"S", 
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                905, 23, 30, 30, hWnd, (HMENU) id_btn_save, NULL, NULL);
            EnableWindow(btnSave.GetHWindow(), FALSE);
                
            // Save as button
            btnSaveAs = UIButton(L"BUTTON", L"SA", 
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                950, 23, 30, 30, hWnd, (HMENU) id_btn_save_as, NULL, NULL);
            EnableWindow(btnSaveAs.GetHWindow(), FALSE);
                
            // Packets listview
            lvPackets = UIListView(WC_LISTVIEW, NULL,
                WS_CHILD | WS_VISIBLE | LVS_REPORT,
                230, 60, 750, 390, hWnd, (HMENU) id_lv_packets, NULL, NULL);
                
            const wchar_t* columnsHeaders[] = { L"No.", L"Time", L"Source IP", L"Destination IP",
                L"Protocol", L"Source Port", L"Destination Port", L"Length", };
            lvPackets.AddColumns(columnsHeaders, 8);
                
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
            
        switch (LOWORD(wParam)) {
        case id_btn_start:
            if (captureManager.GetCurrentCapturer() != nullptr) {
                if (captureManager.GetCurrentCapturer()->IsCapturing()) {
                    break;
                }
            }
            
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

            if (chbIpv4.isChecked() || chbIpv6.isChecked()) filterExp += "(";
            if (chbIpv4.isChecked()) {
                filterExp += "ip"; // IPv4
            }
            if (chbIpv6.isChecked()) {
                if (chbIpv4.isChecked()) filterExp += " or ";
                filterExp += "ip6"; // IPv6
            }
            if (chbIpv4.isChecked() || chbIpv6.isChecked()) filterExp += ")";
            
            if (!edtIpSource.IsEmpty()) {
                if (!filterExp.empty()) filterExp += " and ";
                std::wstring edtText = edtIpSource.GetText();
                std::string edtTextStr(edtText.begin(), edtText.end());
                
                std::regex ipv4Regex("^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$");
                std::regex ipv6Regex("^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$");

                if (std::regex_match(edtTextStr, ipv4Regex) || std::regex_match(edtTextStr, ipv6Regex)) {
                    filterExp += "src host " + edtTextStr;
                } else {
                    MessageBox(hWnd, L"Source IP is invalid. Please enter a valid IPv4 or IPv6 address.", L"Invalid Input", MB_OK | MB_ICONERROR);
                    break;
                }
            }
            
            if (!edtIpDest.IsEmpty()) {
                if (!filterExp.empty()) filterExp += " and ";
                std::wstring edtTextDest = edtIpDest.GetText();
                std::string edtTextDestStr(edtTextDest.begin(), edtTextDest.end());

                std::regex ipv4Regex("^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$");
                std::regex ipv6Regex("^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$");

                if (std::regex_match(edtTextDestStr, ipv4Regex) || std::regex_match(edtTextDestStr, ipv6Regex)) {
                    filterExp += "dst host " + edtTextDestStr;
                } else {
                    MessageBox(hWnd, L"Destination IP is invalid. Please enter a valid IPv4 or IPv6 address.", L"Invalid Input", MB_OK | MB_ICONERROR);
                    break;
                }
            }
            
            if (chbTCP.isChecked() || chbUDP.isChecked()) {
                if (!filterExp.empty()) filterExp += " and ";
                filterExp += "(";
            }
            if (chbTCP.isChecked()) {
                filterExp += "tcp";
            }
            if (chbUDP.isChecked()) {
                if (chbTCP.isChecked())  filterExp += " or ";
                filterExp += "udp";
            }
            if (chbTCP.isChecked() || chbUDP.isChecked()) {
                filterExp += ")";
            }
            
            if (!edtPortSource.IsEmpty()) {
                if (!filterExp.empty()) filterExp += " and ";
                std::wstring edtTextSourcePort = edtPortSource.GetText();
                std::string edtTextSourcePortStr(edtTextSourcePort.begin(), edtTextSourcePort.end());
                
                std::regex portRegex("^([0-9]{1,5})$");
                if (std::regex_match(edtTextSourcePortStr, portRegex)) {
                    int portValue = std::stoi(edtTextSourcePortStr);
                    if (portValue >= 0 && portValue <= 65535) {
                        filterExp += "src port " + edtTextSourcePortStr;
                    } else {
                        MessageBox(hWnd, L"Source port must be between 0 and 65535.", L"Invalid Input", MB_OK | MB_ICONERROR);
                        break;
                    }
                } else {
                    MessageBox(hWnd, L"Source port is invalid. It must be a number between 0 and 65535.", L"Invalid Input", MB_OK | MB_ICONERROR);
                    break;
                }
            }

            if (!edtPortDest.IsEmpty()) {
                if (!filterExp.empty()) filterExp += " and ";
                std::wstring edtTextDestPort = edtPortDest.GetText();
                std::string edtTextDestPortStr(edtTextDestPort.begin(), edtTextDestPort.end());
                
                std::regex portRegex("^([0-9]{1,5})$");
                if (std::regex_match(edtTextDestPortStr, portRegex)) {
                    int portValue = std::stoi(edtTextDestPortStr);
                    if (portValue >= 0 && portValue <= 65535) {
                        filterExp += "dst port " + edtTextDestPortStr;
                    } else {
                        MessageBox(hWnd, L"Destination port must be between 0 and 65535.", L"Invalid Input", MB_OK | MB_ICONERROR);
                        break;
                    }
                } else {
                    MessageBox(hWnd, L"Destination port is invalid. It must be a number between 0 and 65535.", L"Invalid Input", MB_OK | MB_ICONERROR);
                    break;
                }
            }
            
            params->captureManager = &captureManager;
            params->filterExp = filterExp;
        
            hCaptureThread = CreateThread(
                NULL,                   
                0,                      
                CaptureThreadFunction,  
                params,
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
            if (captureManager.GetCurrentCapturer() != nullptr) {
                if (captureManager.GetCurrentCapturer()->IsCapturing()) {
                    break;
                }
            }
            
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
                isCancelled = !fileDialog.OpenFileDialog();

                if (isCancelled) {
                    break;
                }
            
                LoadPackets(packetManager, fileDialog.GetLastPath());

                ListView_DeleteAllItems(lvPackets.GetHWindow());
                PacketParser parser;
                for (int i = 0; i < packetManager.GetPacketsCount(); i++) {
                    Packet* packet = packetManager.GetPacket(i);
                    ParsedPacket parsed = parser.ParsePacket(i, *packet);

                    const wchar_t* columnsValues[8] = {
                        parsed.index.c_str(),
                        parsed.time.c_str(),
                        parsed.srcIp.c_str(),
                        parsed.destIp.c_str(),
                        parsed.protocol.c_str(),
                        parsed.srcPort.c_str(),
                        parsed.destPort.c_str(),
                        parsed.length.c_str(),
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
            if (captureManager.GetCurrentCapturer() != nullptr) {
                if (captureManager.GetCurrentCapturer()->IsCapturing()) {
                    break;
                }
            }
            
            isCancelled = !fileDialog.SaveFileDialog();

            if(isCancelled) {
                break;
            }
        
            SavePackets(packetManager, fileDialog.GetLastPath());
    
            UpdateWindowTitle(hWnd, fileDialog.GetLastPath());

            EnableWindow(btnSave.GetHWindow(), FALSE);
        
            break;
        case id_btn_default_filters:
            chbIpv4.Check();
            chbIpv6.Check();
            chbTCP.Check();
            chbUDP.Check();

            edtIpDest.Clear();
            edtIpSource.Clear();
            edtPortDest.Clear();
            edtPortSource.Clear();
            
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

            const wchar_t* columnsValues[8] = {
                parsed.index.c_str(),
                parsed.time.c_str(),
                parsed.srcIp.c_str(),
                parsed.destIp.c_str(),
                parsed.protocol.c_str(),
                parsed.srcPort.c_str(),
                parsed.destPort.c_str(),
                parsed.length.c_str(),
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
