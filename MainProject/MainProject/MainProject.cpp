#include <iostream>
#include <pcap.h>

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
    
    hWnd = CreateWindow(L"NetTrafficAnalyzer", L"Net Traffic Analyzer",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0,
        CW_USEDEFAULT, 0, NULL, NULL, hInst, NULL);

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}

void NPCAPTEST() {
    pcap_if_t *alldevs;
    pcap_if_t *device;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Получение списка всех устройств
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Ошибка при получении списка устройств: " << errbuf << '\n';
    }
    
    // Используем первое устройство (можно выбрать вручную)
    device = alldevs->next->next->next;
    
    // Открываем устройство для захвата трафика
    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Ошибка при открытии устройства: " << errbuf << '\n';
    }
    
    std::cout << "Захват трафика с устройства: " << device->name << '\n';
    
    // Захват одного пакета
    pcap_pkthdr *header;
    const u_char *packet;
    
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 1) {
        std::cout << "Пакет длиной: " << header->len << " байт" << '\n';
    } else if (res == -1) {
        std::cerr << "Ошибка при захвате пакета: " << pcap_geterr(handle) << '\n';
    }
    
    // Освобождаем ресурсы
    pcap_close(handle);
    pcap_freealldevs(alldevs);
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);

            POINT ltPoint = {50, 50};
            POINT rtPoint = {100, 50};
            POINT rbPoint = {100, 100};
            POINT lbPoint = {50, 100};
            
            POINT points[4] = {
                ltPoint,
                rtPoint,
                rbPoint,
                lbPoint
            };

            Polygon(hdc, points, 4);
                
            RECT rect;
            GetClientRect(hWnd, &rect);

            NPCAPTEST();

            EndPaint(hWnd, &ps);
            break;
        }
        
        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
    }

    return 0;
}
