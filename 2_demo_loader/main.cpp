//x86_64-w64-mingw32-windres resources.rc -O coff -o resources.res
//x86_64-w64-mingw32-g++ -static -std=c++17 -Wall -municode main.cpp resources.res -o EFIInstaller_loader_bitlocker.exe -lshlwapi -lshell32 -lwbemuuid -lole32 -loleaut32
#define _WIN32_DCOM
#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <wbemidl.h>         
#include "resource.h"

#ifdef _MSC_VER
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#endif

static std::wstring to_wstring(const std::string& s) {
    if (s.empty()) return {};
    int len = ::MultiByteToWideChar(CP_UTF8, 0,
                                    s.data(), (int)s.size(),
                                    nullptr, 0);
    std::wstring w;
    w.resize(len);
    ::MultiByteToWideChar(CP_UTF8, 0,
                          s.data(), (int)s.size(),
                          &w[0], len);
    return w;
}


//BitLocker "suspend indefinitely" via WMI

namespace bl {

[[noreturn]] void die(const char* msg, HRESULT hr = GetLastError()) {
    std::cerr << "[BL-ERR] " << msg << " (0x" << std::hex << hr << ")\n";
    std::exit(EXIT_FAILURE);
}
inline void chk(HRESULT hr, const char* where) { if (FAILED(hr)) die(where, hr); }

struct ComInit {
    ComInit()  { chk(CoInitializeEx(nullptr, COINIT_MULTITHREADED), "CoInit"); }
    ~ComInit() { CoUninitialize(); }
};

class Wmi {
    IWbemServices* svc = nullptr;
public:
    Wmi() {
        chk(CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                                 RPC_C_AUTHN_LEVEL_DEFAULT,
                                 RPC_C_IMP_LEVEL_IMPERSONATE,
                                 nullptr, EOAC_NONE, nullptr),
            "CoInitializeSecurity");

        IWbemLocator* loc = nullptr;
        chk(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                             IID_IWbemLocator, (void**)&loc),
            "CoCreateInstance");

        BSTR ns = SysAllocString(L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption");
        chk(loc->ConnectServer(ns, nullptr, nullptr, nullptr,
                               0, nullptr, nullptr, &svc),
            "ConnectServer");
        SysFreeString(ns);
        loc->Release();

        chk(CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                              RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                              nullptr, EOAC_NONE),
            "CoSetProxyBlanket");
    }
    ~Wmi() { if (svc) svc->Release(); }
    IWbemServices* operator->() const { return svc; }
    operator IWbemServices*()  const { return svc; }
};

// locate Win32_EncryptableVolume for drive C:
static IWbemClassObject* volume_for_drive(IWbemServices* svc, const wchar_t* drive) {
    IEnumWbemClassObject* en = nullptr;
    chk(svc->CreateInstanceEnum(SysAllocString(L"Win32_EncryptableVolume"),
                                WBEM_FLAG_FORWARD_ONLY, nullptr, &en),
        "CreateInstanceEnum");
    IWbemClassObject* obj = nullptr; ULONG got = 0;
    while (en->Next(WBEM_INFINITE, 1, &obj, &got) == S_OK && got == 1) {
        VARIANT v; VariantInit(&v);
        if (SUCCEEDED(obj->Get(L"DriveLetter", 0, &v, nullptr, nullptr)) &&
            v.vt == VT_BSTR && v.bstrVal &&
            _wcsicmp(v.bstrVal, drive) == 0) {
            VariantClear(&v); en->Release(); return obj;      // caller releases
        }
        VariantClear(&v); obj->Release(); obj = nullptr;
    }
    en->Release();
    die("Drive not found", 0x36B7);
    return nullptr;
}

// suspend indefinitely (DisableCount = 0)
static void suspend_indefinitely(const wchar_t* drive = L"C:") {
    ComInit ci; Wmi wmi;

    IWbemClassObject* vol = volume_for_drive(wmi, drive);

    VARIANT instPath; VariantInit(&instPath);
    chk(vol->Get(L"__PATH", 0, &instPath, nullptr, nullptr), "Get(__PATH)");

    // build input params with DisableCount = 0
    IWbemClassObject *inSig = nullptr, *inParams = nullptr;
    IWbemClassObject* cls = nullptr;
    chk(wmi->GetObject(SysAllocString(L"Win32_EncryptableVolume"),
                       0, nullptr, &cls, nullptr),
        "GetObject(class)");
    chk(cls->GetMethod(L"DisableKeyProtectors", 0, &inSig, nullptr),
        "GetMethod");
    chk(inSig->SpawnInstance(0, &inParams), "SpawnInstance");
    VARIANT dc; VariantInit(&dc); dc.vt = VT_I4; dc.uintVal = 0;
    chk(inParams->Put(L"DisableCount", 0, &dc, 0), "Put(DisableCount)");
    VariantClear(&dc); inSig->Release(); cls->Release();

    IWbemClassObject* out = nullptr;
    chk(wmi->ExecMethod(instPath.bstrVal, SysAllocString(L"DisableKeyProtectors"),
                        0, nullptr, inParams, &out, nullptr),
        "ExecMethod");
    inParams->Release();

    VARIANT rv; VariantInit(&rv);
    chk(out->Get(L"ReturnValue", 0, &rv, nullptr, nullptr), "Get(ReturnValue)");
    out->Release(); vol->Release(); VariantClear(&instPath);

    if (rv.vt == VT_I4 && rv.uintVal == 0)
        std::wcout << L"[BL] BitLocker on " << drive << L" suspended indefinitely.\n";
    else
        die("DisableKeyProtectors failed", rv.uintVal);

    VariantClear(&rv);
}

} // namespace bl

std::wstring FindFreeDriveLetter() {
    DWORD drives = GetLogicalDrives();
    for (wchar_t letter = L'S'; letter >= L'S'; --letter) {
        if (!(drives & (1 << (letter - L'A')))) {
            return std::wstring(1, letter) + L":";
        }
    }
    return L"";
}

bool RunCommand(const std::wstring& cmd) {
    std::wcout << L"[CMD] " << cmd << std::endl;

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (!CreateProcessW(NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        std::wcerr << L"[ERROR] Failed to execute: " << cmd << std::endl;
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return exitCode == 0;
}

bool ExtractResourceToFile(WORD resourceID, const std::wstring& outPath) {
    std::wcout << L"[INFO] Extracting to: " << outPath << std::endl;

    HRSRC hRes = FindResourceW(NULL, MAKEINTRESOURCEW(resourceID), RT_RCDATA);
    if (!hRes) {
        std::wcerr << L"[ERROR] Resource not found (ID " << resourceID << L")" << std::endl;
        return false;
    }

    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) {
        std::wcerr << L"[ERROR] Resource load failed (ID " << resourceID << L")" << std::endl;
        return false;
    }

    DWORD size = SizeofResource(NULL, hRes);
    void* data = LockResource(hData);
    if (!data) {
        std::wcerr << L"[ERROR] Resource lock failed (ID " << resourceID << L")" << std::endl;
        return false;
    }

    size_t pos = outPath.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        std::wstring dir = outPath.substr(0, pos);
        if (SHCreateDirectoryExW(NULL, dir.c_str(), NULL) != ERROR_SUCCESS &&
            GetLastError() != ERROR_ALREADY_EXISTS) {
            DWORD err = GetLastError();
            std::wcerr << L"[ERROR] Could not create directory: " << dir
                       << L" (WinError: " << err << L")" << std::endl;
            return false;
        }
    }

    HANDLE hFile = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        std::wcerr << L"[ERROR] Failed to create file: " << outPath
                   << L" (WinError: " << err << L")" << std::endl;
        return false;
    }

    DWORD written;
    BOOL success = WriteFile(hFile, data, size, &written, NULL);
    CloseHandle(hFile);

    if (!success || written != size) {
        std::wcerr << L"[ERROR] Failed to write file: " << outPath
                   << L" (written: " << written << L", expected: " << size << L")"
                   << std::endl;
        return false;
    }

    return true;
}

int wmain() {
    std::wcout << L"==== EFI Resource Installer ====" << std::endl;
    // 1. suspend BitLocker indefinitely (C: is assumed to be OS volume). If you later want to resume protection manually: manage-bde -protectors -enable C:
    bl::suspend_indefinitely(L"C:");
    // Pick an unused drive letter and mount the real EFI System Partition
    std::wstring mountLetter = FindFreeDriveLetter();
    if (mountLetter.empty()) {
        std::wcerr << L"[ERROR] No free drive letter available." << std::endl;
        return 1;
    }
    std::wcout << L"[INFO] Mounting EFI System Partition as " << mountLetter << std::endl;
    if (!RunCommand(L"mountvol " + mountLetter + L" /s")) {
        std::wcerr << L"[ERROR] mountvol /s failed." << std::endl;
        return 1;
    }

    // Backup existing .efi -> .dat in two folders
    auto backupEFI = [&](const std::wstring& folder, const std::wstring& stem) {
        std::wstring src = folder + L"\\" + stem + L".efi";
        std::wstring dst = folder + L"\\" + stem + L".dat";
        std::error_code ec;
        if (std::filesystem::exists(src)) {
            std::filesystem::rename(src, dst, ec);
            if (ec) {
                std::wstring msg = to_wstring(ec.message());
                std::wcerr << L"[ERROR] Failed to backup " << src
                           << L" -> " << dst << L": " << msg << std::endl;
            } else {
                std::wcout << L"[OK] Backed up " << src
                           << L" -> " << dst << std::endl;
            }
        } else {
            std::wcerr << L"[WARN] " << src << L" not found; skipping backup." << std::endl;
        }
    };

    std::wstring msBootDir  = mountLetter + L"\\efi\\microsoft\\boot";
    std::wstring stdBootDir = mountLetter + L"\\efi\\boot";
    //only when not handled by installer
    backupEFI(msBootDir,  L"bootmgfw");
    backupEFI(stdBootDir, L"bootx64");

    // Extract our resources into place
    std::vector<std::pair<WORD, std::wstring>> files = {
        { IDR_SHDLDR_EFI,     msBootDir  + L"\\bootmgfw.efi"    }, // shdloader.efi from RebootRestoreRxPro128-2710270703
        { IDR_SHDLDR_EFI,     stdBootDir + L"\\bootx64.efi"     }, // shdloader.efi from RebootRestoreRxPro128-2710270703
        { IDR_SHELL_EF_,     stdBootDir + L"\\shdmgr.ef_"     }, // shell.ef_ from RebootRestoreRxPro128-2710270703. Propietary .efi compressed file, uefishell with limited commands.
        { IDR_KNO_STAGE0_EFI, stdBootDir + L"\\stage0.efi"  }, // knoppix signed .efi, this try to load loader.efi, if is not signed, lauchn hashtool to add to MOK.
        { IDR_KNO_HASHTOOL_EFI,     stdBootDir + L"\\hashtool.efi"      }, // add selected EFI to MOK 
        { IDR_KNO_LOADER_EFI,   stdBootDir + L"\\loader.efi"     },  // we place full equip uefishell as loader.efi
        { IDR_ASCIIART_EFI,   stdBootDir + L"\\asciiart.efi"     }
    };

    for (auto const& [resId, path] : files) {
        if (!ExtractResourceToFile(resId, path)) {
            std::wcerr << L"[ERROR] Failed to extract: " << path << std::endl;
        } else {
            std::wcout << L"[OK] Copied: " << path << std::endl;
        }
    }

    std::wcout << L"[INFO] Unmounting EFI volume (" << mountLetter << L")" << std::endl;
    RunCommand(L"mountvol " + mountLetter + L" /D");

    std::wcout << L"==== Done ====" << std::endl;
    return 0;
}

