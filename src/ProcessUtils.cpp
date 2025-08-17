#include "ProcessUtils.h"
#include <iostream>
#include <algorithm>

std::vector<ProcessInfo> ProcessUtils::GetProcessList() {
    std::vector<ProcessInfo> processes;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return processes;
    }
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            ProcessInfo info;
            info.processId = pe32.th32ProcessID;
            info.processName = pe32.szExeFile;
            info.windowTitle = GetWindowTitle(pe32.th32ProcessID);
            info.is64Bit = IsProcess64Bit(pe32.th32ProcessID);
            
            // Skip system processes and current process
            if (pe32.th32ProcessID > 4 && pe32.th32ProcessID != GetCurrentProcessId()) {
                processes.push_back(info);
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    
    // Sort by process name
    std::sort(processes.begin(), processes.end(), 
        [](const ProcessInfo& a, const ProcessInfo& b) {
            return a.processName < b.processName;
        });
    
    return processes;
}

DWORD ProcessUtils::GetProcessIdByName(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return 0;
}

std::wstring ProcessUtils::GetProcessName(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) {
        return L"";
    }
    
    wchar_t processName[MAX_PATH];
    DWORD size = MAX_PATH;
    
    if (QueryFullProcessImageNameW(hProcess, 0, processName, &size)) {
        CloseHandle(hProcess);
        std::wstring fullPath(processName);
        size_t lastSlash = fullPath.find_last_of(L"\\");
        if (lastSlash != std::wstring::npos) {
            return fullPath.substr(lastSlash + 1);
        }
        return fullPath;
    }
    
    CloseHandle(hProcess);
    return L"";
}

bool ProcessUtils::IsProcess64Bit(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess) {
        return false;
    }
    
    BOOL isWow64 = FALSE;
    if (IsWow64Process(hProcess, &isWow64)) {
        CloseHandle(hProcess);
        
        // If we're on 64-bit Windows
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
            si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) {
            return !isWow64; // 64-bit process if not running under WOW64
        }
    }
    
    CloseHandle(hProcess);
    return false;
}

bool ProcessUtils::IsProcessRunning(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess) {
        return false;
    }
    
    DWORD exitCode;
    bool isRunning = GetExitCodeProcess(hProcess, &exitCode) && exitCode == STILL_ACTIVE;
    CloseHandle(hProcess);
    return isRunning;
}

HANDLE ProcessUtils::OpenProcessWithPrivileges(DWORD processId) {
    EnableDebugPrivilege();
    
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, processId);
    
    return hProcess;
}

bool ProcessUtils::EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    bool result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);
    
    return result && GetLastError() == ERROR_SUCCESS;
}

std::wstring ProcessUtils::GetWindowTitle(DWORD processId) {
    struct EnumData {
        DWORD targetProcessId;
        std::wstring title;
    };
    
    EnumData data = { processId, L"" };
    
    // Enumerate windows to find the main window of this process
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        EnumData* pData = reinterpret_cast<EnumData*>(lParam);
        DWORD windowProcessId;
        GetWindowThreadProcessId(hwnd, &windowProcessId);
        
        if (windowProcessId == pData->targetProcessId) {
            if (IsWindowVisible(hwnd) && GetWindow(hwnd, GW_OWNER) == NULL) {
                wchar_t windowTitle[256];
                if (GetWindowTextW(hwnd, windowTitle, sizeof(windowTitle) / sizeof(wchar_t))) {
                    if (wcslen(windowTitle) > 0) {
                        pData->title = windowTitle;
                        return FALSE; // Stop enumeration
                    }
                }
            }
        }
        return TRUE; // Continue enumeration
    }, reinterpret_cast<LPARAM>(&data));
    
    return data.title;
}