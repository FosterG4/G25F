#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>

struct ProcessInfo {
    DWORD processId;
    std::wstring processName;
    std::wstring windowTitle;
    bool is64Bit;
};

class ProcessUtils {
public:
    static std::vector<ProcessInfo> GetProcessList();
    static DWORD GetProcessIdByName(const std::wstring& processName);
    static std::wstring GetProcessName(DWORD processId);
    static bool IsProcess64Bit(DWORD processId);
    static bool IsProcessRunning(DWORD processId);
    static HANDLE OpenProcessWithPrivileges(DWORD processId);
    static bool EnableDebugPrivilege();
    
private:
    static std::wstring GetWindowTitle(DWORD processId);
};