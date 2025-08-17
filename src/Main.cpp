#include <iostream>
#include <string>
#include <vector>
#include "Injector.h"
#include "ProcessUtils.h"

int main(int argc, char* argv[])
{
    std::wcout << L"G25F DLL Injector v1.0 - Console Edition" << std::endl;
    std::wcout << L"=========================================" << std::endl;
    
    // Enable debug privileges for the current process
    if (!ProcessUtils::EnableDebugPrivilege()) {
        std::wcout << L"Warning: Failed to enable debug privilege. Some injections may fail." << std::endl;
    }
    
    if (argc == 4) {
        // Command line mode: injector.exe <process_name> <dll_path> <method>
        std::wstring processName(argv[1], argv[1] + strlen(argv[1]));
        std::wstring dllPath(argv[2], argv[2] + strlen(argv[2]));
        std::string method = argv[3];
        
        // Find process by name
        auto processes = ProcessUtils::GetProcessList();
        DWORD processId = 0;
        
        for (const auto& proc : processes) {
            if (proc.processName.find(processName) != std::wstring::npos) {
                processId = proc.processId;
                break;
            }
        }
        
        if (processId == 0) {
            std::wcout << L"Error: Process '" << processName << L"' not found." << std::endl;
            return 1;
        }
        
        // Open process handle
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!hProcess) {
            std::wcout << L"Error: Failed to open process. Error code: " << GetLastError() << std::endl;
            return 1;
        }
        
        // Perform injection
        InjectionResult result = InjectionResult::InjectionFailed;
        InjectionMethod injectionMethod;
        
        if (method == "loadlibrary") {
            injectionMethod = InjectionMethod::LoadLibrary;
        } else if (method == "createremotethread") {
            injectionMethod = InjectionMethod::CreateRemoteThread;
        } else if (method == "manualmap") {
            injectionMethod = InjectionMethod::ManualMap;
        } else if (method == "setwindowshook") {
            injectionMethod = InjectionMethod::SetWindowsHook;
        } else {
            std::wcout << L"Error: Invalid injection method. Use: loadlibrary, createremotethread, manualmap, or setwindowshook" << std::endl;
            CloseHandle(hProcess);
            return 1;
        }
        
        result = Injector::InjectDLL(processId, dllPath, injectionMethod);
        
        CloseHandle(hProcess);
        
        if (result == InjectionResult::Success) {
            std::wcout << L"Injection successful!" << std::endl;
            return 0;
        } else {
            std::wcout << L"Injection failed. Result code: " << static_cast<int>(result) << std::endl;
            return 1;
        }
    } else {
        // Interactive mode
        std::wcout << L"Usage: " << argv[0] << L" <process_name> <dll_path> <method>" << std::endl;
        std::wcout << L"Methods: loadlibrary (recommended), createremotethread, manualmap, setwindowshook" << std::endl;
        std::wcout << L"Example: " << argv[0] << L" notepad.exe C:\\path\\to\\dll.dll loadlibrary" << std::endl;
        return 0;
    }
}