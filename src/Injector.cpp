#include "Injector.h"
#include "ProcessUtils.h"
#include <iostream>
#include <fstream>
#include <algorithm>

InjectionResult Injector::InjectDLL(DWORD processId, const std::wstring& dllPath, InjectionMethod method) {
    // Validate DLL file
    if (!IsValidDLL(dllPath)) {
        return InjectionResult::DllNotFound;
    }
    
    // Check if process is running
    if (!ProcessUtils::IsProcessRunning(processId)) {
        return InjectionResult::ProcessNotFound;
    }
    
    // Open process with required privileges
    HANDLE hProcess = ProcessUtils::OpenProcessWithPrivileges(processId);
    if (!hProcess) {
        return InjectionResult::ProcessAccessDenied;
    }
    
    // Check architecture compatibility
    if (!IsArchitectureCompatible(hProcess, dllPath)) {
        CloseHandle(hProcess);
        return InjectionResult::ArchitectureMismatch;
    }
    
    InjectionResult result = InjectionResult::UnknownError;
    
    switch (method) {
        case InjectionMethod::LoadLibrary:
            CloseHandle(hProcess);
            result = InjectUsingLoadLibrary(processId, dllPath);
            return result;
        case InjectionMethod::CreateRemoteThread:
            result = InjectUsingCreateRemoteThread(hProcess, dllPath);
            break;
        case InjectionMethod::ManualMap:
            result = InjectUsingManualMap(hProcess, dllPath);
            break;
        case InjectionMethod::SetWindowsHook:
            CloseHandle(hProcess);
            result = InjectUsingSetWindowsHook(processId, dllPath);
            return result;
    }
    
    CloseHandle(hProcess);
    return result;
}

InjectionResult Injector::InjectUsingCreateRemoteThread(HANDLE hProcess, const std::wstring& dllPath) {
    try {
        // Get process ID from handle
        DWORD processId = GetProcessId(hProcess);
        if (processId == 0) {
            return InjectionResult::ProcessNotFound;
        }
        
        // Get process using libmem
        auto process = libmem::GetProcess(static_cast<libmem::Pid>(processId));
        if (!process.has_value()) {
            return InjectionResult::ProcessAccessDenied;
        }
        
        // Find kernel32 module to get LoadLibraryW address
        auto kernel32 = libmem::FindModule(&process.value(), "kernel32.dll");
        if (!kernel32.has_value()) {
            return InjectionResult::InjectionFailed;
        }
        
        // Get LoadLibraryW address
        auto loadLibraryAddr = libmem::FindSymbolAddress(&kernel32.value(), "LoadLibraryW");
        if (!loadLibraryAddr.has_value()) {
            return InjectionResult::InjectionFailed;
        }
        
        // Use wide string for Windows API compatibility
        size_t dllPathSize = (dllPath.length() + 1) * sizeof(wchar_t);
        auto remoteMemory = libmem::AllocMemory(&process.value(), dllPathSize, libmem::Prot::RW);
        if (!remoteMemory.has_value()) {
            return InjectionResult::InjectionFailed;
        }
        
        // Write DLL path to target process using libmem
        size_t bytesWritten = libmem::WriteMemory(&process.value(), remoteMemory.value(), 
            reinterpret_cast<uint8_t*>(const_cast<wchar_t*>(dllPath.c_str())), dllPathSize);
        
        if (bytesWritten != dllPathSize) {
            libmem::FreeMemory(&process.value(), remoteMemory.value(), dllPathSize);
            return InjectionResult::InjectionFailed;
        }
        
        // Create remote thread using Windows API (libmem doesn't provide thread creation)
        HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, 
            (LPTHREAD_START_ROUTINE)static_cast<uintptr_t>(loadLibraryAddr.value()), 
            reinterpret_cast<LPVOID>(static_cast<uintptr_t>(remoteMemory.value())), 0, NULL);
        
        if (!hRemoteThread) {
            libmem::FreeMemory(&process.value(), remoteMemory.value(), dllPathSize);
            return InjectionResult::InjectionFailed;
        }
        
        // Wait for thread completion
        WaitForSingleObject(hRemoteThread, INFINITE);
        
        // Get thread exit code (HMODULE of loaded DLL)
        DWORD exitCode;
        GetExitCodeThread(hRemoteThread, &exitCode);
        
        CloseHandle(hRemoteThread);
        libmem::FreeMemory(&process.value(), remoteMemory.value(), dllPathSize);
        
        return (exitCode != 0) ? InjectionResult::Success : InjectionResult::InjectionFailed;
    }
    catch (const std::exception&) {
        return InjectionResult::InjectionFailed;
    }
}

InjectionResult Injector::InjectUsingManualMap(HANDLE hProcess, const std::wstring& dllPath) {
    try {
        // Get process ID from handle
        DWORD processId = GetProcessId(hProcess);
        if (processId == 0) {
            return InjectionResult::ProcessNotFound;
        }
        
        // Get process using libmem
        auto process = libmem::GetProcess(static_cast<libmem::Pid>(processId));
        if (!process.has_value()) {
            return InjectionResult::ProcessAccessDenied;
        }
        
        // Read DLL file
        std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            return InjectionResult::DllNotFound;
        }
        
        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        
        std::vector<BYTE> dllData(fileSize);
        file.read(reinterpret_cast<char*>(dllData.data()), fileSize);
        file.close();
        
        // Validate PE headers
        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dllData.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return InjectionResult::DllInvalid;
        }
        
        PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(dllData.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return InjectionResult::DllInvalid;
        }
        
        // Allocate memory in target process using libmem
        auto remoteImage = libmem::AllocMemory(&process.value(), ntHeaders->OptionalHeader.SizeOfImage, 
            libmem::Prot::XRW);
        
        if (!remoteImage.has_value()) {
            return InjectionResult::InjectionFailed;
        }
        
        // Copy headers using libmem
        size_t headersBytesWritten = libmem::WriteMemory(&process.value(), remoteImage.value(), 
            dllData.data(), ntHeaders->OptionalHeader.SizeOfHeaders);
        
        if (headersBytesWritten != ntHeaders->OptionalHeader.SizeOfHeaders) {
            libmem::FreeMemory(&process.value(), remoteImage.value(), ntHeaders->OptionalHeader.SizeOfImage);
            return InjectionResult::InjectionFailed;
        }
        
        // Copy sections using libmem
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (sectionHeader[i].SizeOfRawData > 0) {
                libmem::Address sectionDest = remoteImage.value() + sectionHeader[i].VirtualAddress;
                uint8_t* pSectionSrc = dllData.data() + sectionHeader[i].PointerToRawData;
                
                size_t sectionBytesWritten = libmem::WriteMemory(&process.value(), sectionDest, 
                    pSectionSrc, sectionHeader[i].SizeOfRawData);
                
                if (sectionBytesWritten != sectionHeader[i].SizeOfRawData) {
                    libmem::FreeMemory(&process.value(), remoteImage.value(), ntHeaders->OptionalHeader.SizeOfImage);
                    return InjectionResult::InjectionFailed;
                }
            }
        }
        
        // Perform relocations and resolve imports
        // (Simplified implementation - full manual mapping requires more complex relocation and import resolution)
        
        // Call DLL entry point
        libmem::Address entryPoint = remoteImage.value() + ntHeaders->OptionalHeader.AddressOfEntryPoint;
        HANDLE hRemoteThread = CreateRemoteThread(hProcess, nullptr, 0, 
            reinterpret_cast<LPTHREAD_START_ROUTINE>(static_cast<uintptr_t>(entryPoint)), 
            reinterpret_cast<LPVOID>(static_cast<uintptr_t>(remoteImage.value())), 0, nullptr);
        
        if (hRemoteThread) {
            WaitForSingleObject(hRemoteThread, INFINITE);
            CloseHandle(hRemoteThread);
            return InjectionResult::Success;
        }
        libmem::FreeMemory(&process.value(), remoteImage.value(), ntHeaders->OptionalHeader.SizeOfImage);
        return InjectionResult::InjectionFailed;
    }
    catch (const std::exception&) {
        return InjectionResult::InjectionFailed;
    }
}

InjectionResult Injector::InjectUsingSetWindowsHook(DWORD processId, const std::wstring& dllPath) {
    try {
        // Get process using libmem
        auto process = libmem::GetProcess(static_cast<libmem::Pid>(processId));
        if (!process.has_value()) {
            return InjectionResult::ProcessAccessDenied;
        }
        
        // Load DLL in current process first
        HMODULE hDll = LoadLibraryW(dllPath.c_str());
        if (!hDll) {
            return InjectionResult::DllNotFound;
        }
        
        // Get a function from the DLL (assuming it exports a hook procedure)
        HOOKPROC hookProc = (HOOKPROC)GetProcAddress(hDll, "HookProc");
        if (!hookProc) {
            FreeLibrary(hDll);
            return InjectionResult::DllInvalid;
        }
        
        // Get thread ID of target process using libmem
        DWORD threadId = 0;
        auto threads = libmem::EnumThreads(&process.value());
        if (threads.has_value() && !threads.value().empty()) {
            // Use the first thread found
            threadId = static_cast<DWORD>(threads.value()[0].tid);
        }
        
        // Fallback to traditional method if libmem fails
        if (threadId == 0) {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                THREADENTRY32 te32;
                te32.dwSize = sizeof(THREADENTRY32);
                
                if (Thread32First(hSnapshot, &te32)) {
                    do {
                        if (te32.th32OwnerProcessID == processId) {
                            threadId = te32.th32ThreadID;
                            break;
                        }
                    } while (Thread32Next(hSnapshot, &te32));
                }
                CloseHandle(hSnapshot);
            }
        }
        
        if (threadId == 0) {
            FreeLibrary(hDll);
            return InjectionResult::ProcessNotFound;
        }
        
        // Install hook
        HHOOK hHook = SetWindowsHookExW(WH_GETMESSAGE, hookProc, hDll, threadId);
        if (!hHook) {
            FreeLibrary(hDll);
            return InjectionResult::InjectionFailed;
        }
        
        // Trigger the hook by posting a message
        PostThreadMessageW(threadId, WM_NULL, 0, 0);
        
        // Clean up (in a real scenario, you might want to keep the hook active)
        Sleep(1000);
        UnhookWindowsHookEx(hHook);
        FreeLibrary(hDll);
        
        return InjectionResult::Success;
    }
    catch (const std::exception&) {
        return InjectionResult::InjectionFailed;
    }
}

bool Injector::IsValidDLL(const std::wstring& dllPath) {
    std::ifstream file(dllPath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    
    file.seekg(dosHeader.e_lfanew);
    IMAGE_NT_HEADERS ntHeaders;
    file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(ntHeaders));
    
    return ntHeaders.Signature == IMAGE_NT_SIGNATURE && 
           (ntHeaders.FileHeader.Characteristics & IMAGE_FILE_DLL);
}

bool Injector::IsArchitectureCompatible(HANDLE hProcess, const std::wstring& dllPath) {
    // Check if target process is 64-bit
    BOOL isWow64Process = FALSE;
    IsWow64Process(hProcess, &isWow64Process);
    bool targetIs64Bit = !isWow64Process;
    
    // Check DLL architecture
    std::ifstream file(dllPath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    
    file.seekg(dosHeader.e_lfanew);
    IMAGE_NT_HEADERS ntHeaders;
    file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(ntHeaders));
    
    bool dllIs64Bit = (ntHeaders.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
    
    return targetIs64Bit == dllIs64Bit;
}

std::wstring Injector::GetErrorMessage(InjectionResult result) {
    switch (result) {
        case InjectionResult::Success:
            return L"Injection successful";
        case InjectionResult::ProcessNotFound:
            return L"Target process not found or not running";
        case InjectionResult::ProcessAccessDenied:
            return L"Access denied to target process. Try running as administrator.";
        case InjectionResult::DllNotFound:
            return L"DLL file not found or cannot be read";
        case InjectionResult::DllInvalid:
            return L"Invalid DLL file or not a valid PE file";
        case InjectionResult::ArchitectureMismatch:
            return L"Architecture mismatch between process and DLL (x86/x64)";
        case InjectionResult::InjectionFailed:
            return L"Injection failed. The target process may have protection.";
        default:
            return L"Unknown error occurred";
    }
}

InjectionResult Injector::InjectUsingLoadLibrary(DWORD processId, const std::wstring& dllPath) {
    // Validate DLL file
    if (!IsValidDLL(dllPath)) {
        return InjectionResult::DllNotFound;
    }
    
    // Check if process is running
    if (!ProcessUtils::IsProcessRunning(processId)) {
        return InjectionResult::ProcessNotFound;
    }
    
    try {
        // Use libmem for LoadLibrary injection
        auto process = libmem::GetProcess(static_cast<libmem::Pid>(processId));
        if (!process.has_value()) {
            return InjectionResult::ProcessAccessDenied;
        }
        
        // Convert wide string to UTF-8 string properly for libmem
        std::string dllPathStr;
        int size = WideCharToMultiByte(CP_UTF8, 0, dllPath.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (size > 1) {
            dllPathStr.resize(size - 1); // size includes null terminator
            WideCharToMultiByte(CP_UTF8, 0, dllPath.c_str(), -1, &dllPathStr[0], size, nullptr, nullptr);
        } else {
            return InjectionResult::DllNotFound;
        }
        
        // Inject using libmem's LoadModule method
        auto module = libmem::LoadModule(&process.value(), dllPathStr.c_str());
        if (module.has_value()) {
            return InjectionResult::Success;
        } else {
            return InjectionResult::InjectionFailed;
        }
    }
    catch (const std::exception&) {
        return InjectionResult::InjectionFailed;
    }
}