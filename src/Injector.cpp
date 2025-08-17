#include "Injector.h"
#include "ProcessUtils.h"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <ctime>
#include <cstdlib>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "libmem/libmem.hpp"

// Windows NT API declarations
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#ifndef SECTION_ALL_ACCESS
#define SECTION_ALL_ACCESS 0x10000000
#endif

#ifndef SEC_COMMIT
#define SEC_COMMIT 0x8000000
#endif

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
        case InjectionMethod::APCInjection:
            {
                StealthOptions defaultStealth = {};
                result = InjectUsingAPC(hProcess, dllPath, defaultStealth);
            }
            break;
        case InjectionMethod::ThreadHijacking:
            {
                StealthOptions defaultStealth = {};
                result = InjectUsingThreadHijacking(hProcess, dllPath, defaultStealth);
            }
            break;
        case InjectionMethod::VEHInjection:
            {
                StealthOptions defaultStealth = {};
                result = InjectUsingVEH(hProcess, dllPath, defaultStealth);
            }
            break;
        case InjectionMethod::SectionMapping:
            {
                StealthOptions defaultStealth = {};
                result = InjectUsingSectionMapping(hProcess, dllPath, defaultStealth);
            }
            break;
        default:
            result = InjectionResult::UnknownError;
            break;
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

// Enhanced injection with stealth options
InjectionResult Injector::InjectWithStealth(DWORD processId, const std::wstring& dllPath, 
                                          InjectionMethod method, const StealthOptions& stealth) {
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
    
    // Add initial injection delay if specified
    if (stealth.injectionDelay > 0) {
        AddRandomDelay(stealth.injectionDelay, stealth.useRandomDelays ? 1000 : 0);
    }
    
    InjectionResult result = InjectionResult::UnknownError;
    
    switch (method) {
        case InjectionMethod::LoadLibrary:
            CloseHandle(hProcess);
            result = InjectUsingLoadLibrary(processId, dllPath);
            break;
        case InjectionMethod::CreateRemoteThread:
            result = InjectUsingCreateRemoteThread(hProcess, dllPath);
            break;
        case InjectionMethod::ManualMap:
            result = InjectUsingManualMap(hProcess, dllPath);
            break;
        case InjectionMethod::SetWindowsHook:
            CloseHandle(hProcess);
            result = InjectUsingSetWindowsHook(processId, dllPath);
            break;
        case InjectionMethod::APCInjection:
            result = InjectUsingAPC(hProcess, dllPath, stealth);
            break;
        case InjectionMethod::ThreadHijacking:
            result = InjectUsingThreadHijacking(hProcess, dllPath, stealth);
            break;
        case InjectionMethod::VEHInjection:
            result = InjectUsingVEH(hProcess, dllPath, stealth);
            break;
        case InjectionMethod::SectionMapping:
            result = InjectUsingSectionMapping(hProcess, dllPath, stealth);
            break;
        default:
            result = InjectionResult::UnknownError;
            break;
    }
    
    CloseHandle(hProcess);
    return result;
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
        
        return InjectionResult::InjectionFailed;
    }
    catch (const std::exception& e) {
        return InjectionResult::InjectionFailed;
    }
}

// Advanced Injection Methods Implementation

// APC (Asynchronous Procedure Call) Injection
InjectionResult Injector::InjectUsingAPC(HANDLE hProcess, const std::wstring& dllPath, const StealthOptions& stealth) {
    try {
        // Get process ID from handle
        DWORD processId = GetProcessId(hProcess);
        if (processId == 0) {
            return InjectionResult::ProcessNotFound;
        }
        
        // Allocate memory for DLL path in target process
        size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
        LPVOID remotePath = VirtualAllocEx(hProcess, nullptr, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remotePath) {
            return InjectionResult::MemoryProtectionFailed;
        }
        
        // Write DLL path to target process
        if (!WriteProcessMemory(hProcess, remotePath, dllPath.c_str(), pathSize, nullptr)) {
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return InjectionResult::InjectionFailed;
        }
        
        // Get LoadLibraryW address
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel32) {
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return InjectionResult::InjectionFailed;
        }
        
        LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
        if (!loadLibraryAddr) {
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return InjectionResult::InjectionFailed;
        }
        
        // Enumerate threads in target process
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return InjectionResult::ThreadCreationFailed;
        }
        
        THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
        bool injected = false;
        
        if (Thread32First(hSnapshot, &te32)) {
            do {
                if (te32.th32OwnerProcessID == processId) {
                    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
                    if (hThread) {
                        // Queue APC to thread
                        if (QueueUserAPC((PAPCFUNC)loadLibraryAddr, hThread, (ULONG_PTR)remotePath)) {
                            injected = true;
                            CloseHandle(hThread);
                            break;
                        }
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hSnapshot, &te32));
        }
        
        CloseHandle(hSnapshot);
        
        if (!injected) {
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return InjectionResult::ThreadCreationFailed;
        }
        
        // Apply stealth techniques if requested
        if (stealth.dllDelay > 0) {
            AddRandomDelay(stealth.dllDelay, stealth.useRandomDelays ? 500 : 0);
        }
        
        return InjectionResult::Success;
        
    } catch (const std::exception&) {
        return InjectionResult::InjectionFailed;
    }
}

// VEH (Vectored Exception Handler) Injection
InjectionResult Injector::InjectUsingVEH(HANDLE hProcess, const std::wstring& dllPath, const StealthOptions& stealth) {
    try {
        DWORD processId = GetProcessId(hProcess);
        if (processId == 0) {
            return InjectionResult::ProcessNotFound;
        }
        
        // Allocate memory for DLL path
        size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
        LPVOID remotePath = VirtualAllocEx(hProcess, nullptr, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remotePath) {
            return InjectionResult::MemoryProtectionFailed;
        }
        
        // Write DLL path
        if (!WriteProcessMemory(hProcess, remotePath, dllPath.c_str(), pathSize, nullptr)) {
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return InjectionResult::InjectionFailed;
        }
        
        // Get necessary function addresses
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        
        LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
        FARPROC addVectoredExceptionHandler = GetProcAddress(hKernel32, "AddVectoredExceptionHandler");
        FARPROC removeVectoredExceptionHandler = GetProcAddress(hKernel32, "RemoveVectoredExceptionHandler");
        
        if (!loadLibraryAddr || !addVectoredExceptionHandler || !removeVectoredExceptionHandler) {
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return InjectionResult::InjectionFailed;
        }
        
        // Allocate memory for VEH handler shellcode
        LPVOID vehHandlerAddr = VirtualAllocEx(hProcess, nullptr, 2048, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!vehHandlerAddr) {
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return InjectionResult::MemoryProtectionFailed;
        }
        
        // Create VEH handler shellcode that loads the DLL on exception
        unsigned char vehShellcode[] = {
            // VEH Handler function
            0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 0x28
            0x48, 0x8B, 0x49, 0x00,                         // mov rcx, [rcx] (ExceptionRecord)
            0x83, 0x39, 0x80000003,                         // cmp dword ptr [rcx], 0x80000003 (EXCEPTION_BREAKPOINT)
            0x75, 0x20,                                     // jne skip_injection
            
            // Load DLL
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, dllPath
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, LoadLibraryW
            0xFF, 0xD0,                                     // call rax
            
            // Remove VEH handler
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, veh_handle
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, RemoveVectoredExceptionHandler
            0xFF, 0xD0,                                     // call rax
            
            // skip_injection:
            0xB8, 0x00, 0x00, 0x00, 0x00,                   // mov eax, EXCEPTION_CONTINUE_SEARCH
            0x48, 0x83, 0xC4, 0x28,                         // add rsp, 0x28
            0xC3                                            // ret
        };
        
        // Patch shellcode with addresses
        *(LPVOID*)(vehShellcode + 15) = remotePath;
        *(LPVOID*)(vehShellcode + 25) = loadLibraryAddr;
        *(LPVOID*)(vehShellcode + 35) = nullptr; // Will be filled with VEH handle
        *(LPVOID*)(vehShellcode + 45) = removeVectoredExceptionHandler;
        
        // Write VEH handler
        if (!WriteProcessMemory(hProcess, vehHandlerAddr, vehShellcode, sizeof(vehShellcode), nullptr)) {
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, vehHandlerAddr, 0, MEM_RELEASE);
            return InjectionResult::InjectionFailed;
        }
        
        // Create remote thread to install VEH handler
        HANDLE hRemoteThread = CreateRemoteThread(hProcess, nullptr, 0, 
            (LPTHREAD_START_ROUTINE)addVectoredExceptionHandler, 
            (LPVOID)1, // First handler
            0, nullptr);
            
        if (!hRemoteThread) {
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, vehHandlerAddr, 0, MEM_RELEASE);
            return InjectionResult::ThreadCreationFailed;
        }
        
        // Wait for VEH installation
        WaitForSingleObject(hRemoteThread, INFINITE);
        CloseHandle(hRemoteThread);
        
        // Trigger exception in target process to activate VEH
        // This is a simplified approach - in practice, you'd need more sophisticated triggering
        HANDLE hTriggerThread = CreateRemoteThread(hProcess, nullptr, 0, 
            (LPTHREAD_START_ROUTINE)DebugBreak, nullptr, 0, nullptr);
            
        if (hTriggerThread) {
            WaitForSingleObject(hTriggerThread, 1000); // Short wait
            CloseHandle(hTriggerThread);
        }
        
        // Apply stealth techniques
        if (stealth.dllDelay > 0) {
            AddRandomDelay(stealth.dllDelay, stealth.useRandomDelays ? 500 : 0);
        }
        
        return InjectionResult::Success;
        
    } catch (const std::exception&) {
        return InjectionResult::InjectionFailed;
    }
}

// Section Mapping Injection
InjectionResult Injector::InjectUsingSectionMapping(HANDLE hProcess, const std::wstring& dllPath, const StealthOptions& stealth) {
    try {
        // Read DLL file
        HANDLE hFile = CreateFileW(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            return InjectionResult::DllNotFound;
        }
        
        DWORD fileSize = GetFileSize(hFile, nullptr);
        if (fileSize == INVALID_FILE_SIZE) {
            CloseHandle(hFile);
            return InjectionResult::DllNotFound;
        }
        
        // Create file mapping
        HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMapping) {
            CloseHandle(hFile);
            return InjectionResult::MemoryProtectionFailed;
        }
        
        // Map view of file
        LPVOID fileData = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        if (!fileData) {
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return InjectionResult::MemoryProtectionFailed;
        }
        
        // Parse PE headers
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            UnmapViewOfFile(fileData);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return InjectionResult::DllInvalid;
        }
        
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)fileData + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            UnmapViewOfFile(fileData);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return InjectionResult::DllInvalid;
        }
        
        // Create section in target process
        HANDLE hSection = nullptr;
        LARGE_INTEGER sectionSize;
        sectionSize.QuadPart = ntHeaders->OptionalHeader.SizeOfImage;
        
        // Use NtCreateSection (requires ntdll functions)
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        typedef NTSTATUS(WINAPI* pNtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
        typedef NTSTATUS(WINAPI* pNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
        
        pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
        pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
        
        if (!NtCreateSection || !NtMapViewOfSection) {
            UnmapViewOfFile(fileData);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return InjectionResult::InjectionFailed;
        }
        
        // Create section
        NTSTATUS status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, nullptr, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);
        if (status != 0) {
            UnmapViewOfFile(fileData);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return InjectionResult::MemoryProtectionFailed;
        }
        
        // Map section in current process
        PVOID localBase = nullptr;
        SIZE_T viewSize = 0;
        status = NtMapViewOfSection(hSection, GetCurrentProcess(), &localBase, 0, 0, nullptr, &viewSize, 1, 0, PAGE_READWRITE);
        if (status != 0) {
            CloseHandle(hSection);
            UnmapViewOfFile(fileData);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return InjectionResult::MemoryProtectionFailed;
        }
        
        // Copy DLL to section
        memcpy(localBase, fileData, fileSize);
        
        // Map section in target process
        PVOID remoteBase = nullptr;
        viewSize = 0;
        status = NtMapViewOfSection(hSection, hProcess, &remoteBase, 0, 0, nullptr, &viewSize, 1, 0, PAGE_EXECUTE_READ);
        if (status != 0) {
            UnmapViewOfFile(localBase);
            CloseHandle(hSection);
            UnmapViewOfFile(fileData);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return InjectionResult::MemoryProtectionFailed;
        }
        
        // Get DLL entry point
        LPVOID entryPoint = (LPVOID)((BYTE*)remoteBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
        
        // Create remote thread at entry point
        HANDLE hRemoteThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)entryPoint, remoteBase, 0, nullptr);
        if (!hRemoteThread) {
            UnmapViewOfFile(localBase);
            CloseHandle(hSection);
            UnmapViewOfFile(fileData);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return InjectionResult::ThreadCreationFailed;
        }
        
        // Wait for DLL initialization
        WaitForSingleObject(hRemoteThread, INFINITE);
        CloseHandle(hRemoteThread);
        
        // Cleanup
        UnmapViewOfFile(localBase);
        CloseHandle(hSection);
        UnmapViewOfFile(fileData);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        
        // Apply stealth techniques
        if (stealth.dllDelay > 0) {
            AddRandomDelay(stealth.dllDelay, stealth.useRandomDelays ? 500 : 0);
        }
        
        return InjectionResult::Success;
        
    } catch (const std::exception&) {
        return InjectionResult::InjectionFailed;
    }
}

// Thread Hijacking Injection
InjectionResult Injector::InjectUsingThreadHijacking(HANDLE hProcess, const std::wstring& dllPath, const StealthOptions& stealth) {
    try {
        DWORD processId = GetProcessId(hProcess);
        if (processId == 0) {
            return InjectionResult::ProcessNotFound;
        }
        
        // Allocate memory for DLL path
        size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
        LPVOID remotePath = VirtualAllocEx(hProcess, nullptr, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remotePath) {
            return InjectionResult::MemoryProtectionFailed;
        }
        
        // Write DLL path
        if (!WriteProcessMemory(hProcess, remotePath, dllPath.c_str(), pathSize, nullptr)) {
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return InjectionResult::InjectionFailed;
        }
        
        // Get LoadLibraryW address
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
        if (!loadLibraryAddr) {
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return InjectionResult::InjectionFailed;
        }
        
        // Find a suitable thread to hijack
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return InjectionResult::ThreadCreationFailed;
        }
        
        THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
        HANDLE hThread = nullptr;
        
        if (Thread32First(hSnapshot, &te32)) {
            do {
                if (te32.th32OwnerProcessID == processId) {
                    hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
                    if (hThread) {
                        break;
                    }
                }
            } while (Thread32Next(hSnapshot, &te32));
        }
        
        CloseHandle(hSnapshot);
        
        if (!hThread) {
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return InjectionResult::ThreadCreationFailed;
        }
        
        // Suspend thread
        if (SuspendThread(hThread) == (DWORD)-1) {
            CloseHandle(hThread);
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return InjectionResult::ThreadCreationFailed;
        }
        
        // Get thread context
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(hThread, &ctx)) {
            ResumeThread(hThread);
            CloseHandle(hThread);
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return InjectionResult::ThreadCreationFailed;
        }
        
        // Allocate memory for shellcode
        LPVOID shellcodeAddr = VirtualAllocEx(hProcess, nullptr, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!shellcodeAddr) {
            ResumeThread(hThread);
            CloseHandle(hThread);
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return InjectionResult::MemoryProtectionFailed;
        }
        
        // Create shellcode to call LoadLibraryW
        unsigned char shellcode[] = {
            0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 0x28
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, dllPath
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, LoadLibraryW
            0xFF, 0xD0,                                     // call rax
            0x48, 0x83, 0xC4, 0x28,                         // add rsp, 0x28
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, original_rip
            0xFF, 0xE0                                      // jmp rax
        };
        
        // Patch shellcode with addresses
        *(LPVOID*)(shellcode + 6) = remotePath;
        *(LPVOID*)(shellcode + 16) = loadLibraryAddr;
#ifdef _WIN64
        *(LPVOID*)(shellcode + 30) = (LPVOID)ctx.Rip;
#else
        *(LPVOID*)(shellcode + 30) = (LPVOID)ctx.Eip;
#endif
        
        // Write shellcode
        if (!WriteProcessMemory(hProcess, shellcodeAddr, shellcode, sizeof(shellcode), nullptr)) {
            ResumeThread(hThread);
            CloseHandle(hThread);
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
            return InjectionResult::InjectionFailed;
        }
        
        // Modify thread context to execute shellcode
#ifdef _WIN64
        ctx.Rip = (DWORD64)shellcodeAddr;
#else
        ctx.Eip = (DWORD)shellcodeAddr;
#endif
        
        if (!SetThreadContext(hThread, &ctx)) {
            ResumeThread(hThread);
            CloseHandle(hThread);
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
            return InjectionResult::ThreadCreationFailed;
        }
        
        // Resume thread
        ResumeThread(hThread);
        CloseHandle(hThread);
        
        // Apply stealth techniques
        if (stealth.dllDelay > 0) {
            AddRandomDelay(stealth.dllDelay, stealth.useRandomDelays ? 500 : 0);
        }
        
        return InjectionResult::Success;
        
    } catch (const std::exception&) {
        return InjectionResult::InjectionFailed;
    }
}

// Helper function for adding random delays
void Injector::AddRandomDelay(int baseDelayMs, int randomRangeMs) {
    int delay = baseDelayMs;
    if (randomRangeMs > 0) {
        srand(static_cast<unsigned int>(time(nullptr)));
        delay += rand() % randomRangeMs;
    }
    Sleep(delay);
}

// Apply stealth techniques
void Injector::ApplyStealthTechniques(HANDLE hProcess, LPVOID moduleBase, const StealthOptions& stealth) {
    if (stealth.erasePEHeader && moduleBase) {
        // Erase PE header to avoid detection
        BYTE zeroBuffer[0x1000] = { 0 };
        WriteProcessMemory(hProcess, moduleBase, zeroBuffer, sizeof(zeroBuffer), nullptr);
    }
    
    if (stealth.cycleMemoryProtection && moduleBase) {
        // Cycle memory protection to confuse scanners
        DWORD oldProtect;
        VirtualProtectEx(hProcess, moduleBase, 0x1000, PAGE_READONLY, &oldProtect);
        Sleep(10);
        VirtualProtectEx(hProcess, moduleBase, 0x1000, oldProtect, &oldProtect);
    }
    
    if (stealth.useRandomDelays) {
        AddRandomDelay(100, 200); // Random delay between 100-300ms
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