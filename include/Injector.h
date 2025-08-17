#pragma once
#include <windows.h>
#include <string>
#include <libmem/libmem.hpp>

enum class InjectionMethod {
    LoadLibrary,
    CreateRemoteThread,
    ManualMap,
    SetWindowsHook,
    // NEW: Advanced anti-cheat evasion methods
    APCInjection,           // Asynchronous Procedure Call
    ThreadHijacking,        // Hijack existing threads
    VEHInjection,          // Vectored Exception Handler
    SectionMapping          // Memory section mapping
};

enum class InjectionResult {
    Success,
    ProcessNotFound,
    ProcessAccessDenied,
    DllNotFound,
    DllInvalid,
    ArchitectureMismatch,
    InjectionFailed,
    UnknownError,
    // NEW: Enhanced error types
    AntiCheatDetected,
    MemoryProtectionFailed,
    ThreadCreationFailed,
    HookInstallationFailed,
    SectionMappingFailed
};

// Enhanced stealth options for anti-cheat evasion
struct StealthOptions {
    bool erasePEHeader = false;        // Erase PE header after injection
    bool hideModule = false;           // Hide module from module list
    bool useRandomDelays = false;      // Add random delays to avoid timing detection
    bool obfuscateStrings = false;     // Obfuscate strings in memory
    bool useIndirectCalls = false;     // Use indirect function calls
    bool cycleMemoryProtection = false; // Cycle memory protection flags
    bool useCustomMemoryPatterns = false; // Use custom memory allocation patterns
    bool bypassModuleEnumeration = false; // Bypass module enumeration APIs
    int injectionDelay = 0;            // Custom injection delay in ms
    int dllDelay = 500;                // Delay after DLL injection in ms
};

class Injector {
public:
    static InjectionResult InjectDLL(DWORD processId, const std::wstring& dllPath, 
                                   InjectionMethod method = InjectionMethod::LoadLibrary);
    static std::wstring GetErrorMessage(InjectionResult result);
    
    // NEW: Enhanced injection methods with stealth options
    static InjectionResult InjectWithStealth(DWORD processId, const std::wstring& dllPath,
                                           InjectionMethod method, const StealthOptions& stealth);
    
private:
    // Existing injection methods
    static InjectionResult InjectUsingCreateRemoteThread(HANDLE hProcess, const std::wstring& dllPath);
    static InjectionResult InjectUsingManualMap(HANDLE hProcess, const std::wstring& dllPath);
    static InjectionResult InjectUsingSetWindowsHook(DWORD processId, const std::wstring& dllPath);
    static InjectionResult InjectUsingLoadLibrary(DWORD processId, const std::wstring& dllPath);
    
    // NEW: Advanced anti-cheat evasion methods
    static InjectionResult InjectUsingAPC(HANDLE hProcess, const std::wstring& dllPath, const StealthOptions& stealth);
    static InjectionResult InjectUsingThreadHijacking(HANDLE hProcess, const std::wstring& dllPath, const StealthOptions& stealth);
    static InjectionResult InjectUsingVEH(HANDLE hProcess, const std::wstring& dllPath, const StealthOptions& stealth);
    static InjectionResult InjectUsingSectionMapping(HANDLE hProcess, const std::wstring& dllPath, const StealthOptions& stealth);
    
    // Helper functions
    static bool IsValidDLL(const std::wstring& dllPath);
    static bool IsArchitectureCompatible(HANDLE hProcess, const std::wstring& dllPath);
    static LPVOID GetProcAddressEx(HANDLE hProcess, HMODULE hModule, const char* functionName);
    
    // Manual mapping helpers
    static bool MapDLLToProcess(HANDLE hProcess, const std::wstring& dllPath);
    static void RelocateImage(LPVOID imageBase, LPVOID newBase, PIMAGE_NT_HEADERS ntHeaders);
    static void ResolveImports(HANDLE hProcess, LPVOID imageBase, PIMAGE_NT_HEADERS ntHeaders);
    
    // NEW: Stealth helper functions
    static void ApplyStealthTechniques(HANDLE hProcess, LPVOID dllBase, const StealthOptions& stealth);
    static void ErasePEHeader(HANDLE hProcess, LPVOID dllBase);
    static void HideModuleFromList(HANDLE hProcess, LPVOID dllBase);
    static void ObfuscateStrings(HANDLE hProcess, LPVOID dllBase);
    static void CycleMemoryProtection(HANDLE hProcess, LPVOID dllBase, size_t size);
    static void AddRandomDelay(int baseDelay, int maxRandomDelay);
    static bool BypassModuleEnumeration(HANDLE hProcess, LPVOID dllBase);
};