#include "Logger.h"
#include "Injector.h"
#include <iostream>
#include <algorithm>
#include <filesystem>
#include <cstdarg>
#include <windows.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

Logger::Logger() 
    : currentLogLevel(LogLevel::Info)
    , maxBufferSize(10000)
    , consoleOutputEnabled(true)
    , fileOutputEnabled(true)
    , totalLogs(0)
    , startTime(std::chrono::system_clock::now()) {
    
    // Initialize statistics arrays
    std::fill(std::begin(logsByLevel), std::end(logsByLevel), 0);
    std::fill(std::begin(logsByCategory), std::end(logsByCategory), 0);
    
    // Set default log file
    logFilename = "G25F_Injector.log";
    
    // Open log file
    if (fileOutputEnabled) {
        logFile.open(logFilename, std::ios::app);
        if (logFile.is_open()) {
            logFile << "=== G25F Injector Log Started ===" << std::endl;
            logFile << "Timestamp: " << formatTimestamp(startTime) << std::endl;
            logFile << "=================================" << std::endl;
            logFile.flush();
        }
    }
}

Logger::~Logger() {
    if (logFile.is_open()) {
        logFile << "=== G25F Injector Log Ended ===" << std::endl;
        logFile << "Timestamp: " << formatTimestamp(std::chrono::system_clock::now()) << std::endl;
        logFile << "Total Logs: " << totalLogs << std::endl;
        logFile << "===============================" << std::endl;
        logFile.close();
    }
}

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

void Logger::log(LogLevel level, LogCategory category, const std::string& message,
                const std::string& processName, const std::string& dllPath,
                const std::string& details) {
    
    if (static_cast<int>(level) < static_cast<int>(currentLogLevel)) {
        return;
    }
    
    LogEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.level = level;
    entry.category = category;
    entry.message = message;
    entry.processName = processName;
    entry.dllPath = dllPath;
    entry.details = details;
    entry.stackTrace = getStackTrace();
    
    std::lock_guard<std::mutex> lock(logMutex);
    
    // Add to buffer
    logBuffer.push_back(entry);
    if (logBuffer.size() > maxBufferSize) {
        logBuffer.erase(logBuffer.begin());
    }
    
    // Update statistics
    totalLogs++;
    logsByLevel[static_cast<size_t>(level)]++;
    logsByCategory[static_cast<size_t>(category)]++;
    
    // Output to destinations
    if (consoleOutputEnabled) {
        writeToConsole(entry);
    }
    
    if (fileOutputEnabled) {
        writeToFile(entry);
    }
}

void Logger::logInjection(InjectionResult result, const std::string& details,
                         const std::string& processName, const std::string& dllPath,
                         InjectionMethod method, const StealthOptions& stealth) {
    
    std::string methodStr;
    switch (method) {
        case InjectionMethod::LoadLibrary: methodStr = "LoadLibrary"; break;
        case InjectionMethod::CreateRemoteThread: methodStr = "CreateRemoteThread"; break;
        case InjectionMethod::ManualMap: methodStr = "ManualMap"; break;
        case InjectionMethod::SetWindowsHook: methodStr = "SetWindowsHook"; break;
        case InjectionMethod::APCInjection: methodStr = "APCInjection"; break;
        case InjectionMethod::ThreadHijacking: methodStr = "ThreadHijacking"; break;
        case InjectionMethod::VEHInjection: methodStr = "VEHInjection"; break;
        case InjectionMethod::SectionMapping: methodStr = "SectionMapping"; break;
    }
    
    std::string stealthInfo;
    if (stealth.erasePEHeader) stealthInfo += "PE_ERASE,";
    if (stealth.hideModule) stealthInfo += "HIDE_MODULE,";
    if (stealth.useRandomDelays) stealthInfo += "RANDOM_DELAYS,";
    if (stealth.obfuscateStrings) stealthInfo += "OBFUSCATE_STRINGS,";
    if (stealth.useIndirectCalls) stealthInfo += "INDIRECT_CALLS,";
    if (stealth.cycleMemoryProtection) stealthInfo += "CYCLE_PROTECTION,";
    if (stealth.useCustomMemoryPatterns) stealthInfo += "CUSTOM_PATTERNS,";
    if (stealth.bypassModuleEnumeration) stealthInfo += "BYPASS_ENUMERATION,";
    
    if (!stealthInfo.empty()) {
        stealthInfo = stealthInfo.substr(0, stealthInfo.length() - 1); // Remove trailing comma
    }
    
    std::string fullDetails = "Method: " + methodStr + 
                             " | Result: " + std::to_string(static_cast<int>(result)) +
                             " | Stealth: [" + stealthInfo + "]" +
                             " | " + details;
    
    LogLevel logLevel = (result == InjectionResult::Success) ? LogLevel::Info : LogLevel::Error;
    
    log(logLevel, LogCategory::INJECTION, "DLL Injection Attempt", 
        processName, dllPath, fullDetails);
}

void Logger::logError(const std::string& error, const std::string& details, const std::string& processName) {
    log(LogLevel::Error, LogCategory::GENERAL, error, processName, "", details);
}

void Logger::logWarning(const std::string& warning, const std::string& details) {
    log(LogLevel::Warning, LogCategory::GENERAL, warning, "", "", details);
}

void Logger::logInfo(const std::string& info, const std::string& details) {
    log(LogLevel::Info, LogCategory::GENERAL, info, "", "", details);
}

void Logger::logDebug(const std::string& debug, const std::string& details) {
    log(LogLevel::Debug, LogCategory::GENERAL, debug, "", "", details);
}

void Logger::setLogLevel(LogLevel level) {
    currentLogLevel = level;
}

void Logger::setLogFile(const std::string& filename) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    if (logFile.is_open()) {
        logFile.close();
    }
    
    logFilename = filename;
    
    if (fileOutputEnabled) {
        logFile.open(logFilename, std::ios::app);
    }
}

void Logger::setMaxBufferSize(size_t size) {
    std::lock_guard<std::mutex> lock(logMutex);
    maxBufferSize = size;
    
    // Trim buffer if necessary
    while (logBuffer.size() > maxBufferSize) {
        logBuffer.erase(logBuffer.begin());
    }
}

void Logger::enableConsoleOutput(bool enable) {
    consoleOutputEnabled = enable;
}

void Logger::enableFileOutput(bool enable) {
    std::lock_guard<std::mutex> lock(logMutex);
    fileOutputEnabled = enable;
    
    if (enable && !logFile.is_open()) {
        logFile.open(logFilename, std::ios::app);
    } else if (!enable && logFile.is_open()) {
        logFile.close();
    }
}

std::vector<LogEntry> Logger::getRecentLogs(size_t count) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    if (count >= logBuffer.size()) {
        return logBuffer;
    }
    
    return std::vector<LogEntry>(logBuffer.end() - count, logBuffer.end());
}

std::vector<LogEntry> Logger::getLogsByCategory(LogCategory category, size_t count) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    std::vector<LogEntry> filteredLogs;
    for (auto it = logBuffer.rbegin(); it != logBuffer.rend() && filteredLogs.size() < count; ++it) {
        if (it->category == category) {
            filteredLogs.push_back(*it);
        }
    }
    
    return filteredLogs;
}

std::vector<LogEntry> Logger::getLogsByLevel(LogLevel level, size_t count) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    std::vector<LogEntry> filteredLogs;
    for (auto it = logBuffer.rbegin(); it != logBuffer.rend() && filteredLogs.size() < count; ++it) {
        if (it->level == level) {
            filteredLogs.push_back(*it);
        }
    }
    
    return filteredLogs;
}

std::vector<LogEntry> Logger::getLogsByProcess(const std::string& processName, size_t count) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    std::vector<LogEntry> filteredLogs;
    for (auto it = logBuffer.rbegin(); it != logBuffer.rend() && filteredLogs.size() < count; ++it) {
        if (it->processName == processName) {
            filteredLogs.push_back(*it);
        }
    }
    
    return filteredLogs;
}

std::string Logger::exportLogsAsText(const std::vector<LogEntry>& logs) {
    std::stringstream ss;
    
    for (const auto& entry : logs) {
        ss << formatTimestamp(entry.timestamp) << " | "
           << levelToString(entry.level) << " | "
           << categoryToString(entry.category) << " | "
           << entry.message;
        
        if (!entry.processName.empty()) {
            ss << " | Process: " << entry.processName;
        }
        
        if (!entry.dllPath.empty()) {
            ss << " | DLL: " << entry.dllPath;
        }
        
        if (!entry.details.empty()) {
            ss << " | Details: " << entry.details;
        }
        
        ss << std::endl;
    }
    
    return ss.str();
}

std::string Logger::exportLogsAsJSON(const std::vector<LogEntry>& logs) {
    std::stringstream ss;
    ss << "[\n";
    
    for (size_t i = 0; i < logs.size(); ++i) {
        const auto& entry = logs[i];
        
        ss << "  {\n"
           << "    \"timestamp\": \"" << formatTimestamp(entry.timestamp) << "\",\n"
           << "    \"level\": \"" << levelToString(entry.level) << "\",\n"
           << "    \"category\": \"" << categoryToString(entry.category) << "\",\n"
           << "    \"message\": \"" << entry.message << "\",\n"
           << "    \"processName\": \"" << entry.processName << "\",\n"
           << "    \"dllPath\": \"" << entry.dllPath << "\",\n"
           << "    \"details\": \"" << entry.details << "\"\n"
           << "  }";
        
        if (i < logs.size() - 1) {
            ss << ",";
        }
        ss << "\n";
    }
    
    ss << "]\n";
    return ss.str();
}

std::string Logger::generateReport() {
    std::stringstream ss;
    
    ss << "=== G25F Injector Log Report ===\n";
    ss << "Generated: " << formatTimestamp(std::chrono::system_clock::now()) << "\n";
    ss << "Total Logs: " << totalLogs << "\n";
    ss << "Session Duration: " << std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now() - startTime).count() << " seconds\n\n";
    
    ss << "Logs by Level:\n";
    ss << "  Debug: " << logsByLevel[0] << "\n";
    ss << "  Info: " << logsByLevel[1] << "\n";
    ss << "  Warning: " << logsByLevel[2] << "\n";
    ss << "  Error: " << logsByLevel[3] << "\n";
    ss << "  Critical: " << logsByLevel[4] << "\n\n";
    
    ss << "Logs by Category:\n";
    ss << "  INJECTION: " << logsByCategory[0] << "\n";
    ss << "  PROCESS: " << logsByCategory[1] << "\n";
    ss << "  MEMORY: " << logsByCategory[2] << "\n";
    ss << "  STEALTH: " << logsByCategory[3] << "\n";
    ss << "  SYSTEM: " << logsByCategory[4] << "\n";
    ss << "  NETWORK: " << logsByCategory[5] << "\n";
    ss << "  GENERAL: " << logsByCategory[6] << "\n";
    
    return ss.str();
}

void Logger::clearBuffer() {
    std::lock_guard<std::mutex> lock(logMutex);
    logBuffer.clear();
    totalLogs = 0;
    std::fill(std::begin(logsByLevel), std::end(logsByLevel), 0);
    std::fill(std::begin(logsByCategory), std::end(logsByCategory), 0);
}

void Logger::rotateLogFile() {
    std::lock_guard<std::mutex> lock(logMutex);
    
    if (logFile.is_open()) {
        logFile.close();
    }
    
    // Create backup filename with timestamp
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream backupName;
    backupName << logFilename << "." << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S");
    
    // Rename current log file
    if (std::filesystem::exists(logFilename)) {
        std::filesystem::rename(logFilename, backupName.str());
    }
    
    // Open new log file
    logFile.open(logFilename, std::ios::app);
    if (logFile.is_open()) {
        logFile << "=== G25F Injector Log Rotated ===" << std::endl;
        logFile << "Timestamp: " << formatTimestamp(now) << std::endl;
        logFile << "Previous: " << backupName.str() << std::endl;
        logFile << "=================================" << std::endl;
        logFile.flush();
    }
}

void Logger::writeToFile(const LogEntry& entry) {
    if (!logFile.is_open()) {
        return;
    }
    
    logFile << formatTimestamp(entry.timestamp) << " | "
            << levelToString(entry.level) << " | "
            << categoryToString(entry.category) << " | "
            << entry.message;
    
    if (!entry.processName.empty()) {
        logFile << " | Process: " << entry.processName;
    }
    
    if (!entry.dllPath.empty()) {
        logFile << " | DLL: " << entry.dllPath;
    }
    
    if (!entry.details.empty()) {
        logFile << " | Details: " << entry.details;
    }
    
    logFile << std::endl;
    logFile.flush();
}

void Logger::writeToConsole(const LogEntry& entry) {
    // Set console color based on log level
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    WORD originalColor;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    originalColor = csbi.wAttributes;
    
    WORD color;
    switch (entry.level) {
        case LogLevel::Debug: color = FOREGROUND_INTENSITY; break;
        case LogLevel::Info: color = FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
        case LogLevel::Warning: color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
        case LogLevel::Error: color = FOREGROUND_RED | FOREGROUND_INTENSITY; break;
        case LogLevel::Critical: color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY; break;
        default: color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    }
    
    SetConsoleTextAttribute(hConsole, color);
    
    std::cout << formatTimestamp(entry.timestamp) << " | "
              << levelToString(entry.level) << " | "
              << categoryToString(entry.category) << " | "
              << entry.message;
    
    if (!entry.processName.empty()) {
        std::cout << " | Process: " << entry.processName;
    }
    
    if (!entry.dllPath.empty()) {
        std::cout << " | DLL: " << entry.dllPath;
    }
    
    if (!entry.details.empty()) {
        std::cout << " | Details: " << entry.details;
    }
    
    std::cout << std::endl;
    
    // Restore original color
    SetConsoleTextAttribute(hConsole, originalColor);
}

std::string Logger::formatTimestamp(const std::chrono::system_clock::time_point& timestamp) {
    auto time_t = std::chrono::system_clock::to_time_t(timestamp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    
    return ss.str();
}

std::string Logger::levelToString(LogLevel level) {
    switch (level) {
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info: return "INFO";
        case LogLevel::Warning: return "WARN";
        case LogLevel::Error: return "ERROR";
        case LogLevel::Critical: return "CRIT";
        default: return "UNKNOWN";
    }
}

std::string Logger::categoryToString(LogCategory category) {
    switch (category) {
        case LogCategory::INJECTION: return "INJECTION";
        case LogCategory::PROCESS: return "PROCESS";
        case LogCategory::MEMORY: return "MEMORY";
        case LogCategory::STEALTH: return "STEALTH";
        case LogCategory::SYSTEM: return "SYSTEM";
        case LogCategory::NETWORK: return "NETWORK";
        case LogCategory::GENERAL: return "GENERAL";
        default: return "UNKNOWN";
    }
}

std::string Logger::getStackTrace() {
    // Simple stack trace implementation
    // In a production environment, you might want to use a more sophisticated approach
    return "Stack trace not implemented";
}
