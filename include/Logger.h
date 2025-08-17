#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <mutex>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <memory>

// Forward declarations to avoid pulling in windows.h via Injector.h here
enum class InjectionResult;
enum class InjectionMethod;
struct StealthOptions;

enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical
};

enum class LogCategory {
    INJECTION,
    PROCESS,
    MEMORY,
    STEALTH,
    SYSTEM,
    NETWORK,
    GENERAL
};

struct LogEntry {
    std::chrono::system_clock::time_point timestamp;
    LogLevel level;
    LogCategory category;
    std::string message;
    std::string processName;
    std::string dllPath;
    std::string details;
    std::string stackTrace;
};

class Logger {
public:
    static Logger& getInstance();
    
    // Logging methods
    void log(LogLevel level, LogCategory category, const std::string& message,
             const std::string& processName = "", const std::string& dllPath = "",
             const std::string& details = "");
    
    void logInjection(InjectionResult result, const std::string& details,
                     const std::string& processName, const std::string& dllPath,
                     InjectionMethod method, const StealthOptions& stealth);
    
    void logError(const std::string& error, const std::string& details = "",
                  const std::string& processName = "");
    
    void logWarning(const std::string& warning, const std::string& details = "");
    
    void logInfo(const std::string& info, const std::string& details = "");

    void logDebug(const std::string& debug, const std::string& details = "");
    
    // Configuration
    void setLogLevel(LogLevel level);
    void setLogFile(const std::string& filename);
    void setMaxBufferSize(size_t size);
    void enableConsoleOutput(bool enable);
    void enableFileOutput(bool enable);
    
    // Retrieval
    std::vector<LogEntry> getRecentLogs(size_t count = 100);
    std::vector<LogEntry> getLogsByCategory(LogCategory category, size_t count = 100);
    std::vector<LogEntry> getLogsByLevel(LogLevel level, size_t count = 100);
    std::vector<LogEntry> getLogsByProcess(const std::string& processName, size_t count = 100);
    
    // Export and analysis
    std::string exportLogsAsText(const std::vector<LogEntry>& logs);
    std::string exportLogsAsJSON(const std::vector<LogEntry>& logs);
    std::string generateReport();
    
    // Cleanup
    void clearBuffer();
    void rotateLogFile();
    
private:
    Logger();
    ~Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    void writeToFile(const LogEntry& entry);
    void writeToConsole(const LogEntry& entry);
    std::string formatTimestamp(const std::chrono::system_clock::time_point& timestamp);
    std::string levelToString(LogLevel level);
    std::string categoryToString(LogCategory category);
    std::string getStackTrace();
    
    // Configuration
    LogLevel currentLogLevel;
    std::string logFilename;
    size_t maxBufferSize;
    bool consoleOutputEnabled;
    bool fileOutputEnabled;
    
    // Internal state
    std::ofstream logFile;
    std::mutex logMutex;
    std::vector<LogEntry> logBuffer;
    std::chrono::system_clock::time_point startTime;
    
    // Statistics
    size_t totalLogs;
    size_t logsByLevel[5]; // Debug, Info, Warning, Error, Critical
    size_t logsByCategory[7]; // All categories
};

// Convenience macros for logging
#define LOG_DEBUG(category, message, ...) \
    Logger::getInstance().log(LogLevel::Debug, LogCategory::category, message, ##__VA_ARGS__)

#define LOG_INFO(category, message, ...) \
    Logger::getInstance().log(LogLevel::Info, LogCategory::category, message, ##__VA_ARGS__)

#define LOG_WARNING(category, message, ...) \
    Logger::getInstance().log(LogLevel::Warning, LogCategory::category, message, ##__VA_ARGS__)

#define LOG_ERROR(category, message, ...) \
    Logger::getInstance().log(LogLevel::Error, LogCategory::category, message, ##__VA_ARGS__)

#define LOG_CRITICAL(category, message, ...) \
    Logger::getInstance().log(LogLevel::Critical, LogCategory::category, message, ##__VA_ARGS__)

#define LOG_INJECTION(result, details, processName, dllPath, method, stealth) \
    Logger::getInstance().logInjection(result, details, processName, dllPath, method, stealth)
