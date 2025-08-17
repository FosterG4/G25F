#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <sstream>
#include <fstream>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <memory>
#include <functional>
#include <chrono>
#include <mutex>
#include <map>
#include <queue>
#include "Injector.h"
#include "Logger.h"
#include <nlohmann/json.hpp>

#pragma comment(lib, "ws2_32.lib")

using json = nlohmann::json;

struct ProcessInfo {
    DWORD pid;
    std::string name;
    std::string architecture;
};

struct ClientConnection {
    SOCKET socket;
    std::string id;
    std::chrono::system_clock::time_point lastSeen;
    bool isSSE;
};

class RealtimeHttpBackend {
private:
    SOCKET serverSocket;
    bool running;
    Logger& logger;
    
    // Client management
    std::map<std::string, ClientConnection> clients;
    mutable std::mutex clientsMutex;
    
    // Event queue for real-time updates
    std::queue<std::string> eventQueue;
    mutable std::mutex eventMutex;
    
    // Injection state
    std::mutex injectionMutex;
    bool injectionInProgress;
    std::string currentProcess;
    std::string currentDll;
    
    int port;
    
public:
    RealtimeHttpBackend(int httpPort = 8080) 
        : serverSocket(INVALID_SOCKET), running(false), 
          logger(Logger::getInstance()), injectionInProgress(false), port(httpPort) {
    }
    
    ~RealtimeHttpBackend() {
        stop();
    }
    
    bool start() {
        logger.logInfo("Starting realtime HTTP backend", "Port: " + std::to_string(port));
        
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            logger.logError("WSAStartup failed", "Windows Socket initialization failed");
            return false;
        }
        
        serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket == INVALID_SOCKET) {
            logger.logError("Socket creation failed", "HTTP server socket creation failed");
            WSACleanup();
            return false;
        }
        
        // Allow socket reuse
        int opt = 1;
        setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
        
        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port);
        
        if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            logger.logError("Bind failed", "HTTP server bind failed on port " + std::to_string(port));
            closesocket(serverSocket);
            WSACleanup();
            return false;
        }
        
        if (listen(serverSocket, 10) == SOCKET_ERROR) {
            logger.logError("Listen failed", "HTTP server listen failed");
            closesocket(serverSocket);
            WSACleanup();
            return false;
        }
        
        running = true;
        logger.logInfo("Realtime HTTP backend started", "Port: " + std::to_string(port));
        
        // Start event broadcasting thread
        std::thread([this]() { broadcastEvents(); }).detach();
        
        return true;
    }
    
    void run() {
        while (running) {
            sockaddr_in clientAddr;
            int clientAddrLen = sizeof(clientAddr);
            SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrLen);
            
            if (clientSocket != INVALID_SOCKET) {
                std::thread clientThread(&RealtimeHttpBackend::handleClient, this, clientSocket);
                clientThread.detach();
            }
        }
    }
    
    void stop() {
        running = false;
        
        // Close all client connections
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            for (auto& [id, client] : clients) {
                closesocket(client.socket);
            }
            clients.clear();
        }
        
        if (serverSocket != INVALID_SOCKET) {
            closesocket(serverSocket);
            serverSocket = INVALID_SOCKET;
        }
        WSACleanup();
        
        logger.logInfo("Realtime HTTP backend stopped", "Server shutdown completed");
    }
    
    bool isRunning() const { return running; }
    
    // Real-time event methods
    void broadcastInjectionStart(const std::string& processName, const std::string& dllPath) {
        json event = {
            {"type", "injection_start"},
            {"processName", processName},
            {"dllPath", dllPath},
            {"timestamp", std::chrono::system_clock::now().time_since_epoch().count()}
        };
        
        queueEvent(event.dump());
        logger.logInfo("Injection started", "Process: " + processName + ", DLL: " + dllPath);
    }
    
    void broadcastInjectionProgress(const std::string& processName, const std::string& dllPath, int progress) {
        json event = {
            {"type", "injection_progress"},
            {"processName", processName},
            {"dllPath", dllPath},
            {"progress", progress},
            {"timestamp", std::chrono::system_clock::now().time_since_epoch().count()}
        };
        
        queueEvent(event.dump());
    }
    
    void broadcastInjectionComplete(const std::string& processName, const std::string& dllPath, bool success) {
        json event = {
            {"type", success ? "injection_complete" : "injection_error"},
            {"processName", processName},
            {"dllPath", dllPath},
            {"success", success},
            {"timestamp", std::chrono::system_clock::now().time_since_epoch().count()}
        };
        
        queueEvent(event.dump());
        
        if (success) {
            logger.logInfo("Injection completed", "Process: " + processName + ", DLL: " + dllPath);
        } else {
            logger.logError("Injection failed", "Process: " + processName + ", DLL: " + dllPath);
        }
    }
    
    void broadcastProcessUpdate(const std::vector<ProcessInfo>& processes) {
        json event = {
            {"type", "process_update"},
            {"processes", json::array()},
            {"timestamp", std::chrono::system_clock::now().time_since_epoch().count()}
        };
        
        for (const auto& proc : processes) {
            event["processes"].push_back({
                {"pid", proc.pid},
                {"name", proc.name},
                {"architecture", proc.architecture}
            });
        }
        
        queueEvent(event.dump());
    }
    
    void broadcastStatus(const std::string& status) {
        json event = {
            {"type", "status_update"},
            {"status", status},
            {"timestamp", std::chrono::system_clock::now().time_since_epoch().count()}
        };
        
        queueEvent(event.dump());
    }
    
private:
    void queueEvent(const std::string& event) {
        std::lock_guard<std::mutex> lock(eventMutex);
        eventQueue.push(event);
        
        // Keep only last 100 events to prevent memory issues
        if (eventQueue.size() > 100) {
            eventQueue.pop();
        }
    }
    
    void broadcastEvents() {
        while (running) {
            std::string event;
            {
                std::lock_guard<std::mutex> lock(eventMutex);
                if (!eventQueue.empty()) {
                    event = eventQueue.front();
                    eventQueue.pop();
                }
            }
            
            if (!event.empty()) {
                broadcastToAllClients(event);
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    void broadcastToAllClients(const std::string& event) {
        std::lock_guard<std::mutex> lock(clientsMutex);
        
        auto it = clients.begin();
        while (it != clients.end()) {
            auto& [id, client] = *it;
            
            // Check if client is still alive
            if (std::chrono::system_clock::now() - client.lastSeen > std::chrono::seconds(30)) {
                logger.logInfo("Removing stale client", "Client: " + id);
                closesocket(client.socket);
                it = clients.erase(it);
                continue;
            }
            
            // Send event to client
            if (client.isSSE) {
                std::string sseMessage = "data: " + event + "\n\n";
                if (send(client.socket, sseMessage.c_str(), sseMessage.length(), 0) == SOCKET_ERROR) {
                    logger.logWarning("Failed to send SSE to client", "Client: " + id);
                    closesocket(client.socket);
                    it = clients.erase(it);
                    continue;
                }
            } else {
                // For regular HTTP clients, send as JSON response
                std::string response = "HTTP/1.1 200 OK\r\n";
                response += "Content-Type: application/json\r\n";
                response += "Access-Control-Allow-Origin: *\r\n";
                response += "\r\n";
                response += event;
                
                if (send(client.socket, response.c_str(), response.length(), 0) == SOCKET_ERROR) {
                    logger.logWarning("Failed to send HTTP to client", "Client: " + id);
                    closesocket(client.socket);
                    it = clients.erase(it);
                    continue;
                }
            }
            
            ++it;
        }
    }
    
    void handleClient(SOCKET clientSocket) {
        char buffer[4096];
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        
        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';
            std::string request(buffer);
            
            logger.logDebug("HTTP request received", "Request: " + request.substr(0, request.find('\n')));
            
            std::string response = processHttpRequest(request, clientSocket);
            send(clientSocket, response.c_str(), response.length(), 0);
        }
        
        closesocket(clientSocket);
    }
    
    std::string processHttpRequest(const std::string& request, SOCKET clientSocket) {
        std::string response;
        
        if (request.find("GET /api/events") != std::string::npos) {
            // Server-Sent Events endpoint
            response = setupSSEConnection(clientSocket);
        } else if (request.find("GET /api/processes") != std::string::npos) {
            response = getProcessesList();
        } else if (request.find("POST /api/inject") != std::string::npos) {
            response = handleInjectionRequest(request);
        } else if (request.find("GET /api/status") != std::string::npos) {
            response = getServerStatus();
        } else if (request.find("GET /api/logs") != std::string::npos) {
            response = getRecentLogs();
        } else if (request.find("GET /") != std::string::npos) {
            response = getIndexPage();
        } else {
            response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nEndpoint not found";
        }
        
        return response;
    }
    
    std::string setupSSEConnection(SOCKET clientSocket) {
        // Generate unique client ID
        std::string clientId = "client_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
        
        // Add client to our list
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            clients[clientId] = {
                clientSocket,
                clientId,
                std::chrono::system_clock::now(),
                true  // isSSE
            };
        }
        
        logger.logInfo("SSE client connected", "Client: " + clientId);
        
        // Send SSE headers
        std::string response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/event-stream\r\n";
        response += "Cache-Control: no-cache\r\n";
        response += "Connection: keep-alive\r\n";
        response += "Access-Control-Allow-Origin: *\r\n";
        response += "\r\n";
        
        // Send welcome message
        json welcome = {
            {"type", "welcome"},
            {"message", "Connected to G25F Injector realtime server"},
            {"clientId", clientId},
            {"timestamp", std::chrono::system_clock::now().time_since_epoch().count()}
        };
        
        response += "data: " + welcome.dump() + "\n\n";
        
        // Send current status
        broadcastStatus("New SSE client connected. Total clients: " + std::to_string(clients.size()));
        
        return response;
    }
    
    std::string getProcessesList() {
        std::vector<ProcessInfo> processes = enumerateProcesses();
        
        json result = {
            {"processes", json::array()},
            {"timestamp", std::chrono::system_clock::now().time_since_epoch().count()}
        };
        
        for (const auto& proc : processes) {
            result["processes"].push_back({
                {"pid", proc.pid},
                {"name", proc.name},
                {"architecture", proc.architecture}
            });
        }
        
        std::string response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: application/json\r\n";
        response += "Access-Control-Allow-Origin: *\r\n";
        response += "\r\n";
        response += result.dump();
        
        // Broadcast process update
        broadcastProcessUpdate(processes);
        
        return response;
    }
    
    std::string handleInjectionRequest(const std::string& request) {
        // Parse injection request from POST data
        // This is a simplified version - in production, you'd parse JSON properly
        
        logger.logInfo("Injection request received via HTTP", "Processing injection request");
        
        // Broadcast injection start
        broadcastInjectionStart("Unknown Process", "Unknown DLL");
        
        std::string response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: application/json\r\n";
        response += "Access-Control-Allow-Origin: *\r\n";
        response += "\r\n";
        response += "{\"status\": \"success\", \"message\": \"Injection request received\"}";
        
        return response;
    }
    
    std::string getServerStatus() {
        json status = {
            {"status", "running"},
            {"http_port", port},
            {"clients", clients.size()},
            {"injectionInProgress", injectionInProgress},
            {"uptime", "running"}
        };
        
        std::string response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: application/json\r\n";
        response += "Access-Control-Allow-Origin: *\r\n";
        response += "\r\n";
        response += status.dump();
        
        return response;
    }
    
    std::string getRecentLogs() {
        auto logs = logger.getRecentLogs(50);
        
        std::string response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: application/json\r\n";
        response += "Access-Control-Allow-Origin: *\r\n";
        response += "\r\n";
        response += logger.exportLogsAsJSON(logs);
        
        return response;
    }
    
    std::string getIndexPage() {
        std::string html = R"(
<!DOCTYPE html>
<html>
<head>
    <title>G25F Injector - Realtime Backend</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .status { padding: 10px; margin: 10px 0; border-radius: 5px; }
        .connected { background-color: #d4edda; color: #155724; }
        .disconnected { background-color: #f8d7da; color: #721c24; }
        .events { background: #f8f9fa; padding: 20px; border-radius: 5px; max-height: 400px; overflow-y: auto; }
        .event { padding: 5px; margin: 2px 0; background: white; border-radius: 3px; font-family: monospace; }
    </style>
</head>
<body>
    <h1>🚀 G25F Injector - Realtime Backend</h1>
    <div id="status" class="status disconnected">Connecting...</div>
    <div>
        <h3>📡 Real-time Events</h3>
        <div id="events" class="events">Waiting for connection...</div>
    </div>
    
    <script>
        let eventSource = null;
        let isConnected = false;
        
        function connect() {
            try {
                eventSource = new EventSource('/api/events');
                
                eventSource.onopen = function() {
                    updateStatus(true, 'Connected to realtime server');
                };
                
                eventSource.onmessage = function(event) {
                    try {
                        const data = JSON.parse(event.data);
                        displayEvent(data);
                    } catch (e) {
                        displayEvent({type: 'error', message: 'Failed to parse event'});
                    }
                };
                
                eventSource.onerror = function() {
                    updateStatus(false, 'Connection lost');
                    setTimeout(connect, 5000);
                };
                
            } catch (error) {
                updateStatus(false, 'Failed to connect: ' + error.message);
            }
        }
        
        function updateStatus(connected, message) {
            isConnected = connected;
            const statusEl = document.getElementById('status');
            statusEl.className = 'status ' + (connected ? 'connected' : 'disconnected');
            statusEl.textContent = message;
        }
        
        function displayEvent(event) {
            const eventsEl = document.getElementById('events');
            const eventDiv = document.createElement('div');
            eventDiv.className = 'event';
            eventDiv.textContent = '[' + new Date().toLocaleTimeString() + '] ' + JSON.stringify(event);
            eventsEl.appendChild(eventDiv);
            eventsEl.scrollTop = eventsEl.scrollHeight;
        }
        
        // Auto-connect
        connect();
    </script>
</body>
</html>
        )";
        
        std::string response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Content-Length: " + std::to_string(html.length()) + "\r\n";
        response += "\r\n";
        response += html;
        
        return response;
    }
    
    std::vector<ProcessInfo> enumerateProcesses() {
        std::vector<ProcessInfo> processes;
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            logger.logError("Failed to create process snapshot", "CreateToolhelp32Snapshot failed");
            return processes;
        }
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                ProcessInfo info;
                info.pid = pe32.th32ProcessID;
                info.name = std::string(pe32.szExeFile);
                
                // Determine architecture
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    BOOL isWow64 = FALSE;
                    if (IsWow64Process(hProcess, &isWow64)) {
                        info.architecture = isWow64 ? "x86" : "x64";
                    } else {
                        info.architecture = "Unknown";
                    }
                    CloseHandle(hProcess);
                } else {
                    info.architecture = "Unknown";
                }
                
                processes.push_back(info);
                
            } while (Process32Next(hSnapshot, &pe32));
        }
        
        CloseHandle(hSnapshot);
        
        logger.logDebug("Process enumeration completed", 
                       "Found " + std::to_string(processes.size()) + " processes");
        
        return processes;
    }
};

int main(int argc, char* argv[]) {
    // Initialize logger
    Logger& logger = Logger::getInstance();
    logger.setLogLevel(LogLevel::Info);
    logger.setLogFile("G25F_Realtime_Backend.log");
    
    logger.logInfo("G25F Injector Realtime Backend starting", "Version 1.0.0");
    
    // Check command line arguments
    int httpPort = 8080;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            httpPort = std::stoi(argv[++i]);
        }
    }
    
    logger.logInfo("Starting realtime HTTP backend", "Port: " + std::to_string(httpPort));
    
    RealtimeHttpBackend backend(httpPort);
    if (backend.start()) {
        logger.logInfo("Realtime HTTP backend started successfully", "Ready for connections");
        
        // Start the main server loop
        backend.run();
    } else {
        logger.logError("Failed to start realtime HTTP backend", "Backend initialization failed");
        return 1;
    }
    
    logger.logInfo("G25F Injector Realtime Backend shutting down", "Application exit");
    return 0;
}
