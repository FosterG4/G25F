#pragma once
#include <string>
#include <set>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <chrono>

// Include ASIO compatibility layer BEFORE websocketpp
#include "websocketpp_asio_compat.h"
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>

// Forward declarations
class Logger;

class WebSocketServer {
public:
    using WsServer = websocketpp::server<websocketpp::config::asio>;
    using ConnectionHdl = websocketpp::connection_hdl;
    using MessagePtr = WsServer::message_ptr;
    
    // Message types for real-time updates
    enum class MessageType {
        INJECTION_START,
        INJECTION_PROGRESS,
        INJECTION_COMPLETE,
        INJECTION_ERROR,
        PROCESS_UPDATE,
        LOG_UPDATE,
        STATUS_UPDATE,
        ERROR_UPDATE
    };
    
    struct WebSocketMessage {
        MessageType type;
        std::string data;
        std::string processName;
        std::string dllPath;
        std::string details;
        std::chrono::system_clock::time_point timestamp;
    };
    
    WebSocketServer(int port = 8081);
    ~WebSocketServer();
    
    // Server control
    bool start();
    void stop();
    bool isRunning() const;
    
    // Message broadcasting
    void broadcastMessage(const WebSocketMessage& message);
    void broadcastToProcess(const std::string& processName, const WebSocketMessage& message);
    void sendToConnection(ConnectionHdl hdl, const WebSocketMessage& message);
    
    // Convenience methods for common message types
    void broadcastInjectionStart(const std::string& processName, const std::string& dllPath);
    void broadcastInjectionProgress(const std::string& processName, const std::string& dllPath, int progress);
    void broadcastInjectionComplete(const std::string& processName, const std::string& dllPath, bool success);
    void broadcastInjectionError(const std::string& processName, const std::string& dllPath, const std::string& error);
    void broadcastProcessUpdate(const std::string& processName, const std::string& status);
    void broadcastLogUpdate(const std::string& logEntry);
    void broadcastStatusUpdate(const std::string& status);
    void broadcastErrorUpdate(const std::string& error);
    
    // Connection management
    size_t getConnectionCount() const;
    std::vector<std::string> getConnectedClients() const;
    
    // Event handlers
    void setOnConnectionOpen(std::function<void(ConnectionHdl)> callback);
    void setOnConnectionClose(std::function<void(ConnectionHdl)> callback);
    void setOnMessage(std::function<void(ConnectionHdl, MessagePtr)> callback);
    
private:
    // WebSocket event handlers
    void onOpen(ConnectionHdl hdl);
    void onClose(ConnectionHdl hdl);
    void onMessage(ConnectionHdl hdl, MessagePtr msg);
    void onFail(ConnectionHdl hdl);
    
    // Message serialization
    std::string serializeMessage(const WebSocketMessage& message);
    
public:
    WebSocketMessage deserializeMessage(const std::string& data);
    
private:
    
    // Internal helpers
    void runServer();
    void cleanupConnections();
    
    // Server instance
    std::unique_ptr<WsServer> wsServer;
    std::thread serverThread;
    
    // Connection management
    std::set<ConnectionHdl, std::owner_less<ConnectionHdl>> connections;
    mutable std::mutex connectionsMutex;
    
    // Configuration
    int port;
    bool running;
    
    // Event callbacks
    std::function<void(ConnectionHdl)> onConnectionOpen;
    std::function<void(ConnectionHdl)> onConnectionClose;
    std::function<void(ConnectionHdl, MessagePtr)> onMessageCallback;
    
    // Logger reference
    Logger* logger;
};
