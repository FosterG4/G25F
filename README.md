# 🚀 G25F Injector

A DLL injector with electron GUI.

## ✨ Features

- **Multiple Injection Methods** - LoadLibrary, CreateRemoteThread, ManualMap, SetWindowsHook
- **GUI** - Electron-based interface with real-time updates
- **Realtime Backend** - HTTP server with Server-Sent Events for live updates
- **Process Management** - Real-time process enumeration and monitoring
- **Installer** - Windows installer with automatic admin elevation
- **Cross-Platform GUI** - web-based interface

## 🏗️ Project Structure

```
G25F/
├── G25F_Injector.exe              ← Console application
├── G25F_Injector_Backend.exe      ← HTTP server with realtime capabilities
├── electron/                       ← GUI interface
├── include/                        ← Header files
├── src/                           ← Source code
│   ├── backend.cpp                ← Single backend (HTTP + SSE)
│   ├── Injector.cpp               ← Core injection logic
│   ├── ProcessUtils.cpp           ← Process management
│   ├── Logger.cpp                 ← Logging system
│   └── Main.cpp                   ← Console entry point
├── lib/                           ← Library files
├── build.bat                      ← Single build command
└── build/                         ← Build output
```

## 🚀 Quick Start

### For Users
1. **Download** the installer: `G25F-Injector-Setup.exe`
2. **Double-click** to install
3. **Run** from desktop shortcut or start menu
4. **Enjoy** DLL injection tool

### For Developers
1. **Clone** the repository
2. **Run one command**: `build.bat`
3. **Get everything**: Installer, portable version, and all executables

## 🛠️ Building

### Prerequisites
- Visual Studio 2019+ with C++ support
- Windows SDK 10.0+
- CMake 3.20+
- Node.js (for Electron GUI)
- Git (for dependencies)

### 🎯 **One Command Build**

```bash
# Everything in one command!
build.bat
```

This single command will:
- ✅ **Install dependencies** automatically (JSON library)
- ✅ **Build C++ backend** with CMake + MSBuild
- ✅ **Build console app** 
- ✅ **Install Electron dependencies** with npm
- ✅ **Create Windows installer** with electron-builder
- ✅ **Generate portable version**

### 📁 Output Files

After running `build.bat`, you'll get:
```
build/
├── Release/
│   ├── G25F_Injector.exe              ← Console application
│   └── G25F_Injector_Backend.exe      ← HTTP server
└── electron/
    ├── G25F-Injector-Setup.exe        ← Windows installer
    └── G25F-Injector-Portable.exe     ← Portable version
```

## 📡 Backend API

The backend provides HTTP endpoints:
- `GET /api/processes` - List running processes
- `POST /api/inject` - Inject DLL into process
- `GET /api/status` - Server status
- `GET /api/logs` - Recent logs
- `GET /api/events` - Server-Sent Events for real-time updates

## 🎮 GUI Features

- **Process List** - Real-time process enumeration
- **DLL Injection** - Multiple injection methods
- **Progress Tracking** - Live injection progress updates
- **Log Viewer** - Real-time log monitoring
- **Settings** - Configurable injection options

## 🔧 Technical Details

- **C++ Backend** - High-performance injection engine
- **libmem Integration** - Advanced memory manipulation
- **HTTP Server** - RESTful API with SSE support
- **Electron GUI** - responsive interface
- **Windows API** - Native Windows integration

## 📦 Distribution

- **Windows Installer** - MSI-style installer
- **Portable Version** - Single executable for advanced users
- **Clean Install** - Proper installation/uninstallation

## 🎉 Build System Benefits

- **Single Command** - `build.bat` does everything
- **Automatic Dependencies** - Installs JSON library automatically
- **Integrated Build** - CMake + MSBuild + npm in one flow
- **Professional Output** - Ready-to-distribute installer
- **Error Handling** - Clear feedback and troubleshooting

## 📄 License

This project is licensed under the MIT License.

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines.

---

**G25F Injector** - DLL injection! 🎯