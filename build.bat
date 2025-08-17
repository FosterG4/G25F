@echo off
setlocal enabledelayedexpansion

echo ========================================
echo G25F Injector - Automated Build System
echo ========================================
echo.

REM Set colors for output
set "GREEN=[92m"
set "YELLOW=[93m"
set "RED=[91m"
set "BLUE=[94m"
set "RESET=[0m"

REM Check if external dependencies exist
if not exist "external\json" (
    echo %RED%[ERROR]%RESET% nlohmann/json not found in external/ directory
    echo %YELLOW%[INFO]%RESET% Installing dependencies...
    if not exist "external" mkdir external
    git clone https://github.com/nlohmann/json.git external/json
    if %ERRORLEVEL% neq 0 (
        echo %RED%[ERROR]%RESET% Failed to clone JSON dependency
        pause
        exit /b 1
    )
    echo %GREEN%[SUCCESS]%RESET% Dependencies installed
) else (
    echo %GREEN%[INFO]%RESET% Dependencies found
)

echo.

REM Build the C++ backend and console app
echo %BLUE%[BUILD]%RESET% Building C++ components...
if not exist "build" mkdir build
cd build

echo %YELLOW%[INFO]%RESET% Configuring with CMake...
cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release
if %ERRORLEVEL% neq 0 (
    echo %RED%[ERROR]%RESET% CMake configuration failed
    pause
    exit /b 1
)

echo %YELLOW%[INFO]%RESET% Building with MSBuild...
cmake --build . --config Release
if %ERRORLEVEL% neq 0 (
    echo %RED%[ERROR]%RESET% Build failed
    pause
    exit /b 1
)

echo %GREEN%[SUCCESS]%RESET% C++ components built successfully!
cd ..

REM Build the Electron installer
echo.
echo %BLUE%[BUILD]%RESET% Building Windows installer...
cd electron

echo %YELLOW%[INFO]%RESET% Installing Electron dependencies...
call npm install
if %ERRORLEVEL% neq 0 (
    echo %RED%[ERROR]%RESET% npm install failed
    pause
    exit /b 1
)

echo %YELLOW%[INFO]%RESET% Building Windows installer...
call npm run build:installer
if %ERRORLEVEL% neq 0 (
    echo %RED%[ERROR]%RESET% Installer build failed
    pause
    exit /b 1
)

echo %GREEN%[SUCCESS]%RESET% Windows installer built successfully!

echo %YELLOW%[INFO]%RESET% Building portable version...
call npm run build:portable
if %ERRORLEVEL% neq 0 (
    echo %RED%[ERROR]%RESET% Portable build failed
    pause
    exit /b 1
)

echo %GREEN%[SUCCESS]%RESET% Portable version built successfully!
cd ..

echo.
echo ========================================
echo %GREEN%BUILD COMPLETED SUCCESSFULLY!%RESET%
echo ========================================
echo.

echo %GREEN%[SUCCESS]%RESET% Your Windows installer is ready:
echo   - Installer: %BLUE%build\electron\G25F-Injector-Setup.exe%RESET%
echo   - Portable: %BLUE%build\electron\G25F-Injector-Portable.exe%RESET%
echo.

echo %GREEN%[SUCCESS]%RESET% C++ components built:
echo   - Console App: %BLUE%build\Release\G25F_Injector.exe%RESET%
echo   - Backend Server: %BLUE%build\Release\G25F_Injector_Backend.exe%RESET%
echo.

echo %YELLOW%[INFO]%RESET% Users can now:
echo   1. Double-click the installer
echo   2. Choose installation directory
echo   3. Get desktop and start menu shortcuts
echo   4. Run with admin privileges automatically
echo.

echo %BLUE%[BUILD]%RESET% Build completed in: %TIME%
echo %GREEN%[READY]%RESET% Project is ready for distribution!
echo.

pause
