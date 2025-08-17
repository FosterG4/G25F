@echo off
echo ========================================
echo G25F Injector - Dependencies Setup
echo ========================================
echo.

REM Create external directory if it doesn't exist
if not exist "external" (
    echo [INFO] Creating external directory...
    mkdir external
)

REM Check if websocketpp exists
if not exist "external\websocketpp" (
    echo [INFO] Cloning websocketpp...
    git clone https://github.com/zaphoyd/websocketpp.git external/websocketpp
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Failed to clone websocketpp
        pause
        exit /b 1
    )
) else (
    echo [INFO] websocketpp already exists
)

REM Check if json exists
if not exist "external\json" (
    echo [INFO] Cloning nlohmann/json...
    git clone https://github.com/nlohmann/json.git external/json
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Failed to clone nlohmann/json
        pause
        exit /b 1
    )
) else (
    echo [INFO] nlohmann/json already exists
)

REM Check if asio exists
if not exist "external\asio" (
    echo [INFO] Cloning asio...
    git clone https://github.com/chriskohlhoff/asio.git external/asio
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Failed to clone asio
        pause
        exit /b 1
    )
) else (
    echo [INFO] asio already exists
)

echo.
echo ========================================
echo DEPENDENCIES SETUP COMPLETED!
echo ========================================
echo.
echo All required external libraries are now available.
echo You can now run: build_release.bat
echo.
pause
