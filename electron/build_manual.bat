@echo off
echo Building G25F Injector Standalone (Manual Build)...
echo.

REM Create output directory
if not exist "..\build\electron" mkdir "..\build\electron"
if not exist "..\build\electron\win-unpacked" mkdir "..\build\electron\win-unpacked"

REM Copy application files
echo Copying application files...
xcopy /E /I /Y "*.js" "..\build\electron\win-unpacked\"
xcopy /E /I /Y "*.html" "..\build\electron\win-unpacked\"
xcopy /E /I /Y "*.css" "..\build\electron\win-unpacked\"
xcopy /E /I /Y "assets" "..\build\electron\win-unpacked\assets\"

REM Copy backend executable
echo Copying backend executable...
if not exist "..\build\electron\win-unpacked\resources" mkdir "..\build\electron\win-unpacked\resources"
if not exist "..\build\electron\win-unpacked\resources\backend" mkdir "..\build\electron\win-unpacked\resources\backend"
copy "..\build\Release\G25F_Injector_Backend.exe" "..\build\electron\win-unpacked\resources\backend\"

REM Copy Electron runtime files
echo Copying Electron runtime...
copy "node_modules\electron\dist\electron.exe" "..\build\electron\win-unpacked\G25F Injector.exe"

REM Create launcher script
echo Creating launcher script...
echo @echo off > "..\build\electron\G25F-Injector-Standalone.bat"
echo cd /d "%~dp0win-unpacked" >> "..\build\electron\G25F-Injector-Standalone.bat"
echo start "" "G25F Injector.exe" >> "..\build\electron\G25F-Injector-Standalone.bat"

echo.
echo Manual build completed!
echo Standalone executable: ..\build\electron\G25F-Injector-Standalone.bat
echo.
pause
