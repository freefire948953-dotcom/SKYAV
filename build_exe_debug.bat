@echo off
REM build_exe_debug.bat — same as build_exe.bat but keeps the console
REM window visible so any error messages stay readable.

python --version >nul 2>nul
if %errorlevel%==0 (
    set PYCMD=python
) else (
    py -3.12 --version >nul 2>nul
    if %errorlevel%==0 (
        set PYCMD=py -3.12
    ) else (
        set PYCMD=py
    )
)

echo Using: %PYCMD%
%PYCMD% -c "import sys; print('Python version:', sys.version)"
echo.
echo Installing project dependencies + Nuitka into this exact environment...
%PYCMD% -m pip install -r requirements.txt --quiet
%PYCMD% -m pip install nuitka --quiet

echo.
echo Compiling SkyAV_debug.exe (with visible console for error messages)...
echo.

%PYCMD% -m nuitka ^
    --standalone ^
    --onefile ^
    --enable-plugin=tk-inter ^
    --include-module=watchdog.observers ^
    --include-module=yara ^
    --include-module=pefile ^
    --include-module=psutil ^
    --include-module=pystray ^
    --include-module=PIL ^
    --include-module=oletools ^
    --windows-icon-from-ico=assets\icon.ico ^
    --include-data-dir=assets=assets ^
    --output-filename=SkyAV_debug.exe ^
    --output-dir=dist ^
    main.py

echo.
echo Done. Now run: dist\SkyAV_debug.exe
echo directly from THIS cmd window (not double-click) so any error
echo message stays visible instead of the window closing instantly.
echo.
pause
