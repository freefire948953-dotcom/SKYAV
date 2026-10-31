@echo off
REM build_exe.bat
REM Compiles SkyAV into a single standalone .exe using Nuitka.

echo Checking Python installation...

REM Prefer 'python' first, since that's where project dependencies were
REM installed. Only fall back to 'py -3.12' or bare 'py' if 'python' isn't found.
python --version >nul 2>nul
if %errorlevel%==0 (
    set PYCMD=python
) else (
    py -3.12 --version >nul 2>nul
    if %errorlevel%==0 (
        set PYCMD=py -3.12
    ) else (
        py --version >nul 2>nul
        if %errorlevel%==0 (
            set PYCMD=py
        ) else (
            echo.
            echo ERROR: Python was not found via 'python' or 'py' commands.
            echo Go to Settings -^> Apps -^> Advanced app settings -^>
            echo App execution aliases, and turn OFF "python.exe"/"python3.exe"
            echo under "App Installer". Then try this script again.
            echo.
            pause
            exit /b 1
        )
    )
)

echo Using: %PYCMD%
%PYCMD% -c "import sys; print('Python version:', sys.version)"
echo.
echo Installing project dependencies + Nuitka into this exact environment...
%PYCMD% -m pip install -r requirements.txt --quiet
%PYCMD% -m pip install nuitka --quiet

echo.
echo Compiling SkyAV.exe — this takes a few minutes, please wait...
echo.

%PYCMD% -m nuitka ^
    --standalone ^
    --onefile ^
    --windows-console-mode=disable ^
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
    --output-filename=SkyAV.exe ^
    --output-dir=dist ^
    main.py

echo.
echo Done! Your compiled SkyAV.exe is in the "dist" folder.
echo This single file is what you share with others -- it does NOT
echo include any of your .py source files, and cannot be opened in a
echo text editor to read the code.
echo.
pause
