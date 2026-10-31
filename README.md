SkyAV - Antivirus Software for Windows

SkyAV is a Windows antivirus and security monitoring tool written in Python. It combines hash signatures, heuristic analysis, YARA rules and PE file inspection to detect malware, and adds real-time protection for downloads, USB drives, startup entries and running processes. It has both a command-line interface and a Tkinter desktop GUI.

Note: SkyAV is a learning and portfolio project. It is not a replacement for a commercial antivirus.

<!-- TODO: add 2-3 screenshots of the GUI here, e.g. ![SkyAV GUI](screenshots/gui.png) -->
Features
Scanning
Quick, Full and Custom scans (common malware hotspots, all drives, or a folder you choose)
Signature detection using a SHA-256 hash database that can be updated daily from MalwareBazaar
Heuristic analysis for malware with no known signature (entropy, suspicious patterns, PE header checks)
YARA rules for family-based detection (rules go in data/rules.yar)
Office macro scanner for malicious VBA macros (via oletools)
Digital signature check to avoid flagging trusted, signed software
VirusTotal cross-check of flagged files to reduce false positives
Real-time protection
Folder monitor that scans new or modified files instantly
Download guard that scans a file as soon as a download finishes in the Downloads folder
USB guard that scans removable drives the moment they are plugged in
Ransomware honeypot with hidden trap files in common attack locations
Registry and startup guard that alerts on new persistence entries
Scheduled task scanner that flags suspicious Windows scheduled tasks
Command-line monitor that watches new processes and decodes encoded PowerShell
Process monitor that checks running processes for RAT-like behavior
Network monitor that checks outbound connections against abuse.ch threat feeds
Browser guard that detects hosts-file tampering, unknown extensions and homepage hijacks
Self-protection that watches SkyAV's own files for tampering
Response and alerts
Quarantine with restore and permanent delete (files are moved and renamed so they cannot run)
System Restore Point creation before risky actions
Whitelist to mark trusted files as safe
Remote alerts through Telegram, a Discord webhook or email
AI explanations of flagged files in plain language, with a built-in fallback when the API is unavailable
Tech Stack
Area	Technology
Language	Python 3
GUI	Tkinter, pystray (system tray), Pillow
Detection	yara-python, pefile, oletools
System monitoring	psutil, watchdog, pywin32
Networking	requests
Scheduling	schedule
Packaging	Nuitka (build_exe.bat)
Getting Started

Requirements: Windows 10/11 and Python 3 (3.12 recommended).

bash
git clone https://github.com/freefire948953-dotcom/SKYAV.git
cd SKYAV
pip install -r requirements.txt

Launch the GUI:

bash
python main.py --gui

Or double-click Launch_SkyAV.vbs to open it without a console window. Create_Desktop_Shortcut.vbs creates a desktop shortcut.

Command-Line Usage
bash
python main.py --quick                          # Quick scan
python main.py --full                           # Full system scan
python main.py --custom "D:\Downloads"          # Scan one folder
python main.py --quick --auto-quarantine        # Quarantine threats automatically
python main.py --protect                        # Start real-time protection
python main.py --update                         # Download the latest malware signatures
python main.py --list-quarantine                # List quarantined files
python main.py --restore q_1234567890           # Restore a quarantined file
python main.py --processes                      # Scan running processes
python main.py --history                        # Show recent scan history
python main.py --help                           # See all options
Optional setup
Feature	Command
VirusTotal cross-check	python main.py --set-vt-key YOUR_API_KEY then --check-vt
Telegram alerts	python main.py --set-telegram TOKEN CHAT_ID
Discord webhook alerts	python main.py --set-discord-webhook URL
Email alerts	python main.py --set-email SENDER APP_PASSWORD RECIPIENT
Start with Windows	python main.py --register-startup
Quick scan at every login	python main.py --register-boot-scan
Daily signature updates	python main.py --auto-update
Build a Standalone .exe
bash
build_exe.bat

This installs the dependencies and Nuitka, then compiles SkyAV into a single executable. Data such as quarantine, whitelist and scan history is stored next to the .exe.

Project Structure
File	Purpose
main.py	Command-line entry point
gui.py, tray_icon.py	Tkinter GUI and system tray
scanner.py, signatures.py	Scan engine and signature database
heuristics.py, pe_analyzer.py, yara_scanner.py, macro_scanner.py	Detection engines
monitor.py, download_guard.py, usb_guard.py	Real-time file protection
registry_guard.py, task_scanner.py, startup_manager.py	Persistence detection
process_monitor.py, cmd_monitor.py, network_monitor.py	Behavior monitoring
honeypot.py, self_protect.py, browser_guard.py	Ransomware, tamper and browser protection
quarantine.py, whitelist.py, restore_point.py	Response and recovery
virustotal.py, ai_explain.py, alerts.py, updater.py	Integrations and updates
Disclaimer

SkyAV is built for learning and personal use. Test it only on systems you own. Detection is not guaranteed, and legitimate files can be flagged by mistake, so review results before deleting anything.

Author

Shubham Kumar Yadav LinkedIn
