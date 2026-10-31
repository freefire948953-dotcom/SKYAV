' Create_Desktop_Shortcut.vbs
' Run this ONCE to create a SkyAV shortcut on your Desktop with the
' custom logo icon (a plain "Send to Desktop" shortcut would show a
' generic script icon instead).

Dim fso, scriptDir, WshShell, desktopPath, shortcut

Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)

Set WshShell = CreateObject("WScript.Shell")
desktopPath = WshShell.SpecialFolders("Desktop")

Set shortcut = WshShell.CreateShortcut(desktopPath & "\SkyAV.lnk")
shortcut.TargetPath = "wscript.exe"
shortcut.Arguments = """" & scriptDir & "\Launch_SkyAV.vbs"""
shortcut.WorkingDirectory = scriptDir
shortcut.IconLocation = scriptDir & "\assets\icon.ico"
shortcut.Description = "SkyAV - Custom Antivirus"
shortcut.Save

MsgBox "Desktop shortcut created! Look for 'SkyAV' on your Desktop.", 64, "SkyAV"
