' Launch_SkyAV.vbs
' Double-click this to open SkyAV with no console window flashing,
' and no dependency on pythonw.exe being registered in PATH.

Dim fso, scriptDir, WshShell

Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)

Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = scriptDir

' 0 = fully hidden window, False = don't wait for it to finish
WshShell.Run "python.exe """ & scriptDir & "\main.py"" --gui", 0, False
