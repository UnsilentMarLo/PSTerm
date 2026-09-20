@echo off
rem PSTerm launcher.
rem
rem Runs the UI under Windows PowerShell, which is present on every Windows
rem install, so the folder can be copied to a machine and simply run. -STA is
rem required for WinForms (the clipboard and common dialogs need it), and
rem -NoProfile keeps someone's profile script out of the startup path.
rem
rem Set PSTERM_KEEP_CONSOLE=1 first if you want the console kept for diagnostics.

setlocal
set "PSTERM_DIR=%~dp0"
start "" /b powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%PSTERM_DIR%PSTerm.ps1" %*
endlocal
