@echo off
rem PSTerm launcher.
rem
rem Runs the UI under Windows PowerShell, which is present on every Windows
rem install, so the folder can be copied to a machine and simply run. -STA is
rem required for WinForms (the clipboard and common dialogs need it), and
rem -NoProfile keeps someone's profile script out of the startup path.
rem
rem Set PSTERM_KEEP_CONSOLE=1 first to run in this console instead, with its
rem output visible, for diagnostics. The command prompt stays busy until PSTerm
rem exits.

setlocal
set "PSTERM_DIR=%~dp0"

if defined PSTERM_KEEP_CONSOLE goto keep

start "" /b powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%PSTERM_DIR%PSTerm.ps1" %*
goto done

:keep
powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -STA -File "%PSTERM_DIR%PSTerm.ps1" %*

:done
endlocal
