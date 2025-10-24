<#
    PSTerm - A powerful native PowerShell Serial/SSH/Telnet Terminal.
    Copyright (C) 2025 Marlo K <Plays.xenon@yahoo.de>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#>
# Ensure the script stops on errors
$ErrorActionPreference = "Stop"

# Get the root path of the script
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Paths
$CompileFolder = Join-Path $ScriptRoot "Compile"
$SrcFolder     = Join-Path $ScriptRoot "src"
$OutputFolder  = Join-Path $ScriptRoot "PSTerm-Compiled"
$MainScript    = Join-Path $SrcFolder "PSTerm.ps1"
$OutputExe     = Join-Path $OutputFolder "PSTerm.exe"

# Ensure the output folder exists
if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}

# Ensure ps2exe module is available
if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Install-Module ps2exe -Scope CurrentUser -Force
}

# Import the module
Import-Module (Join-Path $CompileFolder "ps2exe.psm1")

# Compile with ps2exe
Invoke-ps2exe -inputFile $MainScript `
              -outputFile $OutputExe `
              -x64 `
			  -conHost `
              -iconFile "$SrcFolder\icon.ico" `
              -title "PowerShell Terminal" `
              -description "A powerful native PowerShell Serial/SSH Terminal compiled with ps2exe" `
              -version "5.0.0.0"

Write-Host "Compilation complete: $OutputExe"

# Define source and target
$SourceLibFolder = Join-Path $SrcFolder "lib"
$TargetLibFolder = Join-Path $OutputFolder "lib"

# Remove old lib folder (optional cleanup)
if (Test-Path $TargetLibFolder) {
    Remove-Item $TargetLibFolder -Recurse -Force
}

# Copy lib folder
if (Test-Path $SourceLibFolder) {
    Copy-Item -Path $SourceLibFolder -Destination $TargetLibFolder -Recurse -Force
    Write-Host "Copied lib folder to output: $TargetLibFolder" -ForegroundColor Green
} else {
    Write-Warning "Source lib folder not found: $SourceLibFolder"
}
