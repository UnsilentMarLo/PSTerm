<# ps2exe [-inputFile] '<file_name>' [[-outputFile] '<file_name>']
       [-prepareDebug] [-x86|-x64] [-lcid <id>] [-STA|-MTA] [-noConsole] [-conHost] [-UNICODEEncoding]
       [-credentialGUI] [-iconFile '<filename>'] [-title '<title>'] [-description '<description>']
       [-company '<company>'] [-product '<product>'] [-copyright '<copyright>'] [-trademark '<trademark>']
       [-version '<version>'] [-configFile] [-noOutput] [-noError] [-noVisualStyles] [-exitOnCancel]
       [-DPIAware] [-requireAdmin] [-supportOS] [-virtualize] [-longPaths]
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
