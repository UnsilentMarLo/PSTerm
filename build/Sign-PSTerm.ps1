<#
.SYNOPSIS
    Authenticode-sign PSTerm's scripts.

.DESCRIPTION
    Signing is optional. It matters when PSTerm is deployed somewhere with an
    execution policy of AllSigned or RemoteSigned, where unsigned scripts are
    refused. PSTerm.cmd passes -ExecutionPolicy Bypass for its own process, so an
    unsigned copy still runs for an ordinary user.

    A self-signed certificate is created if none exists. Be clear about what that
    buys: a self-signed certificate is only trusted on machines where it has been
    installed into Trusted Publishers. It proves the files have not changed since
    signing; it does not vouch for who produced them. For anything beyond a lab,
    use a certificate from a CA your organisation already trusts.

    This replaces v1's Cert.ps1, which signed only the single root script - and
    did so while the build packaged a different copy from src\, so the file that
    shipped was never the file that got signed.

.PARAMETER Path
    Folder whose .ps1 files should be signed. Defaults to the repository root.

.PARAMETER CertificateSubject
    Subject of the code-signing certificate to use or create.

.EXAMPLE
    .\build\Sign-PSTerm.ps1 -Path .\dist\PSTerm
#>
[CmdletBinding()]
param(
    [string]$Path,
    [string]$CertificateSubject = 'CN=PSTerm Code Signing'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $Path) { $Path = Split-Path -Parent $PSScriptRoot }

if (-not (Test-Path -LiteralPath $Path)) {
    throw "Path not found: $Path"
}

# ---------------------------------------------------------- certificate -----

$certificate = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $CertificateSubject -and $_.NotAfter -gt (Get-Date) } |
    Select-Object -First 1

if (-not $certificate) {
    $certificate = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
        Where-Object { $_.NotAfter -gt (Get-Date) } |
        Select-Object -First 1
}

if (-not $certificate) {
    Write-Host "No code-signing certificate found; creating a self-signed one." -ForegroundColor Yellow
    Write-Host "It will only be trusted on machines where you install it into Trusted Publishers." -ForegroundColor Yellow

    $certificate = New-SelfSignedCertificate `
        -Subject $CertificateSubject `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyAlgorithm RSA -KeyLength 3072 `
        -KeyUsage DigitalSignature `
        -Type CodeSigningCert `
        -NotBefore (Get-Date) `
        -NotAfter (Get-Date).AddYears(3) `
        -ErrorAction Stop
}

Write-Host "Certificate: $($certificate.Subject)  (expires $($certificate.NotAfter.ToString('yyyy-MM-dd')))" -ForegroundColor Cyan

# --------------------------------------------------------------- sign -------

# Every shipped script, not just the entry point: PSTerm.ps1 dot-sources the
# rest, and under AllSigned each of those files is checked in turn.
$scripts = @(Get-ChildItem -LiteralPath $Path -Filter '*.ps1' -Recurse -File |
    Where-Object { $_.FullName -notmatch '\\(bin|dist|tests)\\' })

if ($scripts.Count -eq 0) {
    Write-Warning "No .ps1 files found under '$Path'."
    return
}

$signed = 0
$failed = 0

foreach ($script in $scripts) {
    try {
        $result = Set-AuthenticodeSignature -FilePath $script.FullName -Certificate $certificate `
            -HashAlgorithm SHA256 -ErrorAction Stop
        if ($result.Status -eq 'Valid') {
            $signed++
            Write-Verbose "Signed $($script.Name)"
        }
        else {
            $failed++
            Write-Warning "$($script.Name): $($result.StatusMessage)"
        }
    }
    catch {
        $failed++
        Write-Warning "$($script.Name): $($_.Exception.Message)"
    }
}

Write-Host "Signed $signed file(s)." -ForegroundColor Green
if ($failed -gt 0) { Write-Warning "$failed file(s) could not be signed." }

# Export the public certificate so it can be installed on target machines.
$exportPath = Join-Path $Path 'PSTerm-Certificate.cer'
try {
    [System.IO.File]::WriteAllBytes(
        $exportPath,
        $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    Write-Host "Public certificate exported to $exportPath" -ForegroundColor Green
    Write-Host "To trust it on another machine:" -ForegroundColor DarkGray
    Write-Host "  Import-Certificate -FilePath PSTerm-Certificate.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher" -ForegroundColor DarkGray
}
catch {
    Write-Warning "Could not export the certificate: $($_.Exception.Message)"
}
