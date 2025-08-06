<#
.SYNOPSIS
    Signs the script.
#>

Set-Strictmode -Version Latest

$scriptDirectory = $PSScriptRoot

$targetScriptPath = Join-Path -Path $scriptDirectory -ChildPath "PSTerm.ps1"
$certificateExportPath = Join-Path -Path $scriptDirectory -ChildPath "PSTerm-Certificate.cer"

if (-not (Test-Path -Path $targetScriptPath)) {
    Write-Host -ForegroundColor Red "ERROR: The source file '$targetScriptPath' cant be found."
    exit 1
}
 
Write-Host "Source file found: $targetScriptPath"

Write-Host "searching for a valid certificate..."
$certificate = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1

if ($null -eq $certificate) {
    Write-Host -ForegroundColor Yellow "No certificate found, creating new self signed certificate..."

    $certParams = @{
        Subject = "CN=PSTerm Code Signing Certificate"
        CertStoreLocation = "Cert:\CurrentUser\My"
        KeyAlgorithm = "RSA"
        KeyLength = 2048
        KeyUsage = "DigitalSignature"
        Type = "CodeSigningCert"
        NotAfter = (Get-Date).AddYears(5)
        NotBefore = (Get-Date)
    }

    try {
        $certificate = New-SelfSignedCertificate @certParams -ErrorAction Stop
        Write-Host -ForegroundColor Green "Created new certificate. ✅"
    }
    catch {
        Write-Host -ForegroundColor Red "ERROR while creating certificate: $($_.Exception.Message)"
        exit 1
    }
}

Write-Host -ForegroundColor Cyan "using certificate: $($certificate.Subject) ($($certificate.FriendlyName))"

try {
    $bytes = $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    [System.IO.File]::WriteAllBytes($certificateExportPath, $bytes)
}
catch {
    Write-Host -ForegroundColor Red "ERROR while exporting certificate: $($_.Exception.Message)"
    exit 1
}

try {
    Set-AuthenticodeSignature -FilePath $targetScriptPath -Certificate $null -ErrorAction Stop
    Write-Host -ForegroundColor Green "Existing Certificate has been removed."
}
catch {
    Write-Host -ForegroundColor Yellow "No old Signature found."
}

try {
    Write-Host "Signing script..."
    Set-AuthenticodeSignature -FilePath $targetScriptPath -Certificate $certificate -ErrorAction Stop

    Write-Host -ForegroundColor Green "SUCCESS! 'PSTerm.ps1' has been signed. ✅"
}
catch {
    Write-Host -ForegroundColor Red "ERROR while signing: $($_.Exception.Message)"
    exit 1
}