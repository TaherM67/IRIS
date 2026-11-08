<# Create a localhost-only HTTPS certificate. Does not install or trust it. #>
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) '.local\active_demo\tls')
)
$ErrorActionPreference = 'Stop'

function Write-PemFile([string]$Path, [string]$Label, [byte[]]$Bytes) {
    $encoded = [Convert]::ToBase64String($Bytes, [Base64FormattingOptions]::InsertLineBreaks)
    $content = "-----BEGIN $Label-----`r`n$encoded`r`n-----END $Label-----`r`n"
    # Exclusive creation prevents replacing an existing certificate or key.
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytesToWrite = [Text.Encoding]::ASCII.GetBytes($content)
        $stream.Write($bytesToWrite, 0, $bytesToWrite.Length)
    } finally { $stream.Dispose() }
}

$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
if ((Split-Path -Leaf $outputPath) -eq '') { throw 'Choose a certificate output directory.' }
[IO.Directory]::CreateDirectory($outputPath) | Out-Null
$certPath = Join-Path $outputPath 'localhost-cert.pem'
$keyPath = Join-Path $outputPath 'localhost-key.pem'
if ((Test-Path -LiteralPath $certPath) -or (Test-Path -LiteralPath $keyPath)) {
    throw 'Certificate/key files already exist. They were not replaced. Choose a new output directory to renew.'
}
if (@(Get-ChildItem -LiteralPath $outputPath -Force).Count -ne 0) {
    throw 'Choose an empty output directory; permissions on existing unrelated files will not be changed.'
}

# Limit access to this Windows account and SYSTEM, before writing the key.
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
$taskUser = [Security.Principal.WindowsIdentity]::GetCurrent().User
foreach ($sid in @($taskUser, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $outputPath -AclObject $acl

$rsa = [Security.Cryptography.RSACng]::new(2048)
$certificate = $null
try {
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=localhost', $rsa, [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $names = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $names.AddDnsName('localhost')
    $names.AddIpAddress([Net.IPAddress]::Parse('127.0.0.1'))
    $request.CertificateExtensions.Add($names.Build())
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
    $usage = [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($usage, $true))
    $purposes = [Security.Cryptography.OidCollection]::new()
    $purposes.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1')) | Out-Null
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($purposes, $false))
    $now = [DateTimeOffset]::UtcNow
    $certificate = $request.CreateSelfSigned($now.AddMinutes(-5), $now.AddDays(90))
    Write-PemFile $keyPath 'PRIVATE KEY' ($rsa.Key.Export([Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob))
    Write-PemFile $certPath 'CERTIFICATE' $certificate.RawData
    [pscustomobject]@{
        CertificateFile = $certPath
        KeyFile = $keyPath
        Subject = $certificate.Subject
        Thumbprint = $certificate.Thumbprint
        ExpiresUtc = $certificate.NotAfter.ToUniversalTime().ToString('o')
        Trusted = $false
        Note = 'Created files only. No Windows certificate store was changed.'
    } | ConvertTo-Json
} finally {
    if ($null -ne $certificate) { $certificate.Dispose() }
    $rsa.Dispose()
}
