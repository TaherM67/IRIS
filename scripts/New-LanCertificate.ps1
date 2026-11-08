<# Create/reuse a Windows-user-protected LAN CA and issue a LAN server certificate.
   No certificate is installed in an OS trust store. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Address,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string]$CaDirectory=(Join-Path (Split-Path -Parent $PSScriptRoot) '.local\active_demo\lan-ca')
)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security
$ip=[Net.IPAddress]::Parse($Address)
if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    $Address -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)') {
    throw 'The LAN certificate requires a private IPv4 address.'
}
function Private-Directory([string]$Path,[switch]$RequireEmpty) {
    [IO.Directory]::CreateDirectory($Path) | Out-Null
    if ($RequireEmpty -and @(Get-ChildItem -LiteralPath $Path -Force).Count -ne 0) { throw 'Use a new empty certificate directory.' }
    $user=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @($user,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function New-BytesFile([string]$Path,[byte[]]$Bytes) {
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($Bytes,0,$Bytes.Length) } finally { $stream.Dispose() }
}
function New-PemFile([string]$Path,[string]$Label,[byte[]]$Bytes) {
    $encoded=[Convert]::ToBase64String($Bytes,[Base64FormattingOptions]::InsertLineBreaks)
    New-BytesFile $Path ([Text.Encoding]::ASCII.GetBytes("-----BEGIN $Label-----`r`n$encoded`r`n-----END $Label-----`r`n"))
}
function Add-ServerExtensions($Request) {
    $Request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false,$false,0,$true))
    $usage=[Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment
    $Request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($usage,$true))
    $purpose=[Security.Cryptography.OidCollection]::new();$purpose.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1')) | Out-Null
    $Request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($purpose,$false))
    $Request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($Request.PublicKey,$false))
}
$CaDirectory=[IO.Path]::GetFullPath($CaDirectory)
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
$protectedPath=Join-Path $CaDirectory 'root-ca.pfx.dpapi'
$caPath=Join-Path $CaDirectory 'root-ca.pem'
if (-not (Test-Path -LiteralPath $protectedPath)) { Private-Directory $CaDirectory -RequireEmpty }
else { Private-Directory $CaDirectory }
Private-Directory $OutputDirectory -RequireEmpty
$entropy=[Text.Encoding]::UTF8.GetBytes('IRIS LAN certificate authority v1')
$ca=$null;$rootRsa=$null;$rsa=$null;$leaf=$null
$now=[DateTimeOffset]::UtcNow
try {
    if (Test-Path -LiteralPath $protectedPath) {
        $pfx=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($protectedPath),$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
        try {
            $flags=[Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet -bor [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
            $ca=[Security.Cryptography.X509Certificates.X509Certificate2]::new($pfx,'',$flags)
        } finally { [Array]::Clear($pfx,0,$pfx.Length) }
    } else {
        $rootRsa=[Security.Cryptography.RSACng]::new(3072)
        $rootRequest=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=IRIS Local Network CA',$rootRsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $rootRequest.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true,$true,0,$true))
        $rootUsage=[Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign
        $rootRequest.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($rootUsage,$true))
        $rootRequest.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($rootRequest.PublicKey,$false))
        $ca=$rootRequest.CreateSelfSigned($now.AddMinutes(-5),$now.AddYears(3))
        $pfx=$ca.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx,'')
        try {
            New-BytesFile $protectedPath ([Security.Cryptography.ProtectedData]::Protect($pfx,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser))
        } finally { [Array]::Clear($pfx,0,$pfx.Length) }
    }
    if ($ca.NotAfter -lt (Get-Date).AddDays(91)) { throw 'The LAN CA is near expiry. Prepare a replacement CA and update client trust.' }
    if (Test-Path -LiteralPath $caPath) {
        $publicCa=[Security.Cryptography.X509Certificates.X509Certificate2]::new($caPath)
        try { if ($publicCa.Thumbprint -ne $ca.Thumbprint) { throw 'Stored LAN CA public certificate differs from the protected signing key.' } }
        finally { $publicCa.Dispose() }
    } else { New-PemFile $caPath 'CERTIFICATE' $ca.RawData }
    $rsa=[Security.Cryptography.RSACng]::new(2048)
    $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=IRIS Local Network',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $names=[Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $names.AddIpAddress($ip);$names.AddDnsName('localhost');$names.AddIpAddress([Net.IPAddress]::Parse('127.0.0.1'))
    $request.CertificateExtensions.Add($names.Build())
    Add-ServerExtensions $request
    $issuerId=($ca.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.14'}).SubjectKeyIdentifier
    $issuerBytes=[byte[]]::new($issuerId.Length/2)
    for ($index=0;$index -lt $issuerBytes.Length;$index++) { $issuerBytes[$index]=[Convert]::ToByte($issuerId.Substring($index*2,2),16) }
    $authority=[byte[]](@(0x30,($issuerBytes.Length+2),0x80,$issuerBytes.Length)+$issuerBytes)
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509Extension]::new('2.5.29.35',$authority,$false))
    $serial=[byte[]]::new(16);$rng=[Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($serial) } finally { $rng.Dispose() }
    $serial[0]=($serial[0] -band 0x7f) -bor 1
    $leaf=$request.Create($ca,$now.AddMinutes(-5),$now.AddDays(90),$serial)
    $certificatePath=Join-Path $OutputDirectory 'server-cert.pem'
    $privateKeyPath=Join-Path $OutputDirectory 'server-key.pem'
    New-PemFile $certificatePath 'CERTIFICATE' $leaf.RawData
    New-PemFile $privateKeyPath 'PRIVATE KEY' ($rsa.Key.Export([Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob))
    [pscustomobject]@{CertificateFile=$certificatePath;KeyFile=$privateKeyPath;CaCertificateFile=$caPath;
        CaThumbprint=$ca.Thumbprint;ServerThumbprint=$leaf.Thumbprint;TrustStoreChanged=$false} | ConvertTo-Json -Compress
} finally {
    if ($leaf) {$leaf.Dispose()};if ($rsa) {$rsa.Dispose()};if ($ca) {$ca.Dispose()};if ($rootRsa) {$rootRsa.Dispose()}
}
