<# Prepare a LAN certificate and configuration. Does not change the firewall or trust stores. #>
[CmdletBinding()]
param([int]$InterfaceIndex=0,[ValidateRange(1,65535)][int]$Port=8010,[switch]$RenewCertificate)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
$python=Join-Path $projectRoot '.venv\Scripts\python.exe'
$configurationPath=Join-Path $projectRoot '.local\active_demo\lan.json'
$interfaces=@(Get-NetIPConfiguration | Where-Object {
    $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' -and
    ($InterfaceIndex -eq 0 -or $_.InterfaceIndex -eq $InterfaceIndex)
})
if ($interfaces.Count -ne 1) { throw 'Choose one active network adapter using -InterfaceIndex.' }
$interface=$interfaces[0]
$addresses=@($interface.IPv4Address | Where-Object {$_.IPAddress -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'})
if ($addresses.Count -ne 1) { throw 'The adapter must have one explicit private IPv4 address.' }
$address=$addresses[0].IPAddress
$prefix=[int]$addresses[0].PrefixLength
$subnet=& $python -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1],strict=False))' "$address/$prefix"
if ($LASTEXITCODE -ne 0) { throw 'Cannot calculate the local subnet.' }
$profile=(Get-NetConnectionProfile -InterfaceIndex $interface.InterfaceIndex).NetworkCategory.ToString()
if ($profile -eq 'DomainAuthenticated') { $profile='Domain' }
if ($profile -notin @('Public','Private','Domain')) { throw 'Unsupported network profile.' }
$program=& $python -c 'import sys; print(sys._base_executable)'
if ($LASTEXITCODE -ne 0) { throw 'Cannot locate the Python listener executable.' }

$certificatePath=$null
$keyPath=$null
if ((Test-Path -LiteralPath $configurationPath) -and -not $RenewCertificate) {
    $existing=Get-Content -LiteralPath $configurationPath -Raw | ConvertFrom-Json
    if ($existing.address -eq $address) {
        $candidate=Join-Path $projectRoot $existing.certificate
        $candidateKey=Join-Path $projectRoot $existing.private_key
        if ((Test-Path -LiteralPath $candidate) -and (Test-Path -LiteralPath $candidateKey) -and
            (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLower() -eq $existing.certificate_sha256) {
            $savedCertificate=[Security.Cryptography.X509Certificates.X509Certificate2]::new($candidate)
            try {
                if ($savedCertificate.NotAfter -gt (Get-Date).AddDays(7)) {
                    $certificatePath=$candidate; $keyPath=$candidateKey
                }
            } finally { $savedCertificate.Dispose() }
        }
    }
}
if ($null -eq $certificatePath) {
    $certificateDirectory=Join-Path $projectRoot ('.local\active_demo\tls-lan-'+$address.Replace('.','_')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
    $created=& (Join-Path $PSScriptRoot 'New-LocalHttpsCertificate.ps1') -OutputDirectory $certificateDirectory -AdditionalIPAddresses $address -CommonName 'IRIS Local Network'
    $metadata=$created | ConvertFrom-Json
    $certificatePath=$metadata.CertificateFile; $keyPath=$metadata.KeyFile
}
$certificate=[Security.Cryptography.X509Certificates.X509Certificate2]::new($certificatePath)
try {
    $clientDirectory=Join-Path $projectRoot '.local\active_demo\lan-client'
    [IO.Directory]::CreateDirectory($clientDirectory) | Out-Null
    $publicName='IRIS-LAN-'+$address+'-'+$certificate.Thumbprint.Substring(0,12)+'.cer'
    $publicPath=Join-Path $clientDirectory $publicName
    [IO.File]::WriteAllBytes($publicPath,$certificate.RawData)
    $trimRoot=$projectRoot.TrimEnd('\')+'\'
    $configuration=[ordered]@{
        schema='iris-lan-v1'; address=$address; subnet=$subnet.Trim(); prefix_length=$prefix; port=$Port
        interface_alias=$interface.InterfaceAlias; interface_index=$interface.InterfaceIndex; profile=$profile
        python_program=$program.Trim(); certificate=$certificatePath.Substring($trimRoot.Length)
        private_key=$keyPath.Substring($trimRoot.Length)
        certificate_sha256=(Get-FileHash -LiteralPath $certificatePath -Algorithm SHA256).Hash.ToLower()
        public_certificate=$publicPath.Substring($trimRoot.Length)
        public_certificate_sha256=(Get-FileHash -LiteralPath $publicPath -Algorithm SHA256).Hash.ToLower()
        thumbprint=$certificate.Thumbprint; expires_utc=$certificate.NotAfter.ToUniversalTime().ToString('o')
    }
    $encoding=[Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($configurationPath,($configuration | ConvertTo-Json -Depth 3),$encoding)
    $instructions=@"
IRIS local network access
Open https://${address}:$Port/ and sign in with your existing username/password.
Before signing in, trust ONLY the supplied public certificate on your own device.
Public certificate: $publicName
SHA-256: $($configuration.public_certificate_sha256)
Windows certificate thumbprint: $($configuration.thumbprint)
Verify this fingerprint with the server owner before importing.
Windows: Import-Certificate -FilePath '.\$publicName' -CertStoreLocation Cert:\CurrentUser\Root
For iOS/Android/macOS, use the device's certificate import/trust settings.
The server owner must keep the PC on and the LAN demo running.
No private key or account file is included or needed on client devices.
"@
    [IO.File]::WriteAllText((Join-Path $clientDirectory 'README.txt'),$instructions,$encoding)
    $clientPackage=Join-Path $projectRoot '.local\active_demo\IRIS-LAN-client.zip'
    Compress-Archive -LiteralPath @($publicPath,(Join-Path $clientDirectory 'README.txt')) -DestinationPath $clientPackage -Force
    [pscustomobject]@{
        Address=$address; Subnet=$configuration.subnet; Port=$Port; Interface=$interface.InterfaceAlias
        Profile=$profile; PublicCertificate=$publicPath; Thumbprint=$certificate.Thumbprint
        ClientPackage=$clientPackage
        PublicCertificateSha256=$configuration.public_certificate_sha256
        FirewallChanged=$false; TrustStoreChanged=$false
        StartCommand='.\.venv\Scripts\python.exe demo.py --lan'
    } | ConvertTo-Json -Compress
} finally { $certificate.Dispose() }
