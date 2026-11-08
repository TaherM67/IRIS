<# Manage only the narrowly scoped IRIS LAN rule; run as Administrator to apply. #>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
param([switch]$Remove)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
$config=Get-Content -LiteralPath (Join-Path $projectRoot '.local\active_demo\lan.json') -Raw | ConvertFrom-Json
if ($config.schema -ne 'iris-lan-v1' -or $config.port -lt 1 -or $config.port -gt 65535) { throw 'Invalid LAN configuration.' }
$address=Get-NetIPAddress -InterfaceIndex $config.interface_index -AddressFamily IPv4 | Where-Object {$_.IPAddress -eq $config.address}
if (-not $address -or $address.PrefixLength -ne $config.prefix_length) { throw 'Network address changed. Prepare LAN access again.' }
$python=Join-Path $projectRoot '.venv\Scripts\python.exe'
$expectedSubnet=& $python -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1],strict=False))' "$($config.address)/$($address.PrefixLength)"
if ($LASTEXITCODE -ne 0 -or $expectedSubnet.Trim() -ne $config.subnet) { throw 'Configured subnet does not match the adapter.' }
$profile=(Get-NetConnectionProfile -InterfaceIndex $config.interface_index).NetworkCategory.ToString()
if ($profile -eq 'DomainAuthenticated') { $profile='Domain' }
if ($profile -ne $config.profile -or $profile -notin @('Private','Public','Domain')) { throw 'Network profile changed. Prepare LAN access again.' }
$actualProgram=& $python -c 'import sys; print(sys._base_executable)'
if ($LASTEXITCODE -ne 0 -or $actualProgram.Trim() -ne $config.python_program) { throw 'Python executable differs from the prepared listener.' }
$ruleName='IRIS-Demo-LAN-HTTPS-'+$config.port
$description='IRIS same-subnet HTTPS; managed for '+$projectRoot
$existing=Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
if ($existing -and $existing.Description -ne $description) { throw 'A different application owns this firewall rule name.' }
$isAdmin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $WhatIfPreference -and -not $isAdmin) { throw 'Run this script in an Administrator PowerShell window.' }
if ($Remove) {
    if ($existing -and $PSCmdlet.ShouldProcess($ruleName,'Remove only the IRIS LAN firewall exception')) {
        Remove-NetFirewallRule -Name $ruleName
    }
} elseif ($PSCmdlet.ShouldProcess("$($config.address):$($config.port) on $($config.interface_alias), $profile profile, remote $($config.subnet)",'Allow inbound HTTPS for the IRIS Python process')) {
    $parameters=@{
        Direction='Inbound'; Action='Allow'; Enabled='True'; Protocol='TCP'; LocalPort=$config.port
        LocalAddress=$config.address; RemoteAddress=$config.subnet; InterfaceAlias=$config.interface_alias
        Profile=$profile; Program=$config.python_program; EdgeTraversalPolicy='Block'
    }
    if ($existing) { Set-NetFirewallRule -Name $ruleName @parameters }
    else { New-NetFirewallRule -Name $ruleName -DisplayName 'IRIS local network HTTPS' -Description $description @parameters | Out-Null }
}
[pscustomobject]@{RuleName=$ruleName;LocalAddress=$config.address;Port=$config.port;RemoteSubnet=$config.subnet;
    Interface=$config.interface_alias;Profile=$profile;Program=$config.python_program;Remove=[bool]$Remove;WhatIf=[bool]$WhatIfPreference} | ConvertTo-Json -Compress
