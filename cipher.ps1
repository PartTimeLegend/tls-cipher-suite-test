<#
 .DESCRIPTION
   Disables and Enables security protocols deemed high-severity by Aspect Software.

 .NOTES

   Author: Stacey Smith (stacey.smith@aspect.com)
   Version: 2.0
   Last Update: August 24, 2016
   Required: If using SQlServer, then must be SQLServer2014 R2 (both server and client).

.AVAILABLE FUNCTIONS
    Set-TLSv1_0

 .EXAMPLE
    ## You must run script as an administrator ##
    ## note that powershell4 does not use -FullyQualifiedName, only -Name ##

    1. Open a command line (cmd.exe)
    2. Start a Windows Powershell Session... C:\>PowerShell.exe
    3. PS C:\> Start-Process powershell -Verb runAs
    4. PS C:\> Get-Module -Name C:\your-path-to-file\server_hardening.psm1 -ListAvailable
    5. PS C:\> Import-Module -Name C:\your-path-to-file\server_hardening.psm1 -PassThru
    6. PS C:\> Enable-SecureServer
    7. Reboot
 #>

 $REG_PATH_PROTOCOLS = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\"
 $REG_PATH_CIPHERS = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\"
 $REG_PATH_HASHES = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\"
 $DOT_NET_REG_PATH = "HKLM:\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319"
 $DOT_NET_64_REG_PATH = "HKLM:\\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
 
 # Set cipher suites order as secure as possible (Enables Perfect Forward Secrecy).
 # Information taken from https://www.hass.de/content/setup-your-iis-ssl-perfect-forward-secrecy-and-tls-12
 $os = Get-WmiObject -class Win32_OperatingSystem
 # Not ideal but Windows 2022 seems to return as 10.
 if ($os.Caption.Contains("2022")) {
     Write-Verbose 'Use cipher suites order for Windows 2022.'
     $cipherSuitesOrder = @(
      'TLS_AES_256_GCM_SHA384',
      'TLS_AES_128_GCM_SHA256',
      'TLS_CHACHA20_POLY1305_SHA256',
      'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
      'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
      'TLS_ECDHE_ECDSA_WITH_AES128_GCM_SHA256',
      'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
     )
 }
 else {
     Write-Verbose 'Use cipher suites order for Windows 10/2016/2019'
     $cipherSuitesOrder = @(
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
     )
 }
 
 
 $INSECURECIPHERS = @(
     'DES 56/56',
     'DES 168/168'
     'NULL',
     'RC2 128/128',
     'RC2 40/128',
     'RC2 56/128',
     'RC4 40/128',
     'RC4 56/128',
     'RC4 64/128',
     'RC4 128/128',
     'Triple DES 168'
 )
 
 $SECURECIPHERS = @(
     'AES 128/128',
     'AES 256/256'
 )
 
 $INSECUREPROTOCOLS = @(
     'TLS 1.0',
     'TLS 1.1',
     'PCT 1.0',
     'SSL 2.0',
     'SSL 3.0'
 )
 
 $INSECUREHASHES = @('MD5', 'SHA')
 
 $SECUREHASHES = @(
     'SHA256',
     'SHA384',
     'SHA512'
   )
 
 function Set-TLSVersion {
     [CmdletBinding()]
     param (
         [Parameter(Mandatory = $true)]
         [string] $Version,
         [switch] $Disable
     )
 
     $tls_version = $Version
     $tls_enabled = [int](-Not ($Disable.IsPresent))
     $tls_disabledbydefault = [int]$Disable.IsPresent
 
     $reg_path = "$REG_PATH_PROTOCOLS$tls_version"
     if (!(Test-Path $reg_path)) {
         New-Item -Path $reg_path -Force | Out-Null
     }
     $reg_path_server = "${reg_path}\Server"
     if (!(Test-Path $reg_path_server)) {
         New-Item -Path $reg_path_server -Force | Out-Null
     }
     $reg_path_client = "${reg_path}\Client"
     if (!(Test-Path $reg_path_client)) {
         New-Item -Path $reg_path_client -Force | Out-Null
     }
 
     #Server
     set-ItemProperty -Path "$reg_path_server" -name "Enabled" -Value $tls_enabled -erroraction silentlycontinue -Type DWord -Force | Out-Null
     set-ItemProperty -Path "$reg_path_server" -name "DisabledByDefault" -Value $tls_disabledbydefault -erroraction silentlycontinue -Type DWord -Force | Out-Null
 
     #Client
     set-ItemProperty -Path "$reg_path_client" -name "Enabled" -Value $tls_enabled -erroraction silentlycontinue -Type DWord -Force | Out-Null
     set-ItemProperty -Path "$reg_path_client" -name "DisabledByDefault" -Value $tls_disabledbydefault -erroraction silentlycontinue -Type DWord -Force | Out-Null
 }
 
 function Test-TLSVersion {
     [CmdletBinding()]
     param (
         [Parameter(Mandatory = $true)]
         [string] $Version,
         [switch] $Disable
     )
 
     $tls_version = $Version
     $tls_enabled = [int](-Not ($Disable.IsPresent))
     $tls_disabledbydefault = [int]$Disable.IsPresent
 
     $reg_path_server = "$REG_PATH_PROTOCOLS$tls_version\Server"
     $reg_path_client = "$REG_PATH_PROTOCOLS$tls_version\Client"
 
     if (!(Test-Path $reg_path_server)) {
         return $false
     }
     if (!(Test-Path $reg_path_client)) {
         return $false
     }
     $test = Test-RegistryValue $reg_path_server "Enabled" "$tls_enabled"
     if (!$test) {
         return $false
     }
     $test = Test-RegistryValue $reg_path_server "DisabledByDefault" "$tls_disabledbydefault"
     if (!$test) {
         return $false
     }
     $test = Test-RegistryValue $reg_path_client "Enabled" "$tls_enabled"
     if (!$test) {
         return $false
     }
     $test = Test-RegistryValue $reg_path_client "DisabledByDefault" "$tls_disabledbydefault"
     if (!$test) {
         return $false
     }
 
     return $true
 }
 
 <#
 .SYNOPSIS
 This will test all the necessary reg values to see if RC4 Ciphers are explicitly disabled.
 Return Value: $true - if all reg values are properly set
 Return Value: $false - if any reg values are missing or any not properly set
 
 .PARAMETER none
 #>
 function Test-RC4Ciphers {
     [CmdletBinding()]
     param (
         [switch] $Disable
     )
 
     $tls_enabled = [int](-Not ($Disable.IsPresent))
 
     if (!(Test-Path $REG_PATH_CIPHERS)) {
         return $false
     }
 
     Foreach ($insecureCipher in $INSECURECIPHERS) {
         $cipher_path = "$REG_PATH_CIPHERS$insecureCipher"
         $tls_enabled = [int](-Not ($Disable.IsPresent))
         if (!(Test-Path $cipher_path)) {
             return $false
         }
         $test = Test-RegistryValue $cipher_path "Enabled" "$tls_enabled"
         if (!$test) {
             return $false
         }
     }
 
     return $true
 }
 
 <#
 .SYNOPSIS
 Disables weak RC4 Ciphers.
 
 .PARAMETER none
 #>
 function Set-RC4Ciphers {
     [CmdletBinding()]
     param (
         [switch] $Disable
     )
 
     $tls_enabled = [int](-Not ($Disable.IsPresent))
 
     Foreach ($insecureCipher in $insecureCiphers) {
         $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($insecureCipher)
         $key.SetValue('Enabled', $tls_enabled, 'DWord')
         $key.close()
         Write-Verbose "Cipher $insecureCipher has been disabled: $tls_enabled."
     }
 }
 
 <#
 .SYNOPSIS
 This will test all the necessary reg values to see if IIS is being forced to use TLSv1.2 explicitly.
 Return Value: $true - if all reg values are properly set
 Return Value: $false - if any reg values are missing or any not properly set
 
 .PARAMETER none
 #>
 function Test-DotNetStrongEncryption {
     [CmdletBinding()]
     param (
         [switch] $Disable
     )
 
     $tls_enabled = [int](-Not ($Disable.IsPresent))
 
     if (!(Test-Path $DOT_NET_REG_PATH)) {
         return $false
     }
     if (!(Test-Path $DOT_NET_64_REG_PATH)) {
         return $false
     }
 
     #32-bit
     $test = Test-RegistryValue $DOT_NET_REG_PATH "SchUseStrongCrypto" "$tls_enabled"
     if (!$test) {
         return $false
     }
 
     #64-bit
     $test = Test-RegistryValue $DOT_NET_64_REG_PATH "SchUseStrongCrypto" "$tls_enabled"
     if (!$test) {
         return $false
     }
 
     return $true
 }
 
 <#
 .SYNOPSIS
 Force IIS to use TLSv1.2.
 This is necessary if using .NET's HttpWebRequest
 
 .PARAMETER none
 #>
 function Set-DotNetStrongEncryption {
     [CmdletBinding()]
     param (
         [switch] $Disable
     )
 
     $tls_enabled = [int](-Not ($Disable.IsPresent))
 
     if (!(Test-Path $DOT_NET_REG_PATH)) {
         New-Item -Path $DOT_NET_REG_PATH -Force | Out-Null
     }
     if (!(Test-Path $DOT_NET_64_REG_PATH)) {
         New-Item -Path $DOT_NET_64_REG_PATH -Force | Out-Null
     }
 
     #32-bit
     set-ItemProperty -Path "$DOT_NET_REG_PATH" -name "SchUseStrongCrypto" -Value $tls_enabled -erroraction silentlycontinue -Type DWord -Force | Out-Null
 
     #64-bit
     set-ItemProperty -Path "$DOT_NET_64_REG_PATH" -name "SchUseStrongCrypto" -Value $tls_enabled -erroraction silentlycontinue -Type DWord -Force | Out-Null
 }
 
 #Helper fucntion that will check to see if regkey is explicitly disabled (ie set to value of 0).
 function Test-RegistryValue {
     [CmdletBinding()]
     param(
         [Parameter(Mandatory = $true)]
         [string]
         # The path to the registry key
         $path,
         [Parameter(Mandatory = $true)]
         [string]
         # The name of the reg key
         $name,
         [Parameter(Mandatory = $true)]
         [string]
         # The desired value
         $value
     )
 
     $val = Get-RegistryValue $path $name
 
     $result = (($val -eq $null) -or ($val.Length -eq 0) -or ($val -ne $value))
 
     return -Not ($result)
 }
 
 # Gets the specified registry value or $null if it is missing
 function Get-RegistryValue($path, $name) {
     $key = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
     if ($key) {
         $key.GetValue($name, $null)
     }
 }
 
 <#
 .SYNOPSIS
 This will test all the necessary reg values to see if my server is more secure.
 Return Value: $true - if all necessary reg values are properly set
 Return Value: $false - if any reg values are missing or any not properly set
 
 .PARAMETER none
 #>
 function Test-ServerSecure {
     [CmdletBinding()]
     param()
 
     $result = $true
 
     Foreach ($insecureTLSVersion in $INSECUREPROTOCOLS) {
         $out = Test-TLSVersion -Version:$insecureTLSVersion -Disable
         Write-Verbose "$insecureTLSVersion is Disabled: $out"
 
         if ($result -eq $true) { $result = $out }
     }
 
     $out = Test-RC4Ciphers -Disable
     Write-Verbose "RC4 Ciphers is Disabled: $out"
     if ($result -eq $true) { $result = $out }
 
     $out = Test-TLSVersion -Version:'TLS 1.2'
     Write-Verbose "TLS 1.2 is Enabled: $out"
     if ($result -eq $true) { $result = $out }
 
     $out = Test-DotNetStrongEncryption
     Write-Verbose ".Net Uses Strong Encryption Enabled: $out"
     if ($result -eq $true) { $result = $out }
 
     $out = Test-RDPSecure
     Write-Verbose "RDP Secure Enabled: $out"
     if ($result -eq $true) { $result = $out }
 
     return $result
 }
 
 <#
 .SYNOPSIS
 Secures RDP Connections to avoid using Insecure Methods
 
 SetEncryptionLevel - https://msdn.microsoft.com/en-us/library/aa383800(v=vs.85).aspx
 SetSecurityLayer - https://msdn.microsoft.com/en-us/library/aa383801(v=vs.85).aspx
 
 .PARAMETER none
 #>
 function Set-RDPSecure {
     [CmdletBinding()]
     param (
         [int] $EncryptionLevel = 3,
         [int] $SecurityLayer = 2
     )
 
     $RDSSettings = Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'"
     $RDSSettings.SetEncryptionLevel($EncryptionLevel)
     $RDSSettings.SetSecurityLayer($SecurityLayer)
 }
 
 function Test-RDPSecure {
     [CmdletBinding()]
     param(
         [int] $EncryptionLevel = 3,
         [int] $SecurityLayer = 2
     )
 
     $is_valid = $true
     $RDSSettings = Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'"
 
     if($RDSSettings.MinEncryptionLevel -ne $EncryptionLevel){
         $is_valid = $false
     }
 
     if($RDSSettings.SecurityLayer -ne $SecurityLayer) {
         $is_valid = $false
     }
 
     return $is_valid
 }
 
 function Set-Hashes {
     [CmdletBinding()]
     param (
         [switch] $Disable
     )
 
     $hash_enabled = [int](-Not ($Disable.IsPresent))
 
     $INSECUREHASHES | ForEach-Object {
         $insecure_hash = $_
         New-Item -Path "$REG_PATH_HASHES" -Name $insecure_hash -ItemType directory -Force
         set-ItemProperty -Path "${REG_PATH_HASHES}\$insecure_hash" -name "Enabled" -Value $hash_enabled -erroraction silentlycontinue -Type DWord -Force | Out-Null
     }
 }
 
 <#
 .SYNOPSIS
 Secures Server by enabling TLSv1.2 and disabling weak ciphers and setting registry keys to for .NET to use TLSv1.2.
 
 .PARAMETER none
 #>
 function Set-ServerSecure {
     [CmdletBinding()]
     param()
 
     Foreach ($insecureTLSVersion in $INSECUREPROTOCOLS) {
         Set-TLSVersion -Version:$insecureTLSVersion -Disable
     }
 
     Set-RC4Ciphers -Disable
     Set-TLSVersion -Version:'TLS 1.2'
     Set-DotNetStrongEncryption
 
     # Disable Multi-Protocol Unified Hello
     New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Force | Out-Null
     New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
     New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
     New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -Force | Out-Null
     New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
     New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
     Write-Host 'Multi-Protocol Unified Hello has been disabled.'
 
     # Enable new secure ciphers.
     $SECURECIPHERS | ForEach-Object {
         $secureCipher = $_
         $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($secureCipher)
         New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$secureCipher" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
         $key.close()
         Write-Verbose "Strong cipher $secureCipher has been enabled."
     }
 
     # Enable secure hashes
     $SECUREHASHES | ForEach-Object {
         $secureHash = $_
         $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes', $true).CreateSubKey($secureHash)
         New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$secureHash" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
         $key.close()
         Write-Verbose "Hash $secureHash has been enabled."
     }
 
     # Set KeyExchangeAlgorithms configuration.
     New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms' -Force | Out-Null
     $SECUREKEYEXCHANGEALGORITHMS = @(
     'Diffie-Hellman',
     'ECDH',
     'PKCS'
     )
     $SECUREKEYEXCHANGEALGORITHMS | ForEach-Object {
         $secureKeyExchangeAlgorithm = $_
 
         $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms', $true).CreateSubKey($secureKeyExchangeAlgorithm)
         New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$secureKeyExchangeAlgorithm" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
         $key.close()
         Write-Verbose "KeyExchangeAlgorithm $secureKeyExchangeAlgorithm has been enabled."
     }
 
     # Set cipher suites order as secure as possible (Enables Perfect Forward Secrecy).
     $cipherSuitesAsString = [string]::join(',', $cipherSuitesOrder)
     New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -ErrorAction SilentlyContinue
     New-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions' -value $cipherSuitesAsString -PropertyType 'String' -Force | Out-Null
 
     Set-Hashes -Disable
     Set-RDPSecure
 
     if (-Not (Test-ServerSecure)) {
         Write-Error "Server is not Secure"
     }
 }
 
 Export-ModuleMember -function Test-ServerSecure, Set-ServerSecure