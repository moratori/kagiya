# Collects facts from a Windows machine (run on GitHub Actions Windows runners) to ground kagiya's detection rules and tests.
# This is a verification script, not part of kagiya itself. It mostly reads; the only changes it makes are (both reverted at the end):
#   - creating test self-signed certificates (to learn the on-disk/registry format of certificate store entries)
#   - registering an HTTP.sys SSL binding on 127.0.0.1 only (to learn its registry format)
#
# NOTE: artifacts of a public repository can be downloaded by others. Never output environment variables, tokens or private keys.
#
# This file must stay ASCII-only: Windows PowerShell 5.1 reads a script without a BOM in the ANSI code page,
# so non-ASCII text in string literals breaks parsing.
param([string]$Out = (Join-Path $env:RUNNER_TEMP 'windows-facts'))

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $Out | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Out 'reg') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Out 'certstore') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Out 'files') | Out-Null

function Save([string]$Name, [scriptblock]$Block) {
    $path = Join-Path $Out $Name
    try { & $Block 2>&1 | Out-File -FilePath $path -Encoding utf8 -Width 4096 }
    catch { "ERROR: $_" | Out-File -FilePath $path -Encoding utf8 }
}

# Export a registry key as a .reg file. The absence of a key is a fact too, so record it.
function Export-Key([string]$Key, [string]$Name) {
    $path = Join-Path $Out (Join-Path 'reg' $Name)
    & reg.exe query $Key *> $null
    if ($LASTEXITCODE -ne 0) {
        "(key not present) $Key" | Out-File -FilePath ($path + '.absent.txt') -Encoding utf8
        return
    }
    & reg.exe export $Key $path /y *> $null
}

function Sha256Hex([byte[]]$Bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([System.BitConverter]::ToString($sha.ComputeHash($Bytes)) -replace '-', '').ToLower() }
    finally { $sha.Dispose() }
}

# ---------------------------------------------------------------- 1. OS and runner image
Save 'os.txt' {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
        Select-Object ProductName, EditionID, InstallationType, DisplayVersion, ReleaseId, CurrentBuild, CurrentBuildNumber, UBR, CurrentMajorVersionNumber, CurrentMinorVersionNumber |
        Format-List
    "OSVersion: $([Environment]::OSVersion.VersionString)"
    "Is64BitOS: $([Environment]::Is64BitOperatingSystem)"
    "PowerShell: $($PSVersionTable.PSVersion)"
    # Runner image identification (which image definition built this environment; used to check its customizations)
    "ImageOS: $env:ImageOS"
    "ImageVersion: $env:ImageVersion"
}

# ---------------------------------------------------------------- 2. Schannel (TLS)
Export-Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' 'schannel.reg'
Export-Key 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL' 'ssl-policy.reg'
Export-Key 'HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL' 'ssl-local.reg'
Export-Key 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography' 'cryptography-policy.reg'
Save 'tls-cipher-suites.json' {
    Get-TlsCipherSuite | Select-Object Name, CipherSuite, BaseCipherSuite, Cipher, CipherLength, CipherBlockLength, Hash, HashLength, Exchange, MinimumExchangeLength, MaximumExchangeLength, Certificate, KeyType, Protocols |
        ConvertTo-Json -Depth 4
}
Save 'tls-cipher-suites.txt' { Get-TlsCipherSuite | Format-Table Name, Protocols, Exchange, Cipher, CipherLength, Hash, Certificate -AutoSize }
Save 'tls-ecc-curves.txt' { Get-TlsEccCurve }

# ---------------------------------------------------------------- 3. .NET, FIPS, authentication
Export-Key 'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' 'dotnet-v4-64.reg'
Export-Key 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' 'dotnet-v4-32.reg'
Export-Key 'HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' 'dotnet-v2-64.reg'
Export-Key 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727' 'dotnet-v2-32.reg'
Export-Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' 'fips.reg'
Export-Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' 'kerberos-lsa.reg'
Export-Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 'kerberos-policy.reg'
Export-Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'ntlm-msv1_0.reg'
Export-Key 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'rdp-tcp.reg'
Export-Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' 'winhttp.reg'
Save 'lsa-values.txt' {
    # Do not export the whole Lsa key; read only the values related to cryptography
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' |
        Select-Object LmCompatibilityLevel, NoLMHash, DisableRestrictedAdmin | Format-List
}

# ---------------------------------------------------------------- 4. Certificate stores
Save 'certstore/stores.txt' {
    foreach ($loc in 'LocalMachine', 'CurrentUser') {
        "== Cert:\$loc"
        Get-ChildItem "Cert:\$loc" | ForEach-Object {
            "{0,-28} {1}" -f $_.Name, @(Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue).Count
        }
    }
}
# Physical location of the stores (registry structure and number of entries)
Save 'certstore/registry-layout.txt' {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\SystemCertificates',
        'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates',
        'HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\SystemCertificates',
        'HKCU:\SOFTWARE\Microsoft\SystemCertificates',
        'HKCU:\SOFTWARE\Policies\Microsoft\SystemCertificates',
        'HKLM:\SOFTWARE\Microsoft\Cryptography\Services'
    )
    foreach ($r in $roots) {
        "== $r"
        if (-not (Test-Path $r)) { '   (not present)'; continue }
        Get-ChildItem $r -ErrorAction SilentlyContinue | ForEach-Object {
            $line = "   {0,-34}" -f $_.PSChildName
            foreach ($sub in 'Certificates', 'CRLs', 'CTLs', 'Keys') {
                $p = Join-Path $_.PSPath $sub
                if (Test-Path $p) { $line += " $sub=$(@(Get-ChildItem $p -ErrorAction SilentlyContinue).Count)" }
            }
            $line
        }
    }
    '== value names and kinds of one certificate entry (first entry of ROOT)'
    $first = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates' | Select-Object -First 1
    if ($first) {
        foreach ($n in $first.GetValueNames()) { "   value '$n' kind=$($first.GetValueKind($n)) length=$(@($first.GetValue($n)).Length)" }
    }
    '== file-based user stores'
    foreach ($d in @("$env:APPDATA\Microsoft\SystemCertificates", "$env:ProgramData\Microsoft\Crypto")) {
        "   $d exists=$(Test-Path $d)"
        if (Test-Path $d) { Get-ChildItem $d -Recurse -Directory -ErrorAction SilentlyContinue | ForEach-Object { "      $($_.FullName)  entries=$(@(Get-ChildItem $_.FullName -File -ErrorAction SilentlyContinue).Count)" } }
    }
}

# Keep pairs of the ground truth (values reported by Windows itself) and the raw registry entry (Blob) of the same certificate.
function Describe-Cert($c, [string]$Store) {
    [ordered]@{
        store              = $Store
        thumbprint_sha1    = $c.Thumbprint.ToLower()
        sha256             = Sha256Hex $c.RawData
        subject            = $c.Subject
        issuer             = $c.Issuer
        serial             = $c.SerialNumber.ToLower()
        not_before_utc     = $c.NotBefore.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        not_after_utc      = $c.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        signature_alg_oid  = $c.SignatureAlgorithm.Value
        signature_alg_name = $c.SignatureAlgorithm.FriendlyName
        public_key_oid     = $c.PublicKey.Oid.Value
        public_key_params  = if ($c.PublicKey.EncodedParameters) { ([System.BitConverter]::ToString($c.PublicKey.EncodedParameters.RawData) -replace '-', '').ToLower() } else { '' }
        has_private_key    = $c.HasPrivateKey
    }
}
function Save-Blob([string]$RegPath, [string]$FileName) {
    $k = Get-Item $RegPath -ErrorAction SilentlyContinue
    if ($k) { [System.IO.File]::WriteAllBytes((Join-Path $Out (Join-Path 'certstore' $FileName)), [byte[]]$k.GetValue('Blob')) }
}

$samples = @()
# (a) a few root certificates shipped with the OS (public information)
Get-ChildItem Cert:\LocalMachine\Root | Sort-Object Thumbprint | Select-Object -First 4 | ForEach-Object {
    $samples += Describe-Cert $_ 'LocalMachine\Root'
    Save-Blob "HKLM:\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\$($_.Thumbprint)" "root-$($_.Thumbprint.ToLower()).blob"
    [System.IO.File]::WriteAllBytes((Join-Path $Out "certstore\root-$($_.Thumbprint.ToLower()).cer"), $_.RawData)
}
# a few entries from AuthRoot (roots delivered by automatic update), if present
Get-ChildItem Cert:\LocalMachine\AuthRoot -ErrorAction SilentlyContinue | Sort-Object Thumbprint | Select-Object -First 2 | ForEach-Object {
    $samples += Describe-Cert $_ 'LocalMachine\AuthRoot'
    Save-Blob "HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates\$($_.Thumbprint)" "authroot-$($_.Thumbprint.ToLower()).blob"
}

# (b) certificates with a private key (created for this test and removed at the end).
# The Blob holds the certificate and information on where the key lives, not the private key itself.
$made = @()
try {
    $rsa = New-SelfSignedCertificate -Subject 'CN=kagiya-facts-rsa' -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm RSA -KeyLength 2048 -NotAfter (Get-Date).AddDays(3)
    $ec = New-SelfSignedCertificate -Subject 'CN=kagiya-facts-ecdsa' -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm ECDSA_nistP256 -NotAfter (Get-Date).AddDays(3)
    $usr = New-SelfSignedCertificate -Subject 'CN=kagiya-facts-user' -CertStoreLocation Cert:\CurrentUser\My -KeyAlgorithm RSA -KeyLength 2048 -NotAfter (Get-Date).AddDays(3)
    $made = @($rsa, $ec, $usr)
    foreach ($c in @($rsa, $ec)) {
        $samples += Describe-Cert $c 'LocalMachine\My'
        Save-Blob "HKLM:\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\$($c.Thumbprint)" "my-$($c.Thumbprint.ToLower()).blob"
    }
    $samples += Describe-Cert $usr 'CurrentUser\My'
    # The per-user personal store is kept in files, not in the registry (this also confirms that)
    $userFile = Join-Path $env:APPDATA "Microsoft\SystemCertificates\My\Certificates\$($usr.Thumbprint)"
    "user store file: $userFile exists=$(Test-Path $userFile); registry key exists=$(Test-Path "HKCU:\SOFTWARE\Microsoft\SystemCertificates\My\Certificates\$($usr.Thumbprint)")" |
        Out-File (Join-Path $Out 'certstore\user-store-location.txt') -Encoding utf8
    if (Test-Path $userFile) { Copy-Item $userFile (Join-Path $Out "certstore\usermy-$($usr.Thumbprint.ToLower()).blob") }

    # ---------------------------------------------------------- 5. HTTP.sys SSL binding
    Save 'httpsys-before.txt' { & netsh.exe http show sslcert }
    $appid = '{6b616769-7961-4661-8374-73746f726500}'
    Save 'httpsys-add.txt' { & netsh.exe http add sslcert ipport=127.0.0.1:44399 "certhash=$($rsa.Thumbprint)" "appid=$appid" certstorename=MY }
    Save 'httpsys-show.txt' { & netsh.exe http show sslcert ipport=127.0.0.1:44399 }
    Export-Key 'HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\SslBindingInfo' 'httpsys-sslbindinginfo.reg'
    "rsa certificate thumbprint used for the binding: $($rsa.Thumbprint.ToLower())" | Out-File (Join-Path $Out 'httpsys-expected.txt') -Encoding utf8
    & netsh.exe http delete sslcert ipport=127.0.0.1:44399 *> $null
}
catch { "ERROR: $_" | Out-File (Join-Path $Out 'certstore\ERROR.txt') -Encoding utf8 }
finally {
    foreach ($c in $made) { if ($c) { Remove-Item $c.PSPath -DeleteKey -ErrorAction SilentlyContinue } }
}
$samples | ConvertTo-Json -Depth 4 | Out-File (Join-Path $Out 'certstore\expected.json') -Encoding utf8

# ---------------------------------------------------------------- 6. OpenSSH for Windows
Save 'openssh.txt' {
    foreach ($n in 'ssh.exe', 'sshd.exe') {
        $cmd = Get-Command $n -ErrorAction SilentlyContinue
        if ($cmd) { "$n => $($cmd.Source)  FileVersion=$($cmd.FileVersionInfo.FileVersion) ProductVersion=$($cmd.FileVersionInfo.ProductVersion)" } else { "$n => (not found)" }
    }
    & ssh.exe -V 2>&1
    Get-WindowsCapability -Online -Name 'OpenSSH*' -ErrorAction SilentlyContinue | Select-Object Name, State | Format-Table -AutoSize
    foreach ($p in @("$env:WINDIR\System32\OpenSSH", "$env:ProgramData\ssh")) { "== $p"; Get-ChildItem $p -ErrorAction SilentlyContinue | Select-Object Name, Length | Format-Table -AutoSize }
}
foreach ($f in @("$env:WINDIR\System32\OpenSSH\sshd_config_default", "$env:ProgramData\ssh\sshd_config", "$env:ProgramData\ssh\ssh_config")) {
    if (Test-Path $f) { Copy-Item $f (Join-Path $Out ("files\" + ($f -replace '[:\\]', '_'))) }
}

# ---------------------------------------------------------------- 7. IIS
Save 'iis.txt' {
    Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue | Select-Object Name, InstallState | Format-List
    $cfg = "$env:WINDIR\System32\inetsrv\config\applicationHost.config"
    "applicationHost.config exists=$(Test-Path $cfg)"
    if (Test-Path $cfg) { Select-String -Path $cfg -Pattern '<binding ', 'sslFlags', '<access ' | ForEach-Object { $_.Line.Trim() } }
}

# ---------------------------------------------------------------- 8. File system (drive types, reparse points)
Save 'filesystem.txt' {
    '== drives (DriveType: 2=removable 3=local 4=network 5=CD-ROM)'
    Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, DriveType, FileSystem, ProviderName | Format-Table -AutoSize
    '== reparse points directly under the system drive'
    Get-ChildItem "$env:SystemDrive\" -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue | Select-Object Name, Attributes, LinkType, Target | Format-Table -AutoSize
    '== reparse points directly under the user profile'
    Get-ChildItem "$env:USERPROFILE" -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue | Select-Object Name, Attributes, LinkType | Format-Table -AutoSize
    '== last access time update setting'
    & fsutil.exe behavior query disablelastaccess
}

# ---------------------------------------------------------------- 9. Manifest
Save 'MANIFEST.txt' {
    "collected_at_utc: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    Get-ChildItem $Out -Recurse -File | Where-Object { $_.Name -ne 'MANIFEST.txt' } | ForEach-Object {
        "{0}  {1,9}  {2}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Length, $_.FullName.Substring($Out.Length + 1)
    }
}
Write-Host "collected $(@(Get-ChildItem $Out -Recurse -File).Count) files into $Out"
exit 0
