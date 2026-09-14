<#
.SYNOPSIS
    One-pass connectivity triage: link, IP/DHCP, gateway, DNS, domain controller, SYSVOL, file shares, proxy, internet, Microsoft 365, Wi-Fi and VPN.
.DESCRIPTION
    Answers the whole "I can't reach anything" class of ticket in a single run. Reads the adapter that carries the
    default route (link speed, IP, DHCP lease, DNS servers), then probes every hop a domain PC depends on: the
    gateway, the system resolver and each configured DNS server on its own, the domain controller on LDAP/SMB/
    Kerberos, SYSVOL, the user's mapped file servers, the proxy configuration, the Microsoft connectivity test and
    the Microsoft 365 endpoints. Every probe has a hard timeout and they run in parallel, so a machine with nothing
    reachable finishes in about the same time as a healthy one.
.PARAMETER Display
    Print a readable report to the screen instead of returning objects.
.PARAMETER ReportPath
    Folder to also save the readable report to (only used with -Display). Created if missing.
.PARAMETER FileServer
    Extra file servers to test, as bare host names or full UNC paths (\\server\share). Added to the servers found in
    the signed-in user's persistent drive mappings.
.PARAMETER DnsTestName
    Name to resolve through the system resolver and through each DNS server individually.
    Default: this machine's AD domain DNS name, or www.microsoft.com when the machine is not domain-joined.
.EXAMPLE
    .\Test-Connectivity.ps1
.EXAMPLE
    .\Test-Connectivity.ps1 -Display -ReportPath C:\Temp\Toolkit
.EXAMPLE
    .\Test-Connectivity.ps1 -FileServer '\\fs01\data','nas02' -Display
.NOTES
    Toolkit-Class:     ReadOnly
    Toolkit-Context:   Machine
    Toolkit-Elevation: None
    Requires Windows PowerShell 5.1. Inbox modules only.
#>
[CmdletBinding()]
param(
    [switch]$Display,
    [string]$ReportPath,
    [string[]]$FileServer = @(),
    [string]$DnsTestName
)
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Test-Connectivity'
$script:Warnings  = New-Object System.Collections.Generic.List[string]

function Add-Warning { param([string]$Message) $script:Warnings.Add($Message) }

function Test-IsAdmin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Runs a block; on failure records a warning and returns $Default instead of killing the script.
function Invoke-Section {
    param([string]$Name, [scriptblock]$Script, $Default = $null)
    try { & $Script } catch { Add-Warning ("{0}: {1}" -f $Name, $_.Exception.Message.Trim()); $Default }
}

# External commands: stderr merged as text, exit code captured, safe under $ErrorActionPreference = 'Stop'.
function Invoke-Native {
    param([string]$FilePath, [string[]]$ArgumentList = @())
    $ErrorActionPreference = 'Continue'
    $lines = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { "$_" })
    [PSCustomObject]@{ ExitCode = $LASTEXITCODE; Lines = $lines }
}

function Round1 { param($Value) if ($null -eq $Value) { $null } else { [math]::Round([double]$Value, 1) } }

function Format-Bytes {
    param([double]$Bytes)
    if ($Bytes -ge 1TB) { '{0:N1} TB' -f ($Bytes / 1TB) }
    elseif ($Bytes -ge 1GB) { '{0:N1} GB' -f ($Bytes / 1GB) }
    elseif ($Bytes -ge 1MB) { '{0:N1} MB' -f ($Bytes / 1MB) }
    elseif ($Bytes -ge 1KB) { '{0:N1} KB' -f ($Bytes / 1KB) }
    else { '{0} B' -f [int64]$Bytes }
}

function Format-Duration {
    param([TimeSpan]$Span)
    if ($Span.TotalDays -ge 1) { '{0}d {1}h {2}m' -f [int]$Span.Days, $Span.Hours, $Span.Minutes }
    elseif ($Span.TotalHours -ge 1) { '{0}h {1}m' -f [int]$Span.Hours, $Span.Minutes }
    else { '{0}m {1}s' -f [int]$Span.Minutes, $Span.Seconds }
}

# FILETIME helpers (registry DWORD pairs may arrive as negative Int32; the L suffix matters in PS 5.1).
function ConvertFrom-FileTimePair { param($High, $Low) [DateTime]::FromFileTime(([int64]$High -shl 32) -bor ([int64]$Low -band 0xFFFFFFFFL)) }
function ConvertFrom-FileTimeBytes { param([byte[]]$Bytes) [DateTime]::FromFileTime([BitConverter]::ToInt64($Bytes, 0)) }

# TCP reachability with a real timeout (Test-Path on a dead UNC host can hang 20+ s).
function Test-TcpPort {
    param([string]$ComputerName, [int]$Port, [int]$TimeoutMs = 3000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($async) | Out-Null
        return $true
    } catch { return $false } finally { $client.Close() }
}

# The interactive (console) user, resolved even when this process runs as another account, SYSTEM, or remotely.
# Source: Console (Win32_ComputerSystem.UserName) | Desktop (owner of a live explorer.exe) | Override (-TargetUser) | Process (nobody found; fell back to this process's identity).
function Get-ConsoleUser {
    param([string]$OverrideName)
    $name = $null; $sid = $null; $source = $null; $sessionId = $null; $logonId = $null
    $desktops = @()   # one explorer.exe per live desktop; owner + logon session come from LSA (no DC round trip)
    try { foreach ($p in @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop)) {
        $o = $null; $ls = $null
        try { $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop } catch { }
        try { $ls = Get-CimAssociatedInstance -InputObject $p -ResultClassName Win32_LogonSession -ErrorAction Stop | Where-Object { $_.LogonType -in 2,10,11 } | Select-Object -First 1 } catch { }
        if ($o -and $o.User) { $desktops += [PSCustomObject]@{ Name = ('{0}\{1}' -f $o.Domain, $o.User); SessionId = $p.SessionId; LogonId = $ls.LogonId; LogonType = $ls.LogonType; StartTime = $ls.StartTime } }
    } } catch { }
    if ($OverrideName) { $name = $OverrideName; $source = 'Override' }
    if (-not $name) { try { $name = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName } catch { }; if ($name) { $source = 'Console' } }
    if (-not $name -and $desktops.Count) {
        $pick = $desktops | Sort-Object @{e={$_.LogonType -eq 10}}, @{e={$_.StartTime}; Descending=$true} | Select-Object -First 1
        $name = $pick.Name; $source = 'Desktop'
    }
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $name) { $name = $me.Name; $sid = $me.User.Value; $source = 'Process' }
    if ($name -and -not $sid) { try { $sid = ([System.Security.Principal.NTAccount]$name).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { } }
    $mine = $desktops | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    if ($mine) { $sessionId = $mine.SessionId; $logonId = $mine.LogonId }
    $hive = $null; $profilePath = $null
    if ($sid) {
        if (-not (Get-PSDrive HKU -ErrorAction SilentlyContinue)) { New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Script | Out-Null }
        try { $k = [Microsoft.Win32.Registry]::Users.OpenSubKey($sid); if ($k) { $hive = "HKU:\$sid"; $k.Close() } } catch { }
        try { $profilePath = [Environment]::ExpandEnvironmentVariables((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -ErrorAction Stop).ProfileImagePath) } catch { }
    }
    [PSCustomObject]@{
        Name          = $name            # DOMAIN\user of the person at the desk
        Sid           = $sid
        Hive          = $hive            # HKU:\S-1-5-21-... (openable) or $null. Use INSTEAD of HKCU:
        ProfilePath   = $profilePath     # C:\Users\jdoe. Use INSTEAD of $env:USERPROFILE / APPDATA / LOCALAPPDATA
        SessionId     = $sessionId       # session of that user's live desktop ($null = no desktop found)
        LogonId       = $logonId         # decimal LUID of that logon session (klist -li ('0x{0:x}' -f [int64]$logonId))
        Source        = $source          # Console | Desktop | Override | Process
        OtherDesktops = (($desktops | Where-Object { $_.Name -ne $name } | ForEach-Object { '{0} (session {1})' -f $_.Name, $_.SessionId }) -join ', ')
        IsMe          = ($sid -eq $me.User.Value)
        IsSystem      = ($me.User.Value -eq 'S-1-5-18')
        RunningAs     = $me.Name
    }
}

# Readable report for -Display. Scalars as a list, array properties as tables (never silently dropping columns).
function Show-Result {
    param([Parameter(ValueFromPipeline = $true)]$InputObject, [string]$Title, [string]$ReportPath)
    begin { $items = New-Object System.Collections.Generic.List[object] }
    process { if ($null -ne $InputObject) { $items.Add($InputObject) } }
    end {
        $width = 250
        $table = {
            param($src)
            $rows = @($src)
            $ft = ($rows | Format-Table -Property * -AutoSize -Wrap | Out-String -Width $width).TrimEnd()
            $hdr = ($ft -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
            $dropped = @($rows[0].PSObject.Properties.Name | Where-Object { $hdr -notmatch ('(^|\s)' + [regex]::Escape($_) + '(\s|$)') })
            if ($dropped.Count) { $ft = ($rows | Format-List -Property * | Out-String -Width $width).TrimEnd() }
            $ft
        }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine(('=' * 78))
        [void]$sb.AppendLine(('  {0}   {1}   {2}' -f $Title, $env:COMPUTERNAME, [DateTime]::Now.ToString('yyyy-MM-dd HH:mm')))
        [void]$sb.AppendLine(('=' * 78))
        $isList = { param($p) ($p.Value -is [System.Collections.IEnumerable]) -and ($p.Value -isnot [string]) -and ($p.Value -isnot [System.Collections.IDictionary]) }
        $allFlat = $true
        foreach ($i in $items) { foreach ($p in $i.PSObject.Properties) { if (& $isList $p) { $allFlat = $false } } }
        if ($items.Count -gt 1 -and $allFlat) {
            [void]$sb.AppendLine((& $table $items.ToArray()))
            [void]$sb.AppendLine(''); [void]$sb.AppendLine(('  {0} row(s)' -f $items.Count))
        } elseif ($items.Count -eq 0) {
            [void]$sb.AppendLine('  (no results)')
        } else {
            foreach ($i in $items) {
                $scalars = [ordered]@{}; $lists = @()
                foreach ($p in $i.PSObject.Properties) { if (& $isList $p) { $lists += $p } else { $scalars[$p.Name] = $p.Value } }
                if ($scalars.Count) { [void]$sb.AppendLine(([PSCustomObject]$scalars | Format-List | Out-String -Width $width).Trim()) }
                foreach ($l in $lists) {
                    $rows = @($l.Value)
                    [void]$sb.AppendLine(''); [void]$sb.AppendLine(('--- {0} ({1}) ---' -f $l.Name, $rows.Count))
                    if ($rows.Count) { [void]$sb.AppendLine((& $table $rows)) } else { [void]$sb.AppendLine('  (none)') }
                }
                [void]$sb.AppendLine('')
            }
        }
        $text = $sb.ToString()
        Write-Host $text
        if ($ReportPath) {
            try {
                $ReportPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ReportPath)
                if (-not (Test-Path -LiteralPath $ReportPath)) { New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null }
                $file = Join-Path $ReportPath ('{0}_{1}_{2}.txt' -f $Title, $env:COMPUTERNAME, [DateTime]::Now.ToString('yyyyMMdd-HHmm'))
                [System.IO.File]::WriteAllText($file, $text, [System.Text.Encoding]::UTF8)
                Write-Host ("Report saved: {0}" -f $file)
            } catch { Write-Host ("Could not save report to {0}: {1}" -f $ReportPath, $_.Exception.Message) }
        }
    }
}
# ---------------------------------------------------------------- end toolkit helpers

# ---------------------------------------------------------------- parallel probe engine
# Every network probe runs in its own runspace so a dead host costs wall-clock time only once, not once per probe.
# Each probe body still carries its own timeout (Test-TcpPort 3 s, Ping 1.5 s, Invoke-WebRequest 5 s), and the whole
# set is abandoned at $ProbeDeadlineMs. Abandoned runspaces are background threads: they never delay process exit.
$script:ProbeDeadlineMs = 18000
$script:Probes = [ordered]@{}

function Add-Probe {
    param([string]$Name, [string]$Body, $A, $B, $C)
    $script:Probes[$Name] = [PSCustomObject]@{ Body = $Body; A = $A; B = $B; C = $C }
}

function Invoke-ProbeSet {
    param([int]$DeadlineMs = 18000)
    $out = @{}
    if (-not $script:Probes.Count) { return $out }
    $threads = [Math]::Min(24, [Math]::Max(4, $script:Probes.Count))
    $prelude = "param(`$A, `$B, `$C)`n`$ErrorActionPreference = 'Stop'`nfunction Test-TcpPort {" + ${function:Test-TcpPort}.ToString() + "}`n"
    $pool = [runspacefactory]::CreateRunspacePool(1, $threads)
    $pool.Open()
    $jobs = [ordered]@{}
    foreach ($k in $script:Probes.Keys) {
        $p = $script:Probes[$k]
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($prelude + $p.Body)
        [void]$ps.AddParameters(@{ A = $p.A; B = $p.B; C = $p.C })
        $jobs[$k] = [PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke() }
    }
    $deadline = [DateTime]::Now.AddMilliseconds($DeadlineMs)
    foreach ($k in $jobs.Keys) {
        $j = $jobs[$k]
        $value = $null; $err = ''
        $remain = [int][Math]::Max(0, ($deadline - [DateTime]::Now).TotalMilliseconds)
        if ($j.Handle.AsyncWaitHandle.WaitOne($remain, $false)) {
            try { $value = @($j.PS.EndInvoke($j.Handle)) | Select-Object -First 1 }
            catch { $err = $_.Exception.Message.Trim() }
            if (-not $err -and $j.PS.Streams.Error.Count) { $err = ($j.PS.Streams.Error | ForEach-Object { $_.ToString().Trim() }) -join '; ' }
            try { $j.PS.Dispose() } catch { }
        } else {
            $err = ('gave up after {0} s' -f [int]($DeadlineMs / 1000))
            try { [void]$j.PS.BeginStop($null, $null) } catch { }
        }
        $out[$k] = [PSCustomObject]@{ Value = $value; Error = $err }
    }
    try { [void]$pool.BeginClose($null, $null) } catch { }
    $out
}

# Result of one probe, or $null. A probe that errored or was abandoned adds one warning under $Label.
function Get-ProbeValue {
    param($Results, [string]$Name, [string]$Label)
    if (-not $Results.ContainsKey($Name)) { return $null }
    $r = $Results[$Name]
    if ($r.Error) { Add-Warning ('{0}: {1}' -f $Label, $r.Error); return $null }
    $r.Value
}

# '\\fs01\data' -> Host fs01, Path \\fs01\data.  'fs01' or '\\fs01' -> Host fs01, Path $null (host only, no share to open).
function Split-UncTarget {
    param([string]$Raw)
    $s = "$Raw".Trim() -replace '/', '\'
    if (-not $s) { return $null }
    if ($s -match '^\\\\([^\\]+)(?:\\(.*))?$') {
        $h = $Matches[1]
        $rest = if ($Matches[2]) { $Matches[2].Trim('\') } else { '' }
        if (-not $h) { return $null }
        if ($rest) { return [PSCustomObject]@{ Host = $h; Path = ('\\{0}\{1}' -f $h, $rest) } }
        return [PSCustomObject]@{ Host = $h; Path = $null }
    }
    if ($s -notmatch '[\\/:]') { return [PSCustomObject]@{ Host = $s; Path = $null } }
    $null
}

# ---------------------------------------------------------------- probe bodies (run inside a runspace; $A/$B/$C are the arguments)
$bodyTcp = @'
$sw = [Diagnostics.Stopwatch]::StartNew()
$ok = Test-TcpPort -ComputerName $A -Port $B -TimeoutMs 3000
[PSCustomObject]@{ Ok = [bool]$ok; Ms = [int]$sw.ElapsedMilliseconds }
'@

$bodyPing = @'
$pinger = New-Object System.Net.NetworkInformation.Ping
$ok = $false; $ms = $null; $status = 'NoReply'
try {
    foreach ($attempt in 1..2) {
        $reply = $pinger.Send($A, 1500)
        $status = "$($reply.Status)"
        if ($reply.Status -eq 'Success') { $ok = $true; $ms = [int]$reply.RoundtripTime; break }
    }
} catch { $status = 'NameNotResolved' } finally { $pinger.Dispose() }
[PSCustomObject]@{ Ok = [bool]$ok; Ms = $ms; Status = $status }
'@

# $A = name to resolve, $B = DNS server to ask directly ($null = the system resolver)
$bodyDns = @'
$sw = [Diagnostics.Stopwatch]::StartNew()
$ips = @(); $err = ''
try {
    $splat = @{ Name = $A; Type = 'A'; DnsOnly = $true; ErrorAction = 'Stop' }
    if ($B) { $splat['Server'] = $B; $splat['QuickTimeout'] = $true }
    $answer = @(Resolve-DnsName @splat)
    $ips = @($answer | Where-Object { $_.Type -eq 'A' -and $_.IPAddress } | ForEach-Object { "$($_.IPAddress)" })
    if (-not $ips.Count) { $err = 'answered, but returned no A record' }
} catch { $err = $_.Exception.Message.Trim() }
[PSCustomObject]@{ Ips = ($ips -join '; '); IpCount = [int]$ips.Count; Note = $err; Ms = [int]$sw.ElapsedMilliseconds }
'@

# $A = DNS server IP, $B = name to resolve. TCP 53 and a real query, reported separately.
$bodyDnsServer = @'
$sw = [Diagnostics.Stopwatch]::StartNew()
$reach = Test-TcpPort -ComputerName $A -Port 53 -TimeoutMs 3000
$ips = @(); $err = ''
try {
    $answer = @(Resolve-DnsName -Name $B -Type A -DnsOnly -QuickTimeout -Server $A -ErrorAction Stop)
    $ips = @($answer | Where-Object { $_.Type -eq 'A' -and $_.IPAddress } | ForEach-Object { "$($_.IPAddress)" })
    if (-not $ips.Count) { $err = 'no A record' }
} catch { $err = $_.Exception.Message.Trim() }
[PSCustomObject]@{ Reach = [bool]$reach; Resolves = [bool]$ips.Count; Ips = ($ips -join '; '); Note = $err; Ms = [int]$sw.ElapsedMilliseconds }
'@

# $A = host, $B = UNC path to open ($null = host only, port test only)
$bodyShare = @'
$sw = [Diagnostics.Stopwatch]::StartNew()
$port = Test-TcpPort -ComputerName $A -Port 445 -TimeoutMs 3000
$read = $null
if ($port -and $B) { $read = [bool](Test-Path -LiteralPath $B -ErrorAction SilentlyContinue) }
[PSCustomObject]@{ Port = [bool]$port; Read = $read; Ms = [int]$sw.ElapsedMilliseconds }
'@

$bodyInternet = @'
$sw = [Diagnostics.Stopwatch]::StartNew()
$tcp = Test-TcpPort -ComputerName 'www.msftconnecttest.com' -Port 80 -TimeoutMs 3000
$content = $false; $got = ''
if ($tcp) {
    try {
        $web = Invoke-WebRequest 'http://www.msftconnecttest.com/connecttest.txt' -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        $got = "$($web.Content)".Trim()
        $content = ($got -eq 'Microsoft Connect Test')
    } catch { $got = $_.Exception.Message.Trim() }
}
[PSCustomObject]@{ Tcp = [bool]$tcp; Content = [bool]$content; Got = $got; Ms = [int]$sw.ElapsedMilliseconds }
'@

# ---------------------------------------------------------------- local facts (no network)
$console = Invoke-Section 'Console user' { Get-ConsoleUser }
$cs      = Invoke-Section 'Computer system' { Get-CimInstance Win32_ComputerSystem -ErrorAction Stop }

$domain = $null
$isDomainJoined = $false
if ($cs) {
    $isDomainJoined = [bool]$cs.PartOfDomain
    if ($isDomainJoined) { $domain = "$($cs.Domain)".Trim() }
}
if (-not $DnsTestName) {
    $DnsTestName = if ($domain) { $domain } else { 'www.microsoft.com' }
}
if (-not $isDomainJoined) { Add-Warning 'Not domain-joined: domain controller and SYSVOL checks skipped.' }

# Adapter carrying the default route: lowest RouteMetric + InterfaceMetric.
$route = Invoke-Section 'Default route' {
    @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue) |
        Sort-Object @{ e = { [int]$_.RouteMetric + [int]$_.InterfaceMetric } } | Select-Object -First 1
}
if (-not $route) { Add-Warning 'No IPv4 default route: this machine has no way off its own subnet.' }

$ifIndex = if ($route) { [int]$route.ifIndex } else { $null }
$adapter = $null
if ($null -ne $ifIndex) {
    $adapter = Invoke-Section 'Active adapter' { Get-NetAdapter -InterfaceIndex $ifIndex -ErrorAction Stop }
}

$adapterType = $null
if ($adapter) {
    $physical = "$($adapter.PhysicalMediaType)"
    $ifType   = [int]$adapter.InterfaceType
    $adapterType =
        if ($physical -match '802\.11') { 'Wi-Fi' }
        elseif ($physical -match 'BlueTooth') { 'Bluetooth' }
        elseif ($ifType -eq 71) { 'Wi-Fi' }
        elseif ($ifType -eq 6) { 'Ethernet' }
        elseif ($ifType -in 23, 131) { 'VPN/Tunnel' }
        else { "Other ($physical)" }
}
$isWifi = ($adapterType -eq 'Wi-Fi')

# IP address on that interface
$ipInfo = $null
if ($null -ne $ifIndex) {
    $ipInfo = Invoke-Section 'IPv4 address' {
        $all = @(Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        if ($all.Count -gt 1) { Add-Warning ('Interface has {0} IPv4 addresses; reporting the preferred one.' -f $all.Count) }
        @($all | Sort-Object @{ e = { $_.AddressState -ne 'Preferred' } }) | Select-Object -First 1
    }
}

# DHCP lease and per-adapter DNS from the classic CIM class (Get-CimInstance already returns real [datetime]s).
$nac = $null
if ($null -ne $ifIndex) {
    $nac = Invoke-Section 'Adapter configuration' {
        Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$ifIndex" -ErrorAction Stop | Select-Object -First 1
    }
}

$dhcpEnabled = $null
if ($nac) { $dhcpEnabled = [bool]$nac.DHCPEnabled }
elseif ($ipInfo) { $dhcpEnabled = ("$($ipInfo.PrefixOrigin)" -eq 'Dhcp') }

$dnsServers = Invoke-Section 'DNS servers' {
    if ($null -eq $ifIndex) { return @() }
    @((Get-DnsClientServerAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses)
} -Default @()
$dnsServers = @($dnsServers | Where-Object { $_ })
if (-not $dnsServers.Count) { Add-Warning 'No IPv4 DNS server is configured on the active adapter.' }

$dnsSuffix = Invoke-Section 'DNS suffix' {
    $connection = $null
    if ($null -ne $ifIndex) { $connection = "$((Get-DnsClient -InterfaceIndex $ifIndex -ErrorAction Stop).ConnectionSpecificSuffix)".Trim() }
    if ($connection) { return $connection }
    "$((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -ErrorAction Stop).Domain)".Trim()
}

$dnsSuffixSearchList = Invoke-Section 'DNS suffix search list' {
    @((Get-DnsClientGlobalSetting -ErrorAction Stop).SuffixSearchList) -join '; '
}

$ipv4 = if ($ipInfo) { "$($ipInfo.IPAddress)" } else { $null }
$gateway = if ($route) { "$($route.NextHop)" } else { $null }
if ($gateway -in '0.0.0.0', '') { $gateway = $null }

# Domain controller: the logon server this machine actually used, else ask the locator (works unelevated).
$dc = Invoke-Section 'Domain controller' {
    if (-not $isDomainJoined) { return $null }
    $fromEnv = "$env:LOGONSERVER".TrimStart('\').Trim()
    if ($fromEnv -and $fromEnv -ne $env:COMPUTERNAME) { return $fromEnv }
    $n = Invoke-Native -FilePath 'nltest.exe' -ArgumentList ("/dsgetdc:$domain")
    if ($n.ExitCode -ne 0) {
        Add-Warning ('Domain controller not located (nltest exit {0}: {1}).' -f $n.ExitCode, (@($n.Lines | Where-Object { $_.Trim() }) | Select-Object -First 1))
        return $null
    }
    $hit = @($n.Lines | Where-Object { $_ -match '^\s*DC:\s*\\\\(\S+)' }) | Select-Object -First 1
    if ($hit -and $hit -match '^\s*DC:\s*\\\\(\S+)') { return $Matches[1] }
    Add-Warning 'Domain controller not parsed from nltest output (non-English Windows?).'
    $null
}

# WinHTTP (machine-wide) proxy
$proxyWinHttp = Invoke-Section 'WinHTTP proxy' {
    $n = Invoke-Native -FilePath 'netsh.exe' -ArgumentList 'winhttp', 'show', 'proxy'
    if ($n.ExitCode -ne 0) { Add-Warning ('netsh winhttp show proxy exited {0}.' -f $n.ExitCode); return $null }
    if ($n.Lines | Where-Object { $_ -match 'Direct access' }) { return 'Direct access (no proxy server)' }
    $server = $null; $bypass = $null
    foreach ($line in $n.Lines) {
        if ($line -match '^\s*Proxy Server\(s\)\s*:\s*(.+)$') { $server = $Matches[1].Trim() }
        elseif ($line -match '^\s*Bypass List\s*:\s*(.+)$') { $bypass = $Matches[1].Trim() }
    }
    if ($server) { return (@("Proxy: $server", $(if ($bypass) { "bypass: $bypass" })) | Where-Object { $_ }) -join '; ' }
    Add-Warning 'WinHTTP proxy not parsed (non-English netsh output?).'
    $null
}

# Per-user and policy proxy, read from the console user's hive (never HKCU: - a tech may have elevated).
function Get-ProxySummary {
    param([string]$KeyPath)
    if (-not $KeyPath -or -not (Test-Path -LiteralPath $KeyPath)) { return 'None' }
    $k = Get-ItemProperty -LiteralPath $KeyPath -ErrorAction SilentlyContinue
    if (-not $k) { return 'None' }
    $parts = @()
    if ([int]$k.ProxyEnable -eq 1 -and "$($k.ProxyServer)".Trim()) { $parts += ('Manual: {0}' -f "$($k.ProxyServer)".Trim()) }
    if ("$($k.AutoConfigURL)".Trim()) { $parts += ('PAC: {0}' -f "$($k.AutoConfigURL)".Trim()) }
    if ($parts.Count) { $parts -join '; ' } else { 'None' }
}

$userHive = $null
if ($console) {
    if ($console.Hive) { $userHive = $console.Hive }
    elseif ($console.IsMe) { $userHive = 'HKCU:' }
    else { Add-Warning ('ProxyUser and mapped file servers: registry hive for {0} is not loaded (user signed out?).' -f $console.Name) }
}

$proxyUser = Invoke-Section 'User proxy' {
    if (-not $userHive) { return $null }
    Get-ProxySummary -KeyPath ($userHive.TrimEnd('\') + '\Software\Microsoft\Windows\CurrentVersion\Internet Settings')
}
$proxyPolicy = Invoke-Section 'Policy proxy' {
    Get-ProxySummary -KeyPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
}

# Wi-Fi radio detail. Only parsed when the default route really runs over Wi-Fi.
$wifi = @{}
if ($isWifi) {
    $null = Invoke-Section 'Wi-Fi details' {
        $n = Invoke-Native -FilePath 'netsh.exe' -ArgumentList 'wlan', 'show', 'interfaces'
        if ($n.ExitCode -ne 0) { Add-Warning ('netsh wlan show interfaces exited {0} (WLAN AutoConfig service stopped?).' -f $n.ExitCode); return }
        # Labels are matched on the LEFT of the colon only. 'AP BSSID' is the Windows 11 spelling of 'BSSID'.
        $rx = '^\s*(?:AP\s+)?(SSID|BSSID|Signal|Radio type|Band|Channel|Receive rate \(Mbps\)|Transmit rate \(Mbps\)|Authentication|State)\s*:\s*(.*)$'
        foreach ($line in $n.Lines) {
            if ($line -match $rx) {
                $key = $Matches[1]
                if (-not $wifi.ContainsKey($key)) { $wifi[$key] = $Matches[2].Trim() }
            }
        }
        if (-not $wifi.ContainsKey('SSID')) { Add-Warning 'Wi-Fi details not parsed (non-English netsh output?)' }
    }
}
function Get-WifiNumber { param([string]$Key) if ($wifi.ContainsKey($Key) -and ($wifi[$Key] -match '\d')) { [int]($wifi[$Key] -replace '[^\d]', '') } else { $null } }

$wifiChannel = Get-WifiNumber 'Channel'
$wifiBand = if ($wifi.ContainsKey('Band') -and $wifi['Band']) { $wifi['Band'] }
            elseif ($null -eq $wifiChannel) { $null }
            elseif ($wifiChannel -le 14) { '2.4 GHz' }
            elseif ($wifiChannel -ge 36 -and $wifiChannel -le 177) { '5 GHz' }
            else { '6 GHz' }

# VPN: a connected VPN profile, or a VPN vendor's adapter that is Up.
$vpnActive = Invoke-Section 'VPN' {
    $connected = @()
    foreach ($scope in @($false, $true)) {
        try {
            $profiles = if ($scope) { @(Get-VpnConnection -AllUserConnection -ErrorAction Stop) } else { @(Get-VpnConnection -ErrorAction Stop) }
            $connected += @($profiles | Where-Object { "$($_.ConnectionStatus)" -eq 'Connected' })
        } catch { }
    }
    if ($connected.Count) { return $true }
    $rx = 'VPN|Cisco AnyConnect|GlobalProtect|Fortinet|WireGuard|Tailscale|ZScaler'
    $up = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -match $rx })
    [bool]$up.Count
}

# File servers: the console user's persistent mappings plus anything passed in with -FileServer.
$fileTargets = Invoke-Section 'File server list' {
    $found = New-Object System.Collections.Generic.List[object]
    foreach ($raw in @($FileServer)) {
        $t = Split-UncTarget $raw
        if ($t) { $found.Add($t) } elseif ("$raw".Trim()) { Add-Warning ("-FileServer value not understood: '{0}'" -f $raw) }
    }
    if ($userHive) {
        $networkKey = $userHive.TrimEnd('\') + '\Network'
        if (Test-Path -LiteralPath $networkKey) {
            foreach ($sub in @(Get-ChildItem -LiteralPath $networkKey -ErrorAction SilentlyContinue)) {
                $remote = (Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue).RemotePath
                $t = Split-UncTarget $remote
                if ($t) { $found.Add($t) }
            }
        }
    }
    # one row per host; keep the first path seen for that host
    $seen = [ordered]@{}
    foreach ($t in $found) {
        $key = $t.Host.ToLowerInvariant()
        if (-not $seen.Contains($key)) { $seen[$key] = $t }
        elseif (-not $seen[$key].Path -and $t.Path) { $seen[$key] = $t }
    }
    @($seen.Values)
} -Default @()
$fileTargets = @($fileTargets)

# ---------------------------------------------------------------- queue every network probe, then run them at once
if ($gateway) {
    Add-Probe 'gw.ping'  $bodyPing $gateway
    Add-Probe 'gw.tcp80' $bodyTcp  $gateway 80
    Add-Probe 'gw.tcp443' $bodyTcp $gateway 443
}
Add-Probe 'dns.system' $bodyDns $DnsTestName
for ($i = 0; $i -lt $dnsServers.Count; $i++) { Add-Probe ('dns.server.{0}' -f $i) $bodyDnsServer $dnsServers[$i] $DnsTestName }
if ($dc) {
    Add-Probe 'dc.ldap' $bodyTcp $dc 389
    Add-Probe 'dc.smb'  $bodyTcp $dc 445
    Add-Probe 'dc.krb'  $bodyTcp $dc 88
    Add-Probe 'dc.ping' $bodyPing $dc
}
if ($domain) { Add-Probe 'sysvol' $bodyShare $domain ('\\{0}\SYSVOL' -f $domain) }
for ($i = 0; $i -lt $fileTargets.Count; $i++) { Add-Probe ('fs.{0}' -f $i) $bodyShare $fileTargets[$i].Host $fileTargets[$i].Path }
Add-Probe 'internet'     $bodyInternet
Add-Probe 'm365.outlook' $bodyTcp 'outlook.office365.com' 443
Add-Probe 'm365.login'   $bodyTcp 'login.microsoftonline.com' 443

$results = Invoke-Section 'Network probes' { Invoke-ProbeSet -DeadlineMs $script:ProbeDeadlineMs } -Default @{}
if ($null -eq $results) { $results = @{} }

# ---------------------------------------------------------------- read the probe results back
$gwPing  = Get-ProbeValue $results 'gw.ping'  'Gateway ping'
$gwTcp80 = Get-ProbeValue $results 'gw.tcp80' 'Gateway TCP 80'
$gwTcp443 = Get-ProbeValue $results 'gw.tcp443' 'Gateway TCP 443'
$gatewayReachable = if ($gwPing) { [bool]$gwPing.Ok } else { $null }
$gatewayPingMs = if ($gwPing -and $gwPing.Ok) { [int]$gwPing.Ms } else { $null }
if ($gwPing -and -not $gwPing.Ok -and (($gwTcp80 -and $gwTcp80.Ok) -or ($gwTcp443 -and $gwTcp443.Ok))) {
    Add-Warning 'Gateway did not answer ping but answered TCP 80/443: it is up and blocking ICMP, not missing.'
}

$dnsSystem = Get-ProbeValue $results 'dns.system' 'DNS resolution'
$dnsResolves = if ($dnsSystem) { [bool]($dnsSystem.IpCount -gt 0) } else { $null }
$dnsResolvedTo = if ($dnsSystem -and $dnsSystem.IpCount -gt 0) { "$($dnsSystem.Ips)" } else { $null }
if ($dnsSystem -and $dnsSystem.IpCount -eq 0 -and $dnsSystem.Note) {
    Add-Warning ("DNS: '{0}' did not resolve ({1})." -f $DnsTestName, $dnsSystem.Note)
}

$dnsServerResults = @(Invoke-Section 'DNS server results' {
    $rows = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $dnsServers.Count; $i++) {
        $v = Get-ProbeValue $results ('dns.server.{0}' -f $i) ('DNS server ' + $dnsServers[$i])
        $rows.Add([PSCustomObject]@{
            Server     = $dnsServers[$i]
            Reachable53 = if ($v) { [bool]$v.Reach } else { $null }
            Resolves   = if ($v) { [bool]$v.Resolves } else { $null }
            ResolvedTo = if ($v -and $v.Resolves) { "$($v.Ips)" } else { $null }
            Ms         = if ($v) { [int]$v.Ms } else { $null }
            Note       = if ($v) { "$($v.Note)" } else { 'probe did not finish' }
        })
    }
    $rows.ToArray()
} -Default @())

$dcLdap = Get-ProbeValue $results 'dc.ldap' 'DC LDAP 389'
$dcSmb  = Get-ProbeValue $results 'dc.smb'  'DC SMB 445'
$dcKrb  = Get-ProbeValue $results 'dc.krb'  'DC Kerberos 88'
$dcPing = Get-ProbeValue $results 'dc.ping' 'DC ping'
$sysvol = Get-ProbeValue $results 'sysvol'  'SYSVOL'

$fileServersTested = @(Invoke-Section 'File servers' {
    $rows = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $fileTargets.Count; $i++) {
        $t = $fileTargets[$i]
        $v = Get-ProbeValue $results ('fs.{0}' -f $i) ('File server ' + $t.Host)
        $rows.Add([PSCustomObject]@{
            Host         = $t.Host
            Path         = $t.Path
            Port445      = if ($v) { [bool]$v.Port } else { $null }
            ShareReadable = if ($v) { $(if ($null -eq $v.Read) { $null } else { [bool]$v.Read }) } else { $null }
            Ms           = if ($v) { [int]$v.Ms } else { $null }
        })
    }
    $rows.ToArray()
} -Default @())

$inet = Get-ProbeValue $results 'internet' 'Internet'
$internetReachable = if ($inet) { [bool]($inet.Tcp -or $inet.Content) } else { $null }
if ($inet -and $inet.Tcp -and -not $inet.Content) {
    Add-Warning ('Internet: port 80 answered but the connectivity test returned unexpected content ("{0}") - captive portal or filtering proxy.' -f ("$($inet.Got)" -replace '\s+', ' ').Trim())
}

$m365a = Get-ProbeValue $results 'm365.outlook' 'Microsoft 365 outlook.office365.com'
$m365b = Get-ProbeValue $results 'm365.login'   'Microsoft 365 login.microsoftonline.com'
$m365Reachable = if ($m365a -and $m365b) { [bool]($m365a.Ok -and $m365b.Ok) } else { $null }

# ---------------------------------------------------------------- result object (shape A)
$o = [ordered]@{}
$o.ComputerName        = $env:COMPUTERNAME
$o.CollectedAt         = [DateTime]::Now
$o.ActiveAdapter       = if ($adapter) { '{0} ({1})' -f $adapter.Name, $adapter.InterfaceDescription } else { $null }
$o.AdapterType         = $adapterType
$o.LinkSpeedMbps       = if ($adapter -and [double]$adapter.TransmitLinkSpeed -gt 0) { Round1 ([double]$adapter.TransmitLinkSpeed / 1e6) } else { $null }
$o.MacAddress          = if ($adapter) { "$($adapter.MacAddress)" } else { $null }
$o.IPv4Address         = $ipv4
$o.SubnetPrefix        = if ($ipInfo) { [int]$ipInfo.PrefixLength } else { $null }
$o.DefaultGateway      = $gateway
$o.DhcpEnabled         = $dhcpEnabled
$o.DhcpServer          = if ($nac -and "$($nac.DHCPServer)".Trim()) { "$($nac.DHCPServer)".Trim() } else { $null }
$o.DhcpLeaseObtained   = if ($nac -and $nac.DHCPLeaseObtained) { [datetime]$nac.DHCPLeaseObtained } else { $null }
$o.DhcpLeaseExpires    = if ($nac -and $nac.DHCPLeaseExpires) { [datetime]$nac.DHCPLeaseExpires } else { $null }
$o.IsApipa             = [bool]("$ipv4".StartsWith('169.254.'))
$o.DnsServers          = ($dnsServers -join '; ')
$o.DnsSuffix           = $dnsSuffix
$o.DnsSuffixSearchList = $dnsSuffixSearchList
$o.GatewayReachable    = $gatewayReachable
$o.GatewayPingMs       = $gatewayPingMs
$o.DnsResolves         = $dnsResolves
$o.DnsTestName         = $DnsTestName
$o.DnsResolvedTo       = $dnsResolvedTo
$o.DnsServerResults    = $dnsServerResults
$o.DomainController    = $dc
$o.DcReachableLdap     = if ($dcLdap) { [bool]$dcLdap.Ok } else { $null }
$o.DcReachableSmb      = if ($dcSmb)  { [bool]$dcSmb.Ok }  else { $null }
$o.DcReachableKerberos = if ($dcKrb)  { [bool]$dcKrb.Ok }  else { $null }
$o.DcPingMs            = if ($dcPing -and $dcPing.Ok) { [int]$dcPing.Ms } else { $null }
$o.SysvolReachable     = if ($sysvol) { [bool]($sysvol.Port -and $sysvol.Read) } else { $null }
$o.FileServersTested   = $fileServersTested
$o.ProxyWinHttp        = $proxyWinHttp
$o.ProxyUser           = $proxyUser
$o.ProxyPolicy         = $proxyPolicy
$o.InternetReachable   = $internetReachable
$o.M365Reachable       = $m365Reachable
$o.Ssid                = if ($wifi.ContainsKey('SSID')) { $wifi['SSID'] } else { $null }
$o.WifiSignalPct       = Get-WifiNumber 'Signal'
$o.WifiBand            = $wifiBand
$o.WifiChannel         = $wifiChannel
$o.WifiRadioType       = if ($wifi.ContainsKey('Radio type')) { $wifi['Radio type'] } else { $null }
$o.WifiRxMbps          = Get-WifiNumber 'Receive rate (Mbps)'
$o.WifiTxMbps          = Get-WifiNumber 'Transmit rate (Mbps)'
$o.WifiAuth            = if ($wifi.ContainsKey('Authentication')) { $wifi['Authentication'] } else { $null }
$o.WifiBssid           = if ($wifi.ContainsKey('BSSID')) { $wifi['BSSID'] } else { $null }
$o.VpnActive           = if ($null -eq $vpnActive) { $null } else { [bool]$vpnActive }
$o.TargetUser          = if ($console) { $console.Name } else { $null }
$o.RunningAs           = if ($console) { $console.RunningAs } else { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }

$o.Warnings = ($script:Warnings -join '; ')
$result = [PSCustomObject]$o
if ($Display) { $result | Show-Result -Title $script:ToolName -ReportPath $ReportPath }
else          { $result }
