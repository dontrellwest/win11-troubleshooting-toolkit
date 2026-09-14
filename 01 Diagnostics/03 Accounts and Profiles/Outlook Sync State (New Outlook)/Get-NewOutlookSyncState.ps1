<#
.SYNOPSIS
    Check the new Outlook app (olk.exe) for the signed-in user: install, WebView2, local data, service reach.
.DESCRIPTION
    Read-only diagnostics for new Outlook. It has no automation interface, no MAPI profile and no OST,
    so this reads what exists: the Store package and version, whether it is running, the classic/new
    switch and its policies, the WebView2 runtime it depends on, the local data folders and how recently
    they changed, the default mail client, and whether the Microsoft 365 endpoints answer. Never starts
    or closes the app.
.PARAMETER Display
    Show the report instead of emitting objects.
.PARAMETER ReportPath
    Save the displayed report to this folder.
.PARAMETER TargetUser
    DOMAIN\user to report on when the signed-in user cannot be resolved.
.PARAMETER StaleMinutes
    Minutes after which the newest local data write counts as stale. Default 60.
.EXAMPLE
    .\Get-NewOutlookSyncState.ps1 -Display
.NOTES
    Toolkit-Class: ReadOnly
    Toolkit-Context: User
    Toolkit-Elevation: None
    Requires Windows PowerShell 5.1. Inbox modules only.
#>
[CmdletBinding()]
param([switch]$Display, [string]$ReportPath, [string]$TargetUser, [ValidateRange(1,10080)][int]$StaleMinutes=60)
$ErrorActionPreference = 'Stop'
# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Get-NewOutlookSyncState'
$script:Warnings  = New-Object System.Collections.Generic.List[string]

function Add-Warning { param([string]$Message) $script:Warnings.Add($Message) }

function Test-IsAdmin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Section {
    param([string]$Name, [scriptblock]$Script, $Default = $null)
    try { & $Script } catch { Add-Warning ("{0}: {1}" -f $Name, $_.Exception.Message.Trim()); $Default }
}

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

function ConvertFrom-FileTimePair { param($High, $Low) [DateTime]::FromFileTime(([int64]$High -shl 32) -bor ([int64]$Low -band 0xFFFFFFFFL)) }
function ConvertFrom-FileTimeBytes { param([byte[]]$Bytes) [DateTime]::FromFileTime([BitConverter]::ToInt64($Bytes, 0)) }

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

function Get-ConsoleUser {
    param([string]$OverrideName)
    $name = $null; $sid = $null; $source = $null; $sessionId = $null; $logonId = $null
    $desktops = @()
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
        Name          = $name
        Sid           = $sid
        Hive          = $hive
        ProfilePath   = $profilePath
        SessionId     = $sessionId
        LogonId       = $logonId
        Source        = $source
        OtherDesktops = (($desktops | Where-Object { $_.Name -ne $name } | ForEach-Object { '{0} (session {1})' -f $_.Name, $_.SessionId }) -join ', ')
        IsMe          = ($sid -eq $me.User.Value)
        IsSystem      = ($me.User.Value -eq 'S-1-5-18')
        RunningAs     = $me.Name
    }
}

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
# ---------------------------------------------------------------- tool body
$script:PackageFamily = 'Microsoft.OutlookForWindows_8wekyb3d8bbwe'
function Get-SessionProcessCount {
    param([string]$Name, $User)
    if ($null -eq $User.SessionId) { return $null }
    @(Get-CimInstance Win32_Process -Filter ("Name='{0}' AND SessionId={1}" -f $Name, [int]$User.SessionId) -ErrorAction Stop).Count
}
function Get-RegValue {
    param([string]$Key, [string]$Name)
    if (-not (Test-Path -LiteralPath $Key)) { return $null }
    $item = Get-ItemProperty -LiteralPath $Key -ErrorAction Stop
    if ($null -eq $item.PSObject.Properties[$Name]) { return $null }
    $item.$Name
}
function Get-PolicyOrUser {
    param([string]$PolicyKey, [string]$UserKey, [string]$Name)
    $v = Get-RegValue $PolicyKey $Name; if ($null -ne $v) { return ('{0} (policy)' -f $v) }
    $v = Get-RegValue $UserKey $Name;   if ($null -ne $v) { return ('{0} (user)' -f $v) }
    '(not set)'
}

$console = Get-ConsoleUser -OverrideName $TargetUser
if ($console.OtherDesktops -and -not $TargetUser) { Add-Warning ("Other desktops: " + $console.OtherDesktops) }
$o = [ordered]@{
    ComputerName=$env:COMPUTERNAME; CollectedAt=[datetime]::Now
    TargetUser=$console.Name; RunningAs=$console.RunningAs; TargetSource=$console.Source
    NewOutlookInstalled=$null; NewOutlookVersion=$null; NewOutlookRunning=$null
    ClassicOutlookInstalled=$null; ClassicOutlookRunning=$null; DefaultMailClient=$null
    WebView2Present=$null; WebView2Version=$null
    NewOutlookToggleHidden=$null; AutoMigrationPolicy=$null; MigrationUserSetting=$null; UseNewOutlookPreference=$null
    DataFolder=$null; DataFolderExists=$null; LocalDataFiles=$null; LocalDataMB=$null; LocalDataLastWrite=$null; LocalDataAgeMinutes=$null
    SignedInHint=$null; EntraJoined=$null; WorkplaceJoined=$null
    ServiceOutlookOffice=$null; ServiceOutlookLive=$null; ServiceLogin=$null
    Verdict=$null; NextStep=$null
    DataFolders=@(); Warnings=''
}

# Install: Store package for the target user (own user reads directly; another user needs admin)
$pkg = Invoke-Section 'New Outlook package' {
    if ($console.IsMe) { Get-AppxPackage -Name 'Microsoft.OutlookForWindows' -ErrorAction Stop | Select-Object -First 1 }
    elseif (Test-IsAdmin -and $console.Name) { Get-AppxPackage -User $console.Name -Name 'Microsoft.OutlookForWindows' -ErrorAction Stop | Select-Object -First 1 }
    else { throw 'another user''s Store packages need admin; install state inferred from the data folder' }
}
if ($pkg) { $o.NewOutlookInstalled = $true; $o.NewOutlookVersion = [string]$pkg.Version }
elseif ($console.IsMe) { $o.NewOutlookInstalled = $false }

# Classic Outlook beside it
$exe = Invoke-Section 'Classic Outlook install' { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE' -ErrorAction Stop).'(default)' }
$o.ClassicOutlookInstalled = [bool]($exe -and (Test-Path -LiteralPath $exe))

# Processes in the target user's session only
if ($null -eq $console.SessionId) { Add-Warning 'Target user has no live desktop; running-state checks skipped.' }
else {
    $o.NewOutlookRunning     = Invoke-Section 'New Outlook process' { [bool](Get-SessionProcessCount 'olk.exe' $console) }
    $o.ClassicOutlookRunning = Invoke-Section 'Classic Outlook process' { [bool](Get-SessionProcessCount 'OUTLOOK.EXE' $console) }
}

# WebView2 runtime (new Outlook cannot start without it)
$wv = Invoke-Section 'WebView2 runtime' {
    foreach ($k in 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
                   'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}') {
        $v = Get-RegValue $k 'pv'; if ($v) { return [string]$v }
    }
    $null
}
$o.WebView2Present = [bool]$wv; $o.WebView2Version = $wv

# Registry: default mail client, the classic/new switch and its policies (target user's hive, never HKCU)
if (-not $console.Hive) { Add-Warning 'Target registry hive unavailable; default mail client and migration settings are unknown.' }
else {
    $o.DefaultMailClient = Invoke-Section 'Default mail client' {
        $progId = Get-RegValue ($console.Hive + '\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\mailto\UserChoice') 'ProgId'
        if (-not $progId) { return '(not set)' }
        if ($progId -like 'Outlook.URL.mailto*') { return 'Classic Outlook' }
        if ($progId -like 'AppX*') {
            $aumid = Get-RegValue ('Registry::HKEY_CLASSES_ROOT\' + $progId + '\Application') 'AppUserModelID'
            if ($aumid -like '*OutlookForWindows*') { return 'New Outlook' }
            if ($aumid) { return ('Store app: ' + $aumid) }
            return ('Store app (' + $progId + ')')
        }
        [string]$progId
    }
    $userGen = $console.Hive + '\Software\Microsoft\Office\16.0\Outlook\Options\General'
    $polGen  = $console.Hive + '\Software\Policies\Microsoft\office\16.0\outlook\options\general'
    $o.NewOutlookToggleHidden  = Invoke-Section 'HideNewOutlookToggle' { Get-PolicyOrUser $polGen $userGen 'HideNewOutlookToggle' }
    $o.AutoMigrationPolicy     = Invoke-Section 'DoNewOutlookAutoMigration' { Get-PolicyOrUser $polGen $userGen 'DoNewOutlookAutoMigration' }
    $o.MigrationUserSetting    = Invoke-Section 'NewOutlookMigrationUserSetting' { Get-PolicyOrUser ($console.Hive + '\Software\Policies\Microsoft\office\16.0\outlook\preferences') ($console.Hive + '\Software\Microsoft\Office\16.0\Outlook\Preferences') 'NewOutlookMigrationUserSetting' }
    $o.UseNewOutlookPreference = Invoke-Section 'UseNewOutlook' { $v = Get-RegValue ($console.Hive + '\Software\Microsoft\Office\16.0\Outlook\Preferences') 'UseNewOutlook'; if ($null -eq $v) { '(not set)' } else { [string]$v } }
}

# Local data: new Outlook keeps its offline store, attachments and settings under AppData\Local\Microsoft\Olk
# (a WebView2 profile); the Store package folder holds only sentinels and icons. Both are read from the target
# user's profile, never the technician's. Classic Outlook's AppData\Local\Microsoft\Outlook is never touched.
if (-not $console.ProfilePath) { Add-Warning 'Target profile path unavailable; local data not checked.' }
else {
    $olk = Join-Path $console.ProfilePath 'AppData\Local\Microsoft\Olk'
    $pkg = Join-Path $console.ProfilePath ('AppData\Local\Packages\' + $script:PackageFamily)
    $o.DataFolder = $olk; $o.DataFolderExists = Test-Path -LiteralPath $olk -PathType Container
    if ($null -eq $o.NewOutlookInstalled) { $o.NewOutlookInstalled = (Test-Path -LiteralPath $pkg -PathType Container); Add-Warning 'Install state inferred from the package folder; the version needs admin for another user.' }
    $o.DataFolders = @(Invoke-Section 'Data folders' {
        $rows = @()
        foreach ($spec in @(@('Olk\EBWebView', (Join-Path $olk 'EBWebView')), @('Olk\Attachments', (Join-Path $olk 'Attachments')),
                            @('Olk\pst_index_v2', (Join-Path $olk 'pst_index_v2')), @('Olk\logs', (Join-Path $olk 'logs')),
                            @('Package\LocalState', (Join-Path $pkg 'LocalState')), @('Package\LocalCache', (Join-Path $pkg 'LocalCache')), @('Package\Settings', (Join-Path $pkg 'Settings')))) {
            if (-not (Test-Path -LiteralPath $spec[1] -PathType Container)) { continue }
            $files = @(Get-ChildItem -LiteralPath $spec[1] -Recurse -File -Force -ErrorAction SilentlyContinue)
            $newest = $files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            $rows += [pscustomobject]@{ Name=$spec[0]; Files=[int]$files.Count; SizeMB=(Round1 (($files | Measure-Object Length -Sum).Sum / 1MB)); LastWrite=$(if ($newest) { $newest.LastWriteTime } else { $null }) }
        }
        $rows
    } -Default @())
    $o.LocalDataFiles = [int](($o.DataFolders | Measure-Object Files -Sum).Sum)
    $o.LocalDataMB = Round1 (($o.DataFolders | Measure-Object SizeMB -Sum).Sum)
    # The WebView2 store is the mailbox cache: present means signed in here, its newest write means activity.
    $store = $o.DataFolders | Where-Object { $_.Name -eq 'Olk\EBWebView' } | Select-Object -First 1
    $o.SignedInHint = [bool]($store -and $store.Files -gt 0)
    $newestRow = if ($store -and $store.LastWrite) { $store } else { $o.DataFolders | Where-Object { $_.LastWrite } | Sort-Object LastWrite -Descending | Select-Object -First 1 }
    if ($newestRow) { $o.LocalDataLastWrite = $newestRow.LastWrite; $o.LocalDataAgeMinutes = [int]([datetime]::Now - $newestRow.LastWrite).TotalMinutes }
}
# Windows account state (dsregcmd describes the running user; only meaningful when that is the target)
if ($console.IsMe) {
    $ds = Invoke-Section 'dsregcmd' { Invoke-Native -FilePath 'dsregcmd.exe' -ArgumentList '/status' }
    if ($ds -and $ds.ExitCode -eq 0) {
        $o.EntraJoined     = [bool](@($ds.Lines | Where-Object { $_ -match '^\s*AzureAdJoined\s*:\s*YES' }).Count)
        $o.WorkplaceJoined = [bool](@($ds.Lines | Where-Object { $_ -match '^\s*WorkplaceJoined\s*:\s*YES' }).Count)
    }
} else { Add-Warning 'Entra and workplace join state describe the running account, so they were skipped for another user.' }

# Service reachability (3 s TCP each; new Outlook is a web client, so these matter more than local state)
$o.ServiceOutlookOffice = Invoke-Section 'outlook.office.com' { Test-TcpPort -ComputerName 'outlook.office.com' -Port 443 }
$o.ServiceOutlookLive   = Invoke-Section 'outlook.live.com'   { Test-TcpPort -ComputerName 'outlook.live.com' -Port 443 }
$o.ServiceLogin         = Invoke-Section 'login.microsoftonline.com' { Test-TcpPort -ComputerName 'login.microsoftonline.com' -Port 443 }

# Verdict: a hint for the technician; new Outlook keeps mail on the server, so Outlook on the web is the authority
$verdict = $null; $next = $null
if ($o.NewOutlookInstalled -eq $false) { $verdict = 'New Outlook is not installed for this user'; $next = 'Install it from the Store or the classic Outlook toggle, or use classic Outlook.' }
elseif ($o.WebView2Present -eq $false) { $verdict = 'WebView2 runtime is missing; new Outlook cannot start'; $next = 'Install the Microsoft Edge WebView2 Runtime, then open new Outlook again.' }
elseif ($o.ServiceOutlookOffice -eq $false -and $o.ServiceOutlookLive -eq $false) { $verdict = 'Microsoft 365 endpoints are unreachable'; $next = 'This is a network problem. Run Connectivity; check proxy and firewall before touching the app.' }
elseif ($o.ServiceLogin -eq $false) { $verdict = 'Sign-in endpoint is unreachable'; $next = 'login.microsoftonline.com is blocked or down; the app cannot authenticate. Run Connectivity.' }
elseif ($o.SignedInHint -eq $false) { $verdict = 'No local mailbox data on this PC'; $next = 'The app has not signed in here (or offline mail is off). Open it and add the account; mail itself lives on the server.' }
elseif ($o.NewOutlookRunning -eq $false) { $verdict = 'New Outlook is not running'; $next = 'Open it. If it will not start, check WebView2 and Windows updates; if it opens blank, run the New Outlook cache reset.' }
elseif ($null -ne $o.LocalDataAgeMinutes -and $o.LocalDataAgeMinutes -le $StaleMinutes) { $verdict = 'Local data active and service reachable'; $next = 'If mail is missing on screen, check the folder filter and sort, Focused/Other, and compare with Outlook on the web. The cache reset is not needed.' }
elseif ($null -ne $o.LocalDataAgeMinutes) { $verdict = 'Local data is not updating'; $next = 'Check sign-in (Settings > Accounts) and Outlook on the web. If the app stays stuck, run the New Outlook cache reset.' }
else { $verdict = 'Inconclusive'; $next = 'Read the fields above; compare with Outlook on the web.' }
$o.Verdict = $verdict; $o.NextStep = $next
Add-Warning 'New Outlook exposes no mailbox to automation; this reports app, data and service signals only. Outlook on the web is the authority.'

$o.Warnings = $script:Warnings -join '; '
$result = [pscustomobject]$o
if ($Display) { $result | Show-Result -Title $script:ToolName -ReportPath $ReportPath } else { $result }
