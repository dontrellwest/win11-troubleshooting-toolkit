<#
.SYNOPSIS
    Tell a sync problem from a display problem in classic Outlook before rebuilding the OST.
.DESCRIPTION
    Read-only diagnostics for the signed-in user's classic Outlook: connection mode, Work Offline,
    cached mode and sync window, OST files and how recently they were written, the view and filter
    on screen, the newest Inbox item and the Sync Issues count. Attaches to a running Outlook only;
    it never starts, changes or closes it.
.PARAMETER Display
    Show the report instead of emitting objects.
.PARAMETER ReportPath
    Save the displayed report to this folder.
.PARAMETER TargetUser
    DOMAIN\user to report on when the signed-in user cannot be resolved.
.PARAMETER StaleMinutes
    Minutes after which the newest OST write or Inbox item counts as stale. Default 60.
.EXAMPLE
    .\Get-OutlookSyncState.ps1 -Display
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
$script:ToolName  = 'Get-OutlookSyncState'
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
function Get-SessionProcessCount {
    param([string]$Name, $User)
    if ($null -eq $User.SessionId) { return $null }
    @(Get-CimInstance Win32_Process -Filter ("Name='{0}' AND SessionId={1}" -f $Name, [int]$User.SessionId) -ErrorAction Stop).Count
}
function Expand-TargetProfilePath {
    param([string]$Path, [string]$ProfilePath)
    if (-not $Path) { return $null }
    $p = $Path
    if ($ProfilePath) {
        $p = [regex]::Replace($p, '%USERPROFILE%', $ProfilePath.Replace('$', '$$'), 'IgnoreCase')
        $p = [regex]::Replace($p, '%LOCALAPPDATA%', (Join-Path $ProfilePath 'AppData\Local').Replace('$', '$$'), 'IgnoreCase')
        $p = [regex]::Replace($p, '%APPDATA%', (Join-Path $ProfilePath 'AppData\Roaming').Replace('$', '$$'), 'IgnoreCase')
    }
    $p
}
function Get-RegValue {
    param([string]$Key, [string]$Name)
    if (-not (Test-Path -LiteralPath $Key)) { return $null }
    $item = Get-ItemProperty -LiteralPath $Key -ErrorAction Stop
    if ($null -eq $item.PSObject.Properties[$Name]) { return $null }
    $item.$Name
}
$connModes = @{ 0='No Exchange account'; 100='Working Offline'; 200='Cached mode, offline'; 300='Online, disconnected';
                400='Cached mode, disconnected'; 500='Cached mode, connected (headers only)'; 600='Cached mode, connected (drizzle)';
                700='Cached mode, connected (full items)'; 800='Online, connected' }

$console = Get-ConsoleUser -OverrideName $TargetUser
if ($console.OtherDesktops -and -not $TargetUser) { Add-Warning ("Other desktops: " + $console.OtherDesktops) }
$o = [ordered]@{
    ComputerName=$env:COMPUTERNAME; CollectedAt=[datetime]::Now
    TargetUser=$console.Name; RunningAs=$console.RunningAs; TargetSource=$console.Source
    ClassicOutlookInstalled=$null; ClassicOutlookVersion=$null; ClassicOutlookRunning=$null; NewOutlookRunning=$null
    DefaultProfile=$null; ProfileCount=$null
    ConnectionMode=$null; WorkingOffline=$null; ExchangeMailboxPresent=$null; CachedModeEnabled=$null
    SyncWindowMonths=$null; SyncWindowSource=$null
    OstFolder=$null; OstFileCount=$null; OstSizeMB=$null; OstLimitGB=$null; OstLastWrite=$null; OstAgeMinutes=$null
    InboxItemCount=$null; InboxUnreadCount=$null; NewestInboxReceived=$null; NewestInboxAgeMinutes=$null
    ActiveFolder=$null; ActiveViewName=$null; ActiveViewFilter=$null; InboxViewName=$null; InboxViewFilter=$null
    SyncIssuesCount=$null; Verdict=$null; NextStep=$null
    Stores=@(); Accounts=@(); OstFiles=@(); Warnings=''
}

# Install (machine-wide, readable by anyone)
$exe = Invoke-Section 'Outlook install' { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE' -ErrorAction Stop).'(default)' }
$o.ClassicOutlookInstalled = [bool]($exe -and (Test-Path -LiteralPath $exe))
if ($o.ClassicOutlookInstalled) { $o.ClassicOutlookVersion = Invoke-Section 'Outlook version' { (Get-Item -LiteralPath $exe).VersionInfo.ProductVersion } }

# Processes in the target user's session only
if ($null -eq $console.SessionId) { Add-Warning 'Target user has no live desktop; running-state and Outlook automation checks skipped.' }
else {
    $o.ClassicOutlookRunning = Invoke-Section 'Outlook process' { [bool](Get-SessionProcessCount 'OUTLOOK.EXE' $console) }
    $o.NewOutlookRunning     = Invoke-Section 'New Outlook process' { [bool](Get-SessionProcessCount 'olk.exe' $console) }
}

# Registry: profile, cached mode, sync window, OST size limit (target user's hive, never HKCU)
if (-not $console.Hive) { Add-Warning 'Target registry hive unavailable; profile, cached mode, sync window and OST limit are unknown.' }
else {
    $ok = $console.Hive + '\Software\Microsoft\Office\16.0\Outlook'
    $pk = $console.Hive + '\Software\Policies\Microsoft\office\16.0\outlook'
    $prof = Invoke-Section 'Outlook profile' {
        $name = Get-RegValue $ok 'DefaultProfile'
        $count = if (Test-Path -LiteralPath ($ok + '\Profiles')) { @(Get-ChildItem -LiteralPath ($ok + '\Profiles') -ErrorAction Stop).Count } else { 0 }
        [pscustomobject]@{ DefaultProfile=$name; ProfileCount=[int]$count }
    }
    if ($prof) { $o.DefaultProfile = $prof.DefaultProfile; $o.ProfileCount = $prof.ProfileCount }
    $win = Invoke-Section 'Sync window' {
        $v = Get-RegValue ($pk + '\cached mode') 'SyncWindowSetting'; $src = 'Policy'
        if ($null -eq $v) { $v = Get-RegValue ($ok + '\Cached Mode') 'SyncWindowSetting'; $src = 'User setting' }
        if ($null -eq $v) { $src = 'Default' }
        [pscustomobject]@{ Months=$(if ($null -ne $v) { [int]$v } else { $null }); Source=$src }
    }
    if ($win) { $o.SyncWindowMonths = $win.Months; $o.SyncWindowSource = $win.Source }
    $o.CachedModeEnabled = Invoke-Section 'Cached mode flag' {
        $forced = Get-RegValue ($pk + '\cached mode') 'Enable'
        if ($null -ne $forced) { return [bool]([int]$forced -ne 0) }
        if (-not $o.DefaultProfile) { return $null }
        $bytes = Get-RegValue ($ok + '\Profiles\' + $o.DefaultProfile + '\13dbb0c8aa05101a9bb000aa002fc45a') '00036601'
        if ($bytes -is [byte[]] -and $bytes.Length -ge 1) { [bool]($bytes[0] -band 0x80) } else { $null }
    }
    $limitMb = Invoke-Section 'OST size limit' {
        $v = Get-RegValue ($pk + '\pst') 'MaxLargeFileSize'
        if ($null -eq $v) { $v = Get-RegValue ($ok + '\PST') 'MaxLargeFileSize' }
        if ($null -eq $v) { 51200 } else { [int]$v }
    }
    if ($null -ne $limitMb) { $o.OstLimitGB = Round1 ($limitMb / 1024) }
}

# OST files on disk (target user's profile path, never the technician's)
if (-not $console.ProfilePath) { Add-Warning 'Target profile path unavailable; OST files not checked.' }
else {
    $folder = Join-Path $console.ProfilePath 'AppData\Local\Microsoft\Outlook'
    if ($console.Hive) {
        foreach ($k in @(($console.Hive + '\Software\Policies\Microsoft\Office\16.0\Outlook'), ($console.Hive + '\Software\Microsoft\Office\16.0\Outlook'))) {
            $forced = Invoke-Section 'ForceOSTPath' { Get-RegValue $k 'ForceOSTPath' }
            if ($forced) { $folder = Expand-TargetProfilePath ([string]$forced) $console.ProfilePath; break }
        }
    }
    $o.OstFolder = $folder
    $o.OstFiles = @(Invoke-Section 'OST files' {
        if (-not (Test-Path -LiteralPath $folder -PathType Container)) { return @() }
        @(Get-ChildItem -LiteralPath $folder -File -Force -Filter '*.ost' -ErrorAction Stop | Where-Object { $_.Extension -ieq '.ost' } | ForEach-Object {
            [pscustomobject]@{ Name=$_.Name; SizeMB=(Round1 ($_.Length / 1MB)); LastWrite=$_.LastWriteTime; AgeMinutes=[int]([datetime]::Now - $_.LastWriteTime).TotalMinutes }
        })
    } -Default @())
    $o.OstFileCount = $o.OstFiles.Count
    if ($o.OstFileCount) {
        $o.OstSizeMB = Round1 (($o.OstFiles | Measure-Object SizeMB -Sum).Sum)
        $newest = $o.OstFiles | Sort-Object LastWrite -Descending | Select-Object -First 1
        $o.OstLastWrite = $newest.LastWrite; $o.OstAgeMinutes = $newest.AgeMinutes
        if ($null -ne $o.OstLimitGB -and ($o.OstSizeMB / 1024) -ge ($o.OstLimitGB * 0.9)) { Add-Warning ('OST is within 10% of the {0} GB limit; Outlook stops syncing at the limit.' -f $o.OstLimitGB) }
    }
}

# Outlook automation: attach to the user's running instance only. Never start it, never close it.
$app = $null
if (-not $console.IsMe) { Add-Warning 'Outlook automation is only reachable from the signed-in user''s own session; run unelevated as that user for connection, view and mailbox checks.' }
elseif (-not $o.ClassicOutlookRunning) { Add-Warning 'Classic Outlook is not running; open it and rerun for connection, view and mailbox checks.' }
else {
    $app = Invoke-Section 'Outlook automation' {
        try { [Runtime.InteropServices.Marshal]::GetActiveObject('Outlook.Application') }
        catch {
            # Outlook is single-instance: with a process already running in this session this attaches rather than launching.
            if (Get-SessionProcessCount 'OUTLOOK.EXE' $console) { New-Object -ComObject Outlook.Application } else { throw 'Outlook exited before it could be reached' }
        }
    }
}
if ($app) {
    $ns = $null
    try {
        $ns = $app.GetNamespace('MAPI')
        $mode = Invoke-Section 'Connection mode' { [int]$ns.ExchangeConnectionMode }
        if ($null -ne $mode) { $o.ConnectionMode = if ($connModes.ContainsKey($mode)) { $connModes[$mode] } else { "Unknown ($mode)" } }
        $o.WorkingOffline = Invoke-Section 'Work Offline' { [bool]$ns.Offline }
        $o.Stores = @(Invoke-Section 'Stores' {
            @(foreach ($s in $ns.Stores) {
                $t = [int]$s.ExchangeStoreType
                [pscustomobject]@{ Name=[string]$s.DisplayName; Type=$(switch ($t) { 0 {'Exchange mailbox (primary)'} 1 {'Exchange mailbox'} 2 {'Exchange public folders'} 3 {'Not Exchange'} 4 {'Exchange mailbox (additional)'} default {"Other ($t)"} }); CachedMode=[bool]$s.IsCachedExchange; File=[string]$s.FilePath }
            })
        } -Default @())
        $o.ExchangeMailboxPresent = [bool](@($o.Stores | Where-Object { $_.Type -like 'Exchange mailbox*' }).Count)
        if ($null -eq $o.CachedModeEnabled -and $o.ExchangeMailboxPresent) { $o.CachedModeEnabled = [bool](@($o.Stores | Where-Object { $_.Type -like 'Exchange mailbox*' -and $_.CachedMode }).Count) }
        $o.Accounts = @(Invoke-Section 'Accounts' {
            @(foreach ($a in $ns.Accounts) { [pscustomobject]@{ Name=[string]$a.DisplayName; Type=$(switch ([int]$a.AccountType) { 0 {'Exchange'} 1 {'IMAP'} 2 {'POP3'} 3 {'HTTP'} 4 {'EAS'} default {"Other ($([int]$a.AccountType))"} }); Address=[string]$a.SmtpAddress } })
        } -Default @())
        $inboxInfo = Invoke-Section 'Inbox' {
            $inbox = $ns.GetDefaultFolder(6)
            $items = $inbox.Items; $items.Sort('[ReceivedTime]', $true); $first = $items.GetFirst()
            $received = if ($first -and $first.ReceivedTime) { [datetime]$first.ReceivedTime } else { $null }
            [pscustomobject]@{ Count=[int]$inbox.Items.Count; Unread=[int]$inbox.UnReadItemCount; View=[string]$inbox.CurrentView.Name; Filter=[string]$inbox.CurrentView.Filter; Newest=$received }
        }
        if ($inboxInfo) {
            $o.InboxItemCount = $inboxInfo.Count; $o.InboxUnreadCount = $inboxInfo.Unread
            $o.InboxViewName = $inboxInfo.View; $o.InboxViewFilter = $inboxInfo.Filter
            if ($inboxInfo.Newest) { $o.NewestInboxReceived = $inboxInfo.Newest; $o.NewestInboxAgeMinutes = [int]([datetime]::Now - $inboxInfo.Newest).TotalMinutes }
        }
        $active = Invoke-Section 'Active window' {
            $ex = $app.ActiveExplorer()
            if (-not $ex) { return $null }
            [pscustomobject]@{ Folder=[string]$ex.CurrentFolder.Name; View=[string]$ex.CurrentView.Name; Filter=[string]$ex.CurrentView.Filter }
        }
        if ($active) { $o.ActiveFolder = $active.Folder; $o.ActiveViewName = $active.View; $o.ActiveViewFilter = $active.Filter }
        else { Add-Warning 'No Outlook window is open; the on-screen view could not be read.' }
        if ($o.ExchangeMailboxPresent) {
            $o.SyncIssuesCount = Invoke-Section 'Sync Issues folder' { [int]$ns.GetDefaultFolder(20).Items.Count }
        }
    } finally {
        foreach ($v in @($ns, $app)) { if ($v) { try { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($v) } catch { } } }
    }
}

# Verdict: a hint for the technician, not a diagnosis
$verdict = $null; $next = $null
if ($o.WorkingOffline -eq $true) { $verdict = 'Working Offline is on'; $next = 'Send/Receive tab > Work Offline to turn it off, then check again.' }
elseif ($o.ExchangeMailboxPresent -eq $false) { $verdict = 'No Exchange mailbox in this profile'; $next = 'An OST rebuild does not apply. Check the account setup instead.' }
elseif ($o.ActiveViewFilter) { $verdict = 'Mailbox reachable; a view filter is hiding mail'; $next = ('View > Reset View on the {0} folder, or clear the filter.' -f $o.ActiveFolder) }
elseif ($o.ConnectionMode -in @('Cached mode, connected (full items)', 'Online, connected') -and -not $o.SyncIssuesCount -and $null -ne $o.OstAgeMinutes -and $o.OstAgeMinutes -le $StaleMinutes) {
    $verdict = 'Sync looks healthy'; $next = 'If mail is missing on screen this is a display problem: View > Reset View, then check the sort order and Focused/Other. Do not rebuild the OST.' }
elseif (($o.ConnectionMode -and $o.ConnectionMode -notmatch 'connected') -or ($null -ne $o.OstAgeMinutes -and $o.OstAgeMinutes -gt $StaleMinutes) -or ($o.SyncIssuesCount -gt 0)) {
    $verdict = 'Sync is not keeping up'; $next = 'Check connectivity and sign-in first (Connectivity, Logon Health). If it persists with mail current on the web, the OST rebuild applies.' }
elseif ($null -eq $o.ConnectionMode) { $verdict = 'Inconclusive: Outlook not reachable'; $next = 'Open classic Outlook as the signed-in user and rerun.' }
else { $verdict = 'Inconclusive'; $next = 'Read the fields above; compare with Outlook on the web.' }
$o.Verdict = $verdict; $o.NextStep = $next
Add-Warning 'Verdict is a hint from local signals; Outlook on the web is the authority on what the server holds.'

$o.Warnings = $script:Warnings -join '; '
$result = [pscustomobject]$o
if ($Display) { $result | Show-Result -Title $script:ToolName -ReportPath $ReportPath } else { $result }
