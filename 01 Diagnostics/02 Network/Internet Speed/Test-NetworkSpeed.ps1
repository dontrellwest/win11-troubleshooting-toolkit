# Test-NetworkSpeed.ps1  -  network speed test, no install
#
# Run it straight off the flash drive. Three ways, all supported:
#
#   1. Double-click Test-NetworkSpeed.cmd, which sits next to this file.
#      A .ps1 cannot be launched by double-click, hence the small launcher.
#
#   2. From a prompt:
#      powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-NetworkSpeed.ps1
#
#   3. Pasted straight into an already-open PowerShell window.
#
# Words after the filename, any combination:
#   KeyValue     KEY=VALUE output for RMM, N-central, or logging
#   SkipUpload   skip the upload leg
#   NoPause      do not wait for Enter at the end
#
# Exit codes match Test-NetworkSpeed-NoPowerShell.cmd:  0 ok,  1 download failed.
# Exit and pause are both suppressed when pasted, since either would close
# or hang the console you are sitting in.
#
# Written to survive pasting. Two rules make that work, do not break them:
#   - No param() block. param() is invalid at an interactive prompt.
#   - No blank lines inside braces. A blank line submits the console buffer
#     and cuts the block in half.
#
# Uses Cloudflare's public speed test endpoints, not Ookla's Speedtest CLI,
# whose license limits it to personal non-commercial use.
# Installs nothing and writes nothing to disk. The upload payload is built
# in memory, so unlike the .cmd there is no temp file at all.
#
# Note this honors the per-user WinINET proxy, and Test-NetworkSpeed-NoPowerShell.cmd does not.
# When the two disagree on the same machine, a proxy is usually the reason.
# The proxy in use is printed below so you can see it rather than guess.
#
# Single stream, so the download figure is a floor, not the line's capacity.
# Run ONE machine at a time per site, or they contend and all read low.

$ErrorActionPreference = 'Stop'

# No script path means it was pasted, not run as a file.
$Pasted = -not $MyInvocation.MyCommand.Path

$Format = 'Text'
$SkipUpload = $false
$NoPause = $false
if ($args) {
    if ($args -contains 'KeyValue') { $Format = 'KeyValue' }
    if ($args -contains 'SkipUpload') { $SkipUpload = $true }
    if ($args -contains 'NoPause') { $NoPause = $true }
}

# Catch anything that throws outside the handled sections and hold the window
# open long enough to read it. Without this, a script launched from Explorer
# vanishes the instant it fails, which tells you nothing. A trap is used here
# rather than wrapping the file in try/catch because trap stays paste-safe.
trap {
    Write-Host ''
    Write-Host ('  ERROR: ' + $_.Exception.Message)
    Write-Host ('  at line ' + $_.InvocationInfo.ScriptLineNumber)
    Write-Host ''
    if (-not $Pasted -and -not $NoPause) { $null = Read-Host '  Press Enter to close' }
    if (-not $Pasted) { exit 1 }
    continue
}

$DownloadBytes = 25MB
$UploadBytes = 10MB
$down = "https://speed.cloudflare.com/__down?bytes=$DownloadBytes"
$probe = 'https://speed.cloudflare.com/__down?bytes=0'
$up = 'https://speed.cloudflare.com/__up'

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
[Net.ServicePointManager]::Expect100Continue = $false
# Default is 2 concurrent connections per host, which throttles nothing here
# but costs a stall if a socket lingers. Cheap insurance.
[Net.ServicePointManager]::DefaultConnectionLimit = 10

$latencyMs = $null
$jitterMs = $null
$downMbps = $null
$upMbps = $null
$publicIp = $null
$edge = $null
$proxy = 'none'
$notes = @()

if ($Format -eq 'Text') {
    Write-Host ''
    Write-Host "  Network speed test  -  $env:COMPUTERNAME"
    Write-Host '  ------------------------------------------------'
    Write-Host '  Testing, give it a few seconds...'
    Write-Host ''
}

# Which proxy, if any, .NET will actually use for these requests.
try {
    $p = [Net.WebRequest]::GetSystemWebProxy()
    $viaUri = $p.GetProxy([Uri]$probe)
    if ($viaUri.AbsoluteUri -notlike "$probe*") { $proxy = $viaUri.GetLeftPart([UriPartial]::Authority) }
} catch {
    $notes += "proxy check failed: $($_.Exception.Message)"
}

# One HTTP probe, purely to read back who Cloudflare thinks we are and
# which edge answered. Not timed, because the timing would be misleading:
# this endpoint runs a Worker that costs 30-40 ms of server think time,
# which has nothing to do with the network.
try {
    $req = [Net.HttpWebRequest]::Create($probe)
    $req.Method = 'HEAD'
    $req.Timeout = 15000
    $resp = $req.GetResponse()
    $publicIp = $resp.Headers['cf-meta-ip']
    $ray = $resp.Headers['CF-RAY']
    if ($ray -and $ray.Contains('-')) { $edge = $ray.Split('-')[-1] }
    $resp.Close()
} catch {
    $notes += "probe failed: $($_.Exception.Message)"
}

# Latency, measured as a bare TCP handshake to port 443, which is exactly
# one round trip and carries no server processing. This is the same thing
# Test-NetworkSpeed-NoPowerShell.cmd reports, so the two scripts agree on the same machine.
# DNS is resolved once up front and the connects go to the address, so the
# resolver never lands inside a timed sample.
$latencyMethod = 'TCP handshake'
try {
    $addr = [Net.Dns]::GetHostAddresses('speed.cloudflare.com') | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
    if (-not $addr) { throw 'no IPv4 address resolved' }
    $samples = @()
    for ($i = 0; $i -lt 6; $i++) {
        try {
            $tcp = New-Object Net.Sockets.TcpClient
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $tcp.Connect($addr, 443)
            $sw.Stop()
            $tcp.Close()
            $samples += $sw.Elapsed.TotalMilliseconds
        } catch {
            $tcp = $null
        }
        Start-Sleep -Milliseconds 80
    }
    if ($samples.Count -lt 2) { throw 'no usable samples, port 443 may be forced through a proxy' }
    $sorted = $samples | Sort-Object
    $latencyMs = [math]::Round($sorted[0], 1)
    $median = $sorted[[int]($sorted.Count / 2)]
    $jitterMs = [math]::Round($median - $sorted[0], 1)
} catch {
    $notes += "TCP latency failed, falling back to HTTP timing: $($_.Exception.Message)"
    $latencyMethod = 'HTTP round trip, includes server think time'
    try {
        $samples = @()
        for ($i = 0; $i -lt 6; $i++) {
            $req = [Net.HttpWebRequest]::Create($probe)
            $req.Method = 'HEAD'
            $req.Timeout = 15000
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $resp = $req.GetResponse()
            $sw.Stop()
            $resp.Close()
            $samples += $sw.Elapsed.TotalMilliseconds
            Start-Sleep -Milliseconds 80
        }
        $sorted = $samples | Sort-Object
        $latencyMs = [math]::Round($sorted[0], 1)
        $median = $sorted[[int]($sorted.Count / 2)]
        $jitterMs = [math]::Round($median - $sorted[0], 1)
    } catch {
        $notes += "latency failed: $($_.Exception.Message)"
    }
}

# Download
try {
    $wc = New-Object Net.WebClient
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $data = $wc.DownloadData($down)
    $sw.Stop()
    $wc.Dispose()
    $secs = $sw.Elapsed.TotalSeconds
    if ($secs -le 0.01) { throw "finished in $([math]::Round($secs,3))s, too fast to measure" }
    if ($data.Length -le 0) { throw 'zero bytes returned' }
    if ($data.Length -lt $DownloadBytes) { $notes += "short read: got $($data.Length) of $DownloadBytes bytes" }
    $downMbps = [math]::Round((($data.Length * 8) / $secs / 1e6), 1)
    $data = $null
} catch {
    $notes += "download failed: $($_.Exception.Message)"
}

# Upload. Random bytes, not zeros, so nothing on the path can compress it
# and hand back a flattering number.
if (-not $SkipUpload) {
    try {
        $payload = New-Object byte[] $UploadBytes
        (New-Object Random).NextBytes($payload)
        $wc = New-Object Net.WebClient
        $wc.Headers.Add('Content-Type', 'application/octet-stream')
        $sw = [Diagnostics.Stopwatch]::StartNew()
        [void]$wc.UploadData($up, 'POST', $payload)
        $sw.Stop()
        $wc.Dispose()
        $secs = $sw.Elapsed.TotalSeconds
        if ($secs -le 0.01) { throw "finished in $([math]::Round($secs,3))s, too fast to measure" }
        $upMbps = [math]::Round((($UploadBytes * 8) / $secs / 1e6), 1)
        $payload = $null
        [GC]::Collect()
    } catch {
        $notes += "upload failed: $($_.Exception.Message)"
    }
}

# Output
if ($Format -eq 'KeyValue') {
    Write-Output "COMPUTER=$env:COMPUTERNAME"
    Write-Output "USER=$env:USERNAME"
    Write-Output ('TIMESTAMP=' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))
    Write-Output "LATENCY_MS=$latencyMs"
    Write-Output "LATENCY_METHOD=$latencyMethod"
    Write-Output "JITTER_MS=$jitterMs"
    Write-Output "DOWN_MBPS=$downMbps"
    Write-Output "UP_MBPS=$(if ($SkipUpload) { 'skipped' } else { $upMbps })"
    Write-Output "PUBLIC_IP=$publicIp"
    Write-Output "EDGE=$edge"
    Write-Output "PROXY=$proxy"
    if ($notes) { Write-Output ('NOTES=' + ($notes -join '; ')) }
    Write-Output 'NOTE=Single stream, DOWN_MBPS is a floor. See LATENCY_METHOD for what LATENCY_MS measured.'
} else {
    if ($null -ne $latencyMs) {
        Write-Host ('  Latency   {0,-11} (jitter {1} ms, {2})' -f "$latencyMs ms", $jitterMs, $latencyMethod)
    } else {
        Write-Host '  Latency   FAILED'
    }
    if ($null -ne $downMbps) {
        Write-Host ('  Down      {0,-11} ({1} MB/s)' -f "$downMbps Mbps", [math]::Round($downMbps / 8, 1))
    } else {
        Write-Host '  Down      FAILED'
    }
    if ($SkipUpload) {
        Write-Host '  Up        skipped'
    } elseif ($null -ne $upMbps) {
        Write-Host ('  Up        {0,-11} ({1} MB/s)' -f "$upMbps Mbps", [math]::Round($upMbps / 8, 1))
    } else {
        Write-Host '  Up        FAILED'
    }
    Write-Host ''
    Write-Host ('  Public IP {0}    Edge {1}    Proxy {2}' -f $publicIp, $edge, $proxy)
    Write-Host '  Single stream. Treat Down as a floor, not the line''s capacity.'
    Write-Host ''
    foreach ($n in $notes) { Write-Warning $n }
}

# Pause only when run as a file in text mode. Pasting never pauses, because
# Read-Host would swallow whatever you paste next.
if (-not $Pasted -and $Format -eq 'Text' -and -not $NoPause) {
    Read-Host '  Press Enter to close'
}

# exit would close the console if pasted, so only do it as a file.
if (-not $Pasted) {
    if ($null -eq $downMbps) { exit 1 }
    exit 0
}
