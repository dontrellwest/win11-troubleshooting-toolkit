function Get-TkNetworkSnapshot {
    foreach($a in @(Get-NetAdapter -ErrorAction Stop | Sort-Object InterfaceIndex)){Add-TkResult 'Adapter' ([string]$a.InterfaceIndex) ([string]$a.Status) ($a.Name+'; '+$a.LinkSpeed)}
    foreach($ip in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Sort-Object InterfaceIndex,IPAddress)){Add-TkResult 'IPv4' ($ip.InterfaceIndex.ToString()+' '+$ip.IPAddress) 'Observed' ('Prefix='+$ip.PrefixLength+'; '+$ip.PrefixOrigin)}
    foreach($dns in @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Sort-Object InterfaceIndex)){Add-TkResult 'DNS servers' ([string]$dns.InterfaceIndex) 'Observed' ($dns.ServerAddresses -join ', ')}
    $target=[string]$script:Options.Target;if(-not $target){$target='www.microsoft.com'}
    try {$addresses=@([Net.Dns]::GetHostAddresses($target) | ForEach-Object IPAddressToString | Sort-Object);Add-TkResult 'DNS lookup' $target 'Succeeded' ($addresses -join ', ')}catch{Add-TkResult 'DNS lookup' $target 'Failed' $_.Exception.Message}
    $ok=Test-TkTcp $target 443
    $status='Failed';if($ok){$status='Reachable'}
    Add-TkResult 'TCP 443' $target $status 'A TCP connection does not verify sign-in or application service health.'
}
function Get-TkDefaultGateway {
    # A missing default route is a finding, not a failure: Get-NetRoute throws when nothing matches.
    $routes=@();try{$routes=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop)}catch{return $null}
    $candidates=foreach($route in $routes){
        try{$iface=Get-NetIPInterface -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop}catch{continue}
        if($iface.ConnectionState -eq 'Connected'){[pscustomobject]@{Gateway=$route.NextHop;InterfaceIndex=$route.InterfaceIndex;Metric=([int]$route.RouteMetric+[int]$iface.InterfaceMetric)}}
    }
    $candidates | Sort-Object Metric | Select-Object -First 1
}
function Monitor-TkNetwork {
    $target=Get-TkChoice 'Target' 'DNS name of the failing service (no URL)' @()
    if($target -match '[\s/\\]' -or $target.StartsWith('-')){throw 'Use a DNS name or IP address, not a URL or command option.'}
    $count=[int]$script:Options.Samples;$interval=[int]$script:Options.IntervalSeconds
    for($i=1;$i -le $count;$i++){
        $gateway=Get-TkDefaultGateway
        if($gateway){$ping=New-Object Net.NetworkInformation.Ping;try{$reply=$ping.Send($gateway.Gateway,1000);Add-TkResult 'Gateway sample' "$i $($gateway.Gateway)" ([string]$reply.Status) ('RTT ms='+$reply.RoundtripTime)}catch{Add-TkResult 'Gateway sample' "$i" 'Unavailable' $_.Exception.Message}finally{$ping.Dispose()}}
        else {Add-TkResult 'Gateway sample' "$i" 'Unavailable' 'No connected IPv4 default route.'}
        try {$dns=@(Resolve-DnsName -Name $target -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object IPAddress | ForEach-Object IPAddress);Add-TkResult 'DNS sample' "$i $target" 'Succeeded' ($dns -join ', ')}catch{Add-TkResult 'DNS sample' "$i $target" 'Failed' $_.Exception.Message}
        $sw=[Diagnostics.Stopwatch]::StartNew();$ok=Test-TkTcp $target ([int]$script:Options.Port);$sw.Stop();$status='Failed';if($ok){$status='Reachable'}
        Add-TkResult 'TCP sample' "$i $target" $status ('Port='+$script:Options.Port+'; elapsed ms='+$sw.ElapsedMilliseconds)
        if($script:Options.Display){Write-Host ("Sample {0}/{1}: TCP {2}" -f $i,$count,$status)}
        if($i -lt $count){Start-Sleep -Seconds $interval}
    }
    try {foreach($e in @(Get-TkEvents -Log 'Microsoft-Windows-WLAN-AutoConfig/Operational' -Hours 72 -Maximum 60)){Add-TkResult 'Wi-Fi history' ($e.Time.ToString('o')+' '+$e.Id) 'Observed' $e.Message}}catch{Add-TkResult 'Wi-Fi history' 'Last 72 hours' 'Unavailable' $_.Exception.Message}
    Add-TkHumanCheck 'Correlate failed samples with the user-reported dropouts. Some gateways intentionally ignore ping.'
}
function Repair-TkNetwork {
    $action=Get-TkChoice 'Action' 'Choose the repair justified by the network check' @('ClearDnsCache','RenewDhcp')
    Assert-TkAdmin
    Get-TkNetworkSnapshot
    $target='Local DNS client cache'
    if($action -eq 'RenewDhcp'){
        if([int]$script:Options.InterfaceIndex -le 0){
            $script:Options.InterfaceIndex=$null
            if($script:Options.Interactive){Get-NetAdapter -ErrorAction Stop | Select-Object InterfaceIndex,Name,Status | Format-Table -AutoSize | Out-Host}
        }
        $index=Get-TkChoice 'InterfaceIndex' 'Exact adapter InterfaceIndex from the check' @()
        $indexNumber=0
        if(-not [int]::TryParse($index,[ref]$indexNumber) -or $indexNumber -le 0){throw 'InterfaceIndex must be a positive adapter index.'}
        $adapter=@(Get-NetAdapter -InterfaceIndex ([int]$index) -ErrorAction Stop)
        if($adapter.Count -ne 1){throw 'Exactly one network adapter is required.'}
        $config=@(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter ("InterfaceIndex={0}" -f [int]$index) -ErrorAction Stop | Where-Object IPEnabled)
        if($config.Count -ne 1 -or -not $config[0].DHCPEnabled){throw 'The selected IPv4 adapter is not using DHCP.'}
        $target=$adapter[0].Name
        Add-TkResult 'Notice' $target 'ConnectionMayDrop' 'DHCP renewal can interrupt this connection, including remote support.'
    }
    $plan='Clear the local DNS resolver cache; adapter settings do not change';if($action -eq 'RenewDhcp'){$plan='Renew the DHCP lease on this adapter only; the connection may drop briefly'}
    if(-not (Approve-TkAction $target $plan)){return}
    if($action -eq 'ClearDnsCache'){Clear-DnsClientCache -ErrorAction Stop}
    else {$result=Invoke-CimMethod -InputObject $config[0] -MethodName RenewDHCPLease -ErrorAction Stop;if($result.ReturnValue -notin 0,1){throw "DHCP renewal returned $($result.ReturnValue)"}}
    Add-TkResult 'Action' $target 'Completed' $action
    Get-TkNetworkSnapshot
    Add-TkHumanCheck 'Retry the original website or network task.'
}
function Repair-TkMappedDrive {
    Assert-TkUser
    if(Test-TkAdmin){throw 'Reconnect mapped drives in a normal, non-administrator window so Explorer sees the same mapping.'}
    $drive=(Get-TkChoice 'DriveLetter' 'Drive letter to reconnect, for example Z:' @()).ToUpperInvariant()
    if($drive -notmatch '^[A-Z]:$'){throw 'Specify one drive letter followed by a colon.'}
    $mappings=@(Get-SmbMapping -ErrorAction Stop | Where-Object LocalPath -eq $drive)
    if($mappings.Count -ne 1){throw 'Exactly one existing SMB mapping must match; this tool does not create a new mapping.'}
    $mapping=$mappings[0];$remote=[string]$mapping.RemotePath
    if($remote -notmatch '^\\\\([^\\]+)\\[^\\]+'){throw 'The mapping is not a supported UNC share.'}
    $server=$Matches[1]
    if(-not (Test-TkTcp $server 445)){throw 'The share server is unreachable on TCP 445. Check VPN, DNS and network first.'}
    if(-not (Test-Path -LiteralPath $remote -ErrorAction Stop)){throw 'The share cannot be accessed with current credentials. Resolve access before reconnecting.'}
    $profileKey='HKCU:\Network\'+$drive.Substring(0,1)
    $persistent=Test-Path -LiteralPath $profileKey
    if($persistent){$profile=Get-ItemProperty -LiteralPath $profileKey -ErrorAction Stop;if($profile.RemotePath -ine $remote){throw 'Saved and active paths differ. Review the mapping manually.'};if($profile.UserName -and $profile.UserName -ine [Security.Principal.WindowsIdentity]::GetCurrent().Name){throw 'This mapping uses alternate credentials. Reconnect it manually to preserve that identity.'}}
    $record=Save-TkEvidence 'mapping-before' ([ordered]@{Drive=$drive;Remote=$remote;Persistent=$persistent;Status=[string]$mapping.Status})
    $plan='Disconnect and recreate only this mapping; close files on this drive first'
    if(-not $persistent){Add-TkResult 'Notice' $drive 'SessionOnlyMapping' 'No saved mapping entry exists, so a different account used to create it cannot be detected. The mapping is recreated under the signed-in account.';$plan+='. Session-only mapping: it is recreated under the signed-in account'}
    if(-not (Approve-TkAction "$drive -> $remote" $plan)){return}
    Remove-SmbMapping -LocalPath $drive -Force -Confirm:$false -ErrorAction Stop
    try {New-SmbMapping -LocalPath $drive -RemotePath $remote -Persistent $persistent -ErrorAction Stop | Out-Null}
    catch {throw "Reconnect failed. Original mapping details are in $record. $($_.Exception.Message)"}
    $after=Get-SmbMapping -LocalPath $drive -ErrorAction Stop
    Add-TkResult 'Mapping' $drive ([string]$after.Status) $remote
    Add-TkHumanCheck 'Open the mapped drive in Explorer and retry the original file operation.'
}
