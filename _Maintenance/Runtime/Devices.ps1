function Get-TkStorage {
    foreach($volume in @(Get-Volume -ErrorAction Stop | Where-Object DriveLetter | Sort-Object DriveLetter)){
        Add-TkResult 'Volume' ([string]$volume.DriveLetter+':') ([string]$volume.HealthStatus) ('FileSystem='+$volume.FileSystem+'; FreeGB='+[math]::Round($volume.SizeRemaining/1GB,2)+'; Operational='+($volume.OperationalStatus -join ','))
        if(Test-TkAdmin){$r=Invoke-TkNative (Join-Path $env:SystemRoot 'System32\fsutil.exe') @('dirty','query',([string]$volume.DriveLetter+':')) -AllowFailure;$status='ReviewOutput';if($r.ExitCode -ne 0){$status='Unavailable'};Add-TkResult 'Dirty bit query' ([string]$volume.DriveLetter+':') $status ('Exit='+$r.ExitCode+'; '+$r.Text)}
        else {Add-TkResult 'Dirty bit query' ([string]$volume.DriveLetter+':') 'Unavailable' 'Run elevated to query the volume dirty bit.'}
    }
    foreach($disk in @(Get-PhysicalDisk -ErrorAction Stop | Sort-Object DeviceId)){
        Add-TkResult 'Physical disk' ([string]$disk.DeviceId) ([string]$disk.HealthStatus) ($disk.FriendlyName+'; '+$disk.MediaType+'; '+($disk.OperationalStatus -join ','))
        try {
            $counter=Get-StorageReliabilityCounter -PhysicalDisk $disk -ErrorAction Stop
            $data=@();foreach($name in 'Temperature','TemperatureMax','Wear','PowerOnHours','ReadErrorsTotal','ReadErrorsUncorrected','WriteErrorsTotal','WriteErrorsUncorrected','ReadLatencyMax','WriteLatencyMax'){
                if($null -ne $counter.$name){$data+=$name+'='+$counter.$name}
            }
            $status='Available';if(-not $data.Count){$status='Unavailable';$data=@('Controller did not expose these counters.')}
            Add-TkResult 'Reliability counters' ([string]$disk.DeviceId) $status ($data -join '; ')
        }catch{Add-TkResult 'Reliability counters' ([string]$disk.DeviceId) 'Unavailable' $_.Exception.Message}
    }
    try {
        $events=@(Get-TkEvents -Log System -Hours 168 -Providers @('disk','Ntfs','Microsoft-Windows-Ntfs','storahci','stornvme','Microsoft-Windows-StorPort') -Maximum 100)
        foreach($e in $events){Add-TkResult 'Storage event' ($e.Time.ToString('o')+' '+$e.Id) $e.Level ($e.Provider+': '+$e.Message)}
        if(-not $events.Count){Add-TkResult 'Storage events' 'Last 7 days' 'NoneFound' 'No matching events in the retained System log.'}
    }catch{Add-TkResult 'Storage events' 'Last 7 days' 'Unavailable' $_.Exception.Message}
    Add-TkHumanCheck 'Repeated I/O errors or unhealthy disks call for data protection and hardware investigation before intensive repairs. Missing counters do not mean a disk is healthy.'
}
function Get-TkDefaultAudio {
    if(-not ('ToolkitAudio.Defaults' -as [type])){
        try {Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace ToolkitAudio {
 [ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] class Enumerator {}
 [ComImport, Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
 interface IEnum {
  [PreserveSig] int EnumAudioEndpoints(int f, uint s, out IntPtr p);
  [PreserveSig] int GetDefaultAudioEndpoint(int f, int r, out IDevice d);
  [PreserveSig] int GetDevice([MarshalAs(UnmanagedType.LPWStr)] string id, out IDevice d);
  [PreserveSig] int RegisterEndpointNotificationCallback(IntPtr p);
  [PreserveSig] int UnregisterEndpointNotificationCallback(IntPtr p);
 }
 [ComImport, Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
 interface IDevice {
  [PreserveSig] int Activate(ref Guid i, uint c, IntPtr p, out IntPtr o);
  [PreserveSig] int OpenPropertyStore(uint a, out IntPtr p);
  [PreserveSig] int GetId([MarshalAs(UnmanagedType.LPWStr)] out string id);
  [PreserveSig] int GetState(out uint s);
 }
 public static class Defaults {
  public static string Get(int flow, int role) {
   IEnum e=(IEnum)new Enumerator(); IDevice d=null;
   try {int hr=e.GetDefaultAudioEndpoint(flow,role,out d); if(hr!=0) Marshal.ThrowExceptionForHR(hr);string id;Marshal.ThrowExceptionForHR(d.GetId(out id));return id;}
   finally {if(d!=null) Marshal.ReleaseComObject(d);Marshal.ReleaseComObject(e);}
  }
 }
}
'@ -ErrorAction Stop}catch{Add-TkResult 'Default audio' 'All' 'Unavailable' ('Cannot load the audio endpoint helper: '+$_.Exception.Message);return}
    }
    foreach($flow in 0,1){foreach($role in 0,2){$label='Playback';if($flow -eq 1){$label='Microphone'};$label+=' / ';if($role -eq 0){$label+='Console'}else{$label+='Communications'}
        try{Add-TkResult 'Default audio' $label 'Selected' ([ToolkitAudio.Defaults]::Get($flow,$role))}catch{Add-TkResult 'Default audio' $label 'Unavailable' $_.Exception.Message}
    }}
}
function Get-TkDevices {
    foreach($name in 'Audiosrv','AudioEndpointBuilder','FrameServer'){$service=Get-Service -Name $name -ErrorAction SilentlyContinue;if($service){Add-TkResult 'Device service' $name ([string]$service.Status) 'Camera FrameServer may be stopped when no app is using the camera.'}else{Add-TkResult 'Device service' $name 'NotPresent' 'This Windows edition does not have the service.'}}
    $devices=@(Get-PnpDevice -PresentOnly -ErrorAction Stop | Where-Object {$_.Class -in 'AudioEndpoint','MEDIA','Camera','Image','USB','Bluetooth','Monitor','Display'} | Sort-Object Class,FriendlyName,InstanceId)
    foreach($device in $devices){Add-TkResult ('Device '+$device.Class) $device.InstanceId ([string]$device.Status) ($device.FriendlyName+'; Problem='+$device.Problem)}
    Get-TkDefaultAudio
    foreach($kind in 'microphone','webcam'){
        foreach($root in 'HKCU:','HKLM:'){
            $path=$root+'\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\'+$kind
            if(Test-Path -LiteralPath $path){$value=Get-ItemProperty -LiteralPath $path -ErrorAction Stop;Add-TkResult 'Privacy consent' ($root+' '+$kind) 'Observed' ([string]$value.Value)}
        }
    }
    Add-TkHumanCheck 'Check the selected device in the affected app too. Test playback, microphone recording, camera preview and dock connections. Permission summaries do not cover every app or organizational policy.'
}
function Get-TkAudioRestartPlan {
    $seen=@{};$plan=New-Object Collections.Generic.List[object]
    function Visit-AudioService {param([string]$Name)
        if($seen.ContainsKey($Name)){return};$seen[$Name]=$true
        if($seen.Count -gt 50){throw 'Unexpectedly large audio dependency tree; review manually.'}
        $service=Get-Service -Name $Name -ErrorAction Stop
        foreach($dependent in @($service.DependentServices)){if($dependent.Status -eq 'Running'){Visit-AudioService $dependent.Name}}
        $plan.Add([pscustomobject]@{Name=$service.Name;Status=[string]$service.Status})
    }
    Visit-AudioService 'Audiosrv'
    $plan.ToArray()
}
function Restart-TkAudioPlan {
    param([object[]]$Plan)
    $stopped=New-Object Collections.Generic.List[string];$allStopped=$false
    try {
        foreach($service in $Plan){if($service.Status -eq 'Running'){Stop-Service -Name $service.Name -ErrorAction Stop;$stopped.Add($service.Name);(Get-Service $service.Name).WaitForStatus('Stopped',[timespan]::FromSeconds(20))}}
        $allStopped=$true
    }finally{
        # Restore in reverse order. A service still in StopPending gets time to settle, and each start is retried.
        $failures=@()
        for($i=$stopped.Count-1;$i -ge 0;$i--){
            $name=$stopped[$i];$started=$false;$lastError=''
            for($attempt=1;$attempt -le 3 -and -not $started;$attempt++){
                try {
                    $svc=Get-Service -Name $name -ErrorAction Stop
                    if([string]$svc.Status -eq 'StopPending'){$svc.WaitForStatus('Stopped',[timespan]::FromSeconds(20))}
                    Start-Service -Name $name -ErrorAction Stop
                    (Get-Service -Name $name).WaitForStatus('Running',[timespan]::FromSeconds(20))
                    $started=$true
                }catch{$lastError=$_.Exception.Message;if($attempt -lt 3){Start-Sleep -Seconds 5}}
            }
            if(-not $started){$failures+=$name+': '+$lastError}
        }
        if($failures.Count){Add-TkResult 'Service restore' 'Audio services' 'Failed' ('Start these manually: '+($failures -join '; '));if($allStopped){throw ('Could not restore audio services: '+($failures -join '; '))}}
    }
    if((Get-Service Audiosrv).Status -ne 'Running'){Start-Service Audiosrv -ErrorAction Stop}
    foreach($service in $Plan){Add-TkResult 'Audio service after' $service.Name ([string](Get-Service $service.Name).Status) ('Before='+$service.Status+'; startup type not changed.')}
}
function Repair-TkDevice {
    $action=Get-TkChoice 'Action' 'Choose a targeted action after checking devices' @('RestartAudio','RestartDevice','OpenSettings')
    if($action -eq 'OpenSettings'){
        $page=Get-TkChoice 'Page' 'Choose the settings page' @('Sound','Camera','Microphone','Devices')
        $uris=@{Sound='ms-settings:sound';Camera='ms-settings:privacy-webcam';Microphone='ms-settings:privacy-microphone';Devices='ms-settings:connecteddevices'}
        if(Approve-TkAction $page 'Open Windows Settings for a manual check'){Start-Process $uris[$page] -ErrorAction Stop | Out-Null;Add-TkResult 'Settings' $page 'ManualStepRequired' 'Choose the correct device or permissions, then test in the affected app.'};return
    }
    if(-not $script:Options.WhatIf){Assert-TkAdmin}else{Add-TkResult 'Notice' 'Preview' 'Information' 'Live restarts need the elevated CMD launcher; this preview did not check for administrator rights.'}
    $target='Windows Audio service'
    $description=$action+'; interrupts applications currently using it'
    if($action -eq 'RestartAudio'){
        $audioPlan=@(Get-TkAudioRestartPlan)
        $null=Save-TkEvidence 'audio-services-before' $audioPlan
        $description+='; temporarily stop/restore running services: '+(($audioPlan | Where-Object Status -eq 'Running' | ForEach-Object Name) -join ', ')
    }
    if($action -eq 'RestartDevice'){
        $id=Get-TkChoice 'InstanceId' 'Exact audio or camera device InstanceId from the check' @()
        $devices=@(Get-PnpDevice -PresentOnly -ErrorAction Stop | Where-Object InstanceId -eq $id)
        if($devices.Count -ne 1 -or $devices[0].Class -notin 'AudioEndpoint','MEDIA','Camera','Image'){throw 'Only one present audio or camera device is supported. Hubs, docks, display, network, input and storage devices require manual review.'}
        $target=$id
    }
    if(-not (Approve-TkAction $target $description)){return}
    if($action -eq 'RestartAudio'){
        Restart-TkAudioPlan $audioPlan
    }else{
        $r=Invoke-TkNative (Join-Path $env:SystemRoot 'System32\pnputil.exe') @('/restart-device',$target) -TimeoutSeconds 60 -AllowFailure
        if($r.ExitCode -notin 0,3010){throw "PnPUtil returned $($r.ExitCode): $($r.Text)"}
        $status='RestartRequested';if($r.ExitCode -eq 3010){$status='RestartRequired'}
        Add-TkResult 'Device action' $target $status $r.Text
        $after=Get-PnpDevice -PresentOnly -ErrorAction Stop | Where-Object InstanceId -eq $target
        Add-TkResult 'Device after' $target ([string]$after.Status) $after.FriendlyName
    }
    Add-TkHumanCheck 'Reopen the affected app and test audio or camera. Recheck device selection and app permissions if the problem remains.'
}
