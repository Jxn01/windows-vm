<#  windows-vm VM-mode guard  (plan D4, traps T8/T9/T13)
    Runs as SYSTEM at every boot (a scheduled task, ONSTART), BEFORE anyone logs in.

    It detects whether this boot is the Windows-VM on Garuda (an SMBIOS marker the hardware never has) and:
      * VM boot      -> SAVE the original state of every item it will touch (state.json written BEFORE any
                        change, so a restore is always possible), then SUPPRESS everything that would drive the
                        real world or change the hardware Windows: non-Microsoft scheduled tasks (MatterLights,
                        ambience-rgb, claude-rc, ...), non-Microsoft auto services, HKLM + user Run entries
                        (HASS.Agent, Steam, ...), the user's Startup-folder shortcuts (Zebar, wtq), Windows
                        Update; and set DevicePasswordLessBuildVersion=0 so the password sign-in tile shows.
      * Hardware boot-> RESTORE exactly what was saved, so the next real boot has the lights, HASS.Agent, Zebar
                        and all autostarts back.
      * Unsure (can't read the marker) -> do NOTHING and log loudly (never make the hardware worse).

    It never touches the Windows Hello PIN (owner rule T10) and never runs Windows Update.
    Idempotent. State + log live in C:\ProgramData\jxn-vm\.

    Usage:  guard.ps1 [-Mode auto|vm|hardware|status] [-Quiet]
            auto (default) = detect and act.  vm/hardware = force.  status = print one line and exit.
#>
[CmdletBinding()]
param([ValidateSet('auto','vm','hardware','status')][string]$Mode='auto',[switch]$Quiet)

$ErrorActionPreference = 'Stop'
$Root        = 'C:\ProgramData\jxn-vm'
$StateFile   = Join-Path $Root 'state.json'
$LogFile     = Join-Path $Root 'guard.log'
$RunPark     = 'HKLM:\SOFTWARE\jxn-vm\suppressed'        # parked Run VALUES live in the registry
$StartupPark = Join-Path $Root 'suppressed-startup'      # parked Startup .lnk FILES live on disk
$GuardTaskName = 'jxn-vm-guard'                          # this guard's own task - never disable it
$ProfilePath = 'C:\Users\jxnpe'                          # the owner's profile (jxn)
$UserHiveMnt = 'HKU\jxn-vm-user'                         # temp mount for the owner's hive when not logged in

# Services kept running even in VM mode: SSH, remote mgmt, firewall, security.
$KeepServices = @('sshd','ssh-agent','Tailscale','WinDefend','WdNisSvc','SecurityHealthService','MDCoreSvc','mpssvc','BFE','CoworkVMService')
$WUServices   = @('wuauserv','UsoSvc','WaaSMedicSvc','DoSvc')
$RunKeys = @{ runHKLM   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
              runHKLM32 = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run' }
$StartupDirs = @{ user   = (Join-Path $ProfilePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')
                  common = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup' }

function Secure-Root([string]$path){
  # $path (and everything the guard keeps in it - guard.ps1, state.json, parked Run values/shortcuts) is read
  # and executed by SYSTEM, so it must NOT be writable by normal users (else a planted guard.ps1 or tampered
  # park = local privilege escalation). Lock it to SYSTEM + Administrators, inheritance off. Idempotent.
  New-Item -ItemType Directory -Force -Path $path | Out-Null
  $sys=[System.Security.Principal.SecurityIdentifier]'S-1-5-18'
  $adm=[System.Security.Principal.SecurityIdentifier]'S-1-5-32-544'
  $acl = Get-Acl -Path $path
  $acl.SetAccessRuleProtection($true,$false)
  foreach($r in @($acl.Access)){ [void]$acl.RemoveAccessRule($r) }
  $acl.SetOwner($sys)
  foreach($sid in @($sys,$adm)){
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
  }
  Set-Acl -Path $path -AclObject $acl
}
try { Secure-Root $Root } catch { }

function Log([string]$m){
  $line = "{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m
  try { Add-Content -Path $LogFile -Value $line } catch {}
  if(-not $Quiet){ Write-Host $line }
}
function Stop-Quiet([string]$n){ try { & "$env:SystemRoot\System32\sc.exe" stop "$n" *>$null } catch {} }

# ---- VM detection (the SMBIOS marker the host sets; the hardware never does) ----------------------------
function Get-BootKind {
  # Read the SMBIOS marker from HKLM\HARDWARE\DESCRIPTION\System\BIOS, which the kernel populates from SMBIOS
  # at EVERY boot and is available at ONSTART - unlike WMI's Win32_ComputerSystemProduct, which is empty that
  # early (the guard then misdetected the VM as hardware and did nothing). The hardware never has this marker.
  try {
    $b = Get-ItemProperty 'HKLM:\HARDWARE\DESCRIPTION\System\BIOS' -ErrorAction Stop
    if($b.SystemManufacturer -eq 'jxn' -and $b.SystemProductName -eq 'windows-vm' -and $b.SystemFamily -eq 'jxn-windows-vm-marker-v1'){ return 'vm' }
    if($b.SystemManufacturer -and $b.SystemProductName){ return 'hardware' }
    return 'unsure'
  } catch { return 'unsure' }
}

# ---- run a scriptblock with the owner's user hive available (live if logged in, else mount NTUSER.DAT) --
function With-UserHive([scriptblock]$fn){
  $sid=$null
  try { $p = Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -eq $ProfilePath }; if($p){ $sid=$p.SID } } catch {}
  $loaded=$false; $prefix=$null
  if($sid -and (Test-Path "Registry::HKEY_USERS\$sid")){ $prefix="HKEY_USERS\$sid" }
  else {
    $nt = Join-Path $ProfilePath 'NTUSER.DAT'
    if(Test-Path $nt){ & reg.exe load $UserHiveMnt $nt *>$null; if($LASTEXITCODE -eq 0){ $loaded=$true; $prefix=$UserHiveMnt.Replace('HKU\','HKEY_USERS\') } else { Log "WARN: could not load $nt" } }
  }
  try { & $fn $prefix } finally { if($loaded){ [gc]::Collect(); Start-Sleep -Milliseconds 200; & reg.exe unload $UserHiveMnt *>$null } }
}

function Is-Microsoft([string]$imgPath){
  # A service/binary counts as Microsoft (kept) if its file is validly signed by Microsoft.
  try {
    if(-not $imgPath -or -not (Test-Path $imgPath)){ return $false }
    $sig = Get-AuthenticodeSignature -FilePath $imgPath -ErrorAction Stop
    return ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'Microsoft')
  } catch { return $false }
}
function Binpath([string]$pathName){ (($pathName -replace '^"','') -replace '".*$','') -replace '\s+-.*$','' -replace '\s+/.*$','' }

# =========================================================================================================
function Plan-Suppress {
  # READ-ONLY: build the full plan of what to change. No changes here.
  $state = [ordered]@{ mode='vm'; appliedAt=(Get-Date -Format o); tasks=@(); services=@{};
                       runParked=@('runHKLM','runHKLM32','runUser'); startupParked=@('user','common');
                       wu=@{}; passwordless=$null }
  # tasks: non-Microsoft, enabled, with an auto trigger
  foreach($t in Get-ScheduledTask){
    if($t.TaskPath -like '\Microsoft\*' -or $t.TaskName -eq $GuardTaskName -or $t.State -eq 'Disabled'){ continue }
    $trig = $t.Triggers | ForEach-Object { $_.CimClass.CimClassName }
    if($trig -match 'Logon|Boot|Event|Time|Daily|Weekly|Registration'){ $state.tasks += ($t.TaskPath + $t.TaskName) }
  }
  # services: auto-start, binary outside C:\Windows (i.e. third-party in Program Files), not in the keep list.
  # (Device-driving autostarts are scheduled TASKS, not services; vendor services in System32 are MS/WHQL-signed
  # and benign in the VM. This location rule is fast - no per-binary signature scan - and catches the updaters
  # and launchers that live in Program Files: Adobe, Google, ArmouryCrate, Razer, Overwolf, TeamViewer, ...)
  foreach($s in Get-CimInstance Win32_Service){
    if($s.StartMode -notin @('Auto','Automatic') -or $KeepServices -contains $s.Name){ continue }
    $img = Binpath $s.PathName
    if(-not $img -or $img -like "$env:SystemRoot\*" -or $img -like 'C:\Windows\*'){ continue }
    $state.services[$s.Name] = "$($s.StartMode)"
  }
  # Windows Update services + policy
  foreach($n in $WUServices){ $svc=Get-CimInstance Win32_Service -Filter "Name='$n'" -ErrorAction SilentlyContinue; if($svc){ $state.wu[$n]="$($svc.StartMode)" } }
  $au='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
  $state.wu['NoAutoUpdate_prev'] = if(Test-Path $au){ (Get-ItemProperty -Path $au -Name NoAutoUpdate -ErrorAction SilentlyContinue).NoAutoUpdate } else { $null }
  # passwordless
  $pl='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device'
  if(Test-Path $pl){ $state.passwordless = (Get-ItemProperty -Path $pl -Name DevicePasswordLessBuildVersion -ErrorAction SilentlyContinue).DevicePasswordLessBuildVersion }
  return $state
}

function Apply-Suppress($state){
  foreach($id in $state.tasks){
    $name=Split-Path $id -Leaf; $path=$id.Substring(0,$id.Length-$name.Length)
    try { Disable-ScheduledTask -TaskName $name -TaskPath $path -ErrorAction Stop | Out-Null; Log "task disabled: $id" } catch { Log "WARN task $id : $($_.Exception.Message)" }
  }
  foreach($p in $state.services.PSObject.Properties){ $n=$p.Name
    try { Set-Service -Name $n -StartupType Disabled -ErrorAction Stop
          if((Get-Service $n).Status -eq 'Running'){ Stop-Quiet $n }
          Log "service disabled: $n (was $($p.Value))" } catch { Log "WARN service $n : $($_.Exception.Message)" }
  }
  # Run: park each value in the registry, then remove from Run
  New-Item -Path $RunPark -Force | Out-Null
  foreach($k in $RunKeys.Keys){ Move-RunAway $RunKeys[$k] $k }
  With-UserHive { param($pfx) if($pfx){ Move-RunAway "Registry::$pfx\Software\Microsoft\Windows\CurrentVersion\Run" 'runUser' } }
  # Startup folder .lnks -> park on disk
  foreach($k in $StartupDirs.Keys){ Move-StartupAway $StartupDirs[$k] $k }
  # Windows Update
  foreach($p in $state.wu.PSObject.Properties){ $n=$p.Name; if($n -eq 'NoAutoUpdate_prev'){continue}
    try { Set-Service -Name $n -StartupType Disabled -ErrorAction SilentlyContinue; Stop-Quiet $n; Log "WU stopped: $n" } catch {} }
  $au='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; New-Item -Path $au -Force | Out-Null
  New-ItemProperty -Path $au -Name NoAutoUpdate -PropertyType DWord -Value 1 -Force | Out-Null
  # passwordless 2 -> 0
  if($state.passwordless -ne $null){
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device' -Name DevicePasswordLessBuildVersion -Value 0 -Type DWord
    Log "DevicePasswordLessBuildVersion $($state.passwordless) -> 0"
  }
}

# SSH reachable from the VM host even though the VM's NIC is on a new "Public" network: a scoped inbound allow
# rule for TCP 22 from the host subnet only. Added FIRST in VM mode so the host can drive the VM within seconds
# of boot, before the (slower) suppression runs. Removed on the hardware restore.
function Ensure-SshRule {
  for($i=0; $i -lt 30; $i++){ if((Get-Service mpssvc -ErrorAction SilentlyContinue).Status -eq 'Running'){ break }; Start-Sleep -Seconds 1 }
  for($try=0; $try -lt 5; $try++){
    & "$env:SystemRoot\System32\netsh.exe" advfirewall firewall delete rule name="jxn-vm-ssh" *>$null
    & "$env:SystemRoot\System32\netsh.exe" advfirewall firewall add rule name="jxn-vm-ssh" dir=in action=allow protocol=TCP localport=22 remoteip=192.168.122.0/24 *>$null
    if($LASTEXITCODE -eq 0){ Log "firewall: SSH (TCP22) allowed from 192.168.122.0/24"; return }
    Start-Sleep -Seconds 2
  }
  Log "WARN: could not add the SSH firewall rule after retries"
}

function Move-RunAway([string]$runKey,[string]$label){
  if(-not (Test-Path $runKey)){ return }
  $park = Join-Path $RunPark $label; New-Item -Path $park -Force | Out-Null
  foreach($p in (Get-ItemProperty -Path $runKey).PSObject.Properties){
    if($p.Name -like 'PS*'){ continue }
    $kind = (Get-Item $runKey).GetValueKind($p.Name)
    New-ItemProperty -Path $park -Name $p.Name -PropertyType $kind -Value $p.Value -Force | Out-Null
    Remove-ItemProperty -Path $runKey -Name $p.Name -Force
    Log "Run moved aside [$label]: $($p.Name)"
  }
}
function Move-StartupAway([string]$dir,[string]$label){
  if(-not (Test-Path $dir)){ return }
  $park = Join-Path $StartupPark $label; New-Item -ItemType Directory -Force -Path $park | Out-Null
  foreach($f in Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue){
    if($f.Name -ieq 'desktop.ini'){ continue }
    Move-Item -Path $f.FullName -Destination (Join-Path $park $f.Name) -Force
    Log "startup moved aside [$label]: $($f.Name)"
  }
}

# =========================================================================================================
function Restore {
  if(-not (Test-Path $StateFile)){
    # No plan file, but durable parks may still hold Run/startup items (e.g. a crash mid-apply): restore those.
    if((Test-Path $RunPark) -or (Test-Path $StartupPark)){ Log "no state.json but parked items exist - restoring those" ; Restore-Parked }
    else { Log "nothing to restore (clean) - hardware boot" }
    return
  }
  $state = Get-Content $StateFile -Raw | ConvertFrom-Json
  foreach($id in $state.tasks){
    $name=Split-Path $id -Leaf; $path=$id.Substring(0,$id.Length-$name.Length)
    try { Enable-ScheduledTask -TaskName $name -TaskPath $path -ErrorAction Stop | Out-Null; Log "task re-enabled: $id" } catch { Log "WARN restore task $id : $($_.Exception.Message)" }
  }
  foreach($n in $state.services.PSObject.Properties.Name){
    try { Set-Service -Name $n -StartupType (Norm $state.services.$n) -ErrorAction Stop; Log "service restored: $n -> $($state.services.$n)" } catch { Log "WARN restore svc $n : $($_.Exception.Message)" }
  }
  foreach($n in $state.wu.PSObject.Properties.Name){ if($n -eq 'NoAutoUpdate_prev'){continue}
    try { Set-Service -Name $n -StartupType (Norm $state.wu.$n) -ErrorAction SilentlyContinue; Log "WU restored: $n -> $($state.wu.$n)" } catch {} }
  $au='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
  if($null -eq $state.wu.NoAutoUpdate_prev){ Remove-ItemProperty -Path $au -Name NoAutoUpdate -ErrorAction SilentlyContinue }
  else { Set-ItemProperty -Path $au -Name NoAutoUpdate -Value $state.wu.NoAutoUpdate_prev -Type DWord }
  if($state.passwordless -ne $null){
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device' -Name DevicePasswordLessBuildVersion -Value $state.passwordless -Type DWord
    Log "DevicePasswordLessBuildVersion restored -> $($state.passwordless)"
  }
  & "$env:SystemRoot\System32\netsh.exe" advfirewall firewall delete rule name="jxn-vm-ssh" *>$null
  Restore-Parked
  Remove-Item -Path $StateFile -Force
  Log "hardware restore complete; state cleared"
}
function Norm($m){ switch -regex ("$m"){ 'Disabled'{'Disabled'} 'Manual'{'Manual'} default{'Automatic'} } }

function Restore-Parked {
  # Run entries from the registry park
  foreach($label in @('runHKLM','runHKLM32')){
    $park = Join-Path $RunPark $label
    if(Test-Path $park){ Restore-RunKey $RunKeys[$label] $park $label }
  }
  $uPark = Join-Path $RunPark 'runUser'
  if(Test-Path $uPark){ With-UserHive { param($pfx) if($pfx){ Restore-RunKey "Registry::$pfx\Software\Microsoft\Windows\CurrentVersion\Run" $uPark 'runUser' } } }
  # Startup .lnks from the disk park
  foreach($k in $StartupDirs.Keys){
    $park = Join-Path $StartupPark $k
    if(Test-Path $park){ foreach($f in Get-ChildItem $park -File){ Move-Item $f.FullName (Join-Path $StartupDirs[$k] $f.Name) -Force; Log "startup restored [$k]: $($f.Name)" } }
  }
  Remove-Item -Path $RunPark -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -Path $StartupPark -Recurse -Force -ErrorAction SilentlyContinue
}
function Restore-RunKey([string]$runKey,[string]$park,[string]$label){
  New-Item -Path $runKey -Force | Out-Null
  foreach($p in (Get-ItemProperty -Path $park).PSObject.Properties){
    if($p.Name -like 'PS*'){ continue }
    $kind=(Get-Item $park).GetValueKind($p.Name)
    New-ItemProperty -Path $runKey -Name $p.Name -PropertyType $kind -Value $p.Value -Force | Out-Null
    Log "Run restored [$label]: $($p.Name)"
  }
}

# =========================================================================================================
if($Mode -eq 'status'){
  Write-Output ("detected={0} state={1}" -f (Get-BootKind), $(if(Test-Path $StateFile){'vm-mode-applied'}else{'clean'}))
  exit 0
}
$kind = if($Mode -eq 'auto'){ Get-BootKind } else { $Mode }
Log "guard start: Mode=$Mode kind=$kind"
switch($kind){
  'vm' {
    Ensure-SshRule                                                                     # FIRST: host access, fast
    if(-not (Test-Path $StateFile)){
      $plan = Plan-Suppress                                                            # first VM boot: capture original
      $plan | ConvertTo-Json -Depth 6 | Set-Content -Path $StateFile -Encoding UTF8    # SAVE before any change
      Log ("plan saved: {0} tasks, {1} services, passwordless={2}" -f $plan.tasks.Count,$plan.services.Count,$plan.passwordless)
    } else {
      Log "state.json already present (prior VM boot) - keeping the original plan, re-applying idempotently"
    }
    $state = Get-Content $StateFile -Raw | ConvertFrom-Json                            # always a PSCustomObject
    Apply-Suppress $state
    Log "VM mode applied"
  }
  'hardware' { Restore }
  default    { Log "UNSURE what kind of boot this is (SMBIOS unreadable) - doing NOTHING (never harm the hardware Windows)" }
}
Log "guard done"
