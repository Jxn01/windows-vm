<#  windows-vm VM-mode guard  (plan D4, traps T8/T9/T13)
    Runs as SYSTEM at every boot (a scheduled task, ONSTART), BEFORE anyone logs in.

    It detects whether this boot is the Windows-VM on Garuda (an SMBIOS marker the hardware never has) and:
      * VM boot      -> SAVE the original state of every item it will touch (state.json written BEFORE any
                        change, so a restore is always possible), then SUPPRESS everything that would drive the
                        real world or change the hardware Windows: non-Microsoft scheduled tasks (MatterLights,
                        ambience-rgb, claude-rc, ...), non-Microsoft auto services, HKLM + user Run entries
                        (HASS.Agent, Steam, ...), the user's Startup-folder shortcuts (Zebar, wtq), Windows
                        Update (its four services stopped - wuauserv/UsoSvc also disabled; WaaSMedicSvc and DoSvc
                        are protected and can only be stopped, and Medic re-enables wuauserv - so the two policy
                        values in $VmPolicies do the real blocking: NoAutoUpdate=1 (no automatic OS updates) and
                        the Store's AutoDownload=2 (no app auto-updates); Defender signatures still update); and
                        set DevicePasswordLessBuildVersion=0 so the password sign-in tile shows.
      * Hardware boot-> RESTORE exactly what was saved, so the next real boot has the lights, HASS.Agent, Zebar
                        and all autostarts back. A parked shortcut is given its Startup folder's file permissions
                        while it is still in the park, before it goes back (Unpark-File - else the owner's
                        Explorer cannot read it).
      * Unsure (can't read the marker) -> do NOTHING and log loudly (never make the hardware worse).

    It never touches the Windows Hello PIN (owner rule T10) and never runs Windows Update.
    Idempotent. State + log live in C:\ProgramData\jxn-vm\. The log says what HAPPENED (a protected service is logged
    as 'stopped only', never as disabled). Policy round-trip, for real: test-guard-policies.ps1 (beside this file).

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
$ProfilePath = 'C:\Users\jxnpe'                          # fallback: the rig's owner profile (jxn)
# The real owner profile is recorded by install-guard.ps1 (owner.json): the laptop's is C:\Users\jxn, and a guard
# that hard-coded the rig's never saw the laptop owner's Run keys or Startup folder (found 2026-10-12).
try { $o = Get-Content (Join-Path 'C:\ProgramData\jxn-vm' 'owner.json') -Raw -ErrorAction Stop | ConvertFrom-Json
      if($o.ProfilePath -and (Test-Path $o.ProfilePath)){ $ProfilePath = $o.ProfilePath } } catch { }
$UserHiveMnt = 'HKU\jxn-vm-user'                         # temp mount for the owner's hive when not logged in

# Services kept running even in VM mode: SSH, remote mgmt, firewall, security.
$KeepServices = @('sshd','ssh-agent','Tailscale','WinDefend','WdNisSvc','SecurityHealthService','MDCoreSvc','mpssvc','BFE','CoworkVMService')
$WUServices   = @('wuauserv','UsoSvc','WaaSMedicSvc','DoSvc')
# Policy values set in VM mode and put back on the hardware restore - the ONE place for them (plan, apply and restore
# all walk this table). Why the Store one: WaaSMedicSvc and DoSvc are protected (the service manager refuses to
# disable them), Medic puts wuauserv back, and on 2026-10-11 22:10 the Store pulled 20 app updates inside the VM ten
# minutes after boot. NoAutoUpdate still blocks OS updates; Defender's signature updates stay on (by design).
$VmPolicies = [ordered]@{
  NoAutoUpdate      = @{ key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; name='NoAutoUpdate'; vm=1 }
  StoreAutoDownload = @{ key='HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'; name='AutoDownload'; vm=2 }
}
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
  # Written ONLY when it is not already the locked ACL: every Set-Acl on a folder re-propagates down its tree, and
  # doing that at every boot is what stripped the parked shortcuts' Startup permissions (2026-10-17). $true = rewritten.
  $acl = Get-Acl -Path $path
  $acl.SetAccessRuleProtection($true,$false)
  foreach($r in @($acl.Access)){ [void]$acl.RemoveAccessRule($r) }
  $acl.SetOwner($sys)
  foreach($sid in @($sys,$adm)){
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
  }
  if($acl.Sddl -eq (Get-Acl -Path $path).Sddl){ return $false }
  Set-Acl -Path $path -AclObject $acl
  return $true
}
$RootRewritten = $null; try { $RootRewritten = Secure-Root $Root } catch { $RootRewritten = "failed: $($_.Exception.Message)" }   # logged below

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
# Create a registry key ONLY if it is missing. NEVER `New-Item -Path <key> -Force` on a key that may exist: the registry
# provider then deletes all its values and subkeys and recreates it empty. That destroyed the rig's parked Run entries
# (2026-10-09 12:47, the second VM boot in a row) - tests/test_guard_static.py forbids the forced form.
function Ensure-Key([string]$k){ if(-not (Test-Path -LiteralPath $k)){ New-Item -Path $k -Force | Out-Null } }

# The current value of a policy as {had, value} (had=$false: the value does not exist).
function Read-Policy($p){
  $v = if(Test-Path $p.key){ (Get-ItemProperty -Path $p.key -Name $p.name -ErrorAction SilentlyContinue).($p.name) } else { $null }
  return [pscustomobject]@{ had = ($null -ne $v); value = $v }
}
function Set-VmPolicy([string]$id){
  $p = $VmPolicies[$id]; Ensure-Key $p.key
  New-ItemProperty -Path $p.key -Name $p.name -PropertyType DWord -Value $p.vm -Force | Out-Null
  Log "policy $id : $($p.name)=$($p.vm)"
}
# The original {had, value} saved for policy $id, from either state shape: state.policies (this guard) or the
# NoAutoUpdate_prev that guards before 2026-10-12 wrote into state.wu. $null = nothing saved.
function Saved-Policy($state, [string]$id){
  if($state.PSObject.Properties.Name -contains 'policies' -and $state.policies.PSObject.Properties.Name -contains $id){ return $state.policies.$id }
  if($id -eq 'NoAutoUpdate' -and $state.wu.PSObject.Properties.Name -contains 'NoAutoUpdate_prev'){
    return [pscustomobject]@{ had = ($null -ne $state.wu.NoAutoUpdate_prev); value = $state.wu.NoAutoUpdate_prev }
  }
  return $null
}
# A state.json written by an older guard has no original for a policy added since: capture it NOW, before Apply
# changes anything, and save it - the same SAVE-before-change rule as the first VM boot.
function Ensure-PolicyState($state){
  if($state.PSObject.Properties.Name -notcontains 'policies'){ $state | Add-Member -NotePropertyName policies -NotePropertyValue ([pscustomobject]@{}) }
  $added = @()
  foreach($id in $VmPolicies.Keys){
    if($null -ne (Saved-Policy $state $id)){ continue }
    $state.policies | Add-Member -NotePropertyName $id -NotePropertyValue (Read-Policy $VmPolicies[$id]); $added += $id
  }
  if($added){ $state | ConvertTo-Json -Depth 6 | Set-Content -Path $StateFile -Encoding UTF8; Log "state.json: saved the original of $($added -join ', ')" }
}

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
  $state.policies = [ordered]@{}; foreach($id in $VmPolicies.Keys){ $state.policies[$id] = Read-Policy $VmPolicies[$id] }
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
  Ensure-Key $RunPark
  foreach($k in $RunKeys.Keys){ Move-RunAway $RunKeys[$k] $k }
  With-UserHive { param($pfx) if($pfx){ Move-RunAway "Registry::$pfx\Software\Microsoft\Windows\CurrentVersion\Run" 'runUser' } }
  # Startup folder .lnks -> park on disk
  foreach($k in $StartupDirs.Keys){ Move-StartupAway $StartupDirs[$k] $k }
  # Windows Update
  foreach($p in $state.wu.PSObject.Properties){ $n=$p.Name; if($n -eq 'NoAutoUpdate_prev'){continue}
    try { Set-Service -Name $n -StartupType Disabled -ErrorAction Stop; $how = 'disabled + stopped' } catch { $how = 'stopped only (protected - Windows refuses to disable it)' }
    Stop-Quiet $n; Log "WU $how : $n" }
  Ensure-PolicyState $state
  foreach($id in $VmPolicies.Keys){ Set-VmPolicy $id }
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
  $park = Join-Path $RunPark $label; Ensure-Key $park
  foreach($p in (Get-ItemProperty -Path $runKey).PSObject.Properties){
    if($p.Name -like 'PS*'){ continue }
    $kind = (Get-Item $runKey).GetValueKind($p.Name)
    New-ItemProperty -Path $park -Name $p.Name -PropertyType $kind -Value $p.Value -Force | Out-Null
    Remove-ItemProperty -Path $runKey -Name $p.Name -Force
    Log "Run moved aside [$label]: $($p.Name)"
  }
}
# A Startup folder lives under the owner's own profile, so the owner (unelevated) can replace it - or any component of
# its path - with a junction/symlink. A SYSTEM move INTO such a folder, or a SYSTEM enumerate-and-move OUT of it, then
# lands on whatever the reparse point names: arbitrary file write / move as SYSTEM (LPE). Test-SafeDir refuses unless the
# folder exists AND no component from the volume root down is a reparse point. The park itself is under $Root (Secure-Root:
# SYSTEM+Administrators only, protected, no inheritance), where the owner cannot create a reparse point, so it is trusted.
function Test-SafeDir([string]$path){
  try {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if($item.PSProvider.Name -ne 'FileSystem' -or -not $item.PSIsContainer){ return $false }
    for($cur=$item; $cur; $cur=$cur.Parent){ if($cur.Attributes -band [System.IO.FileAttributes]::ReparsePoint){ return $false } }
    return $true
  } catch { return $false }
}
function Move-StartupAway([string]$dir,[string]$label){
  if(-not (Test-SafeDir $dir)){ if(Test-Path $dir){ Log "WARN startup park [$label]: $dir is a reparse point - skipped" }; return }
  $park = Join-Path $StartupPark $label; New-Item -ItemType Directory -Force -Path $park | Out-Null
  foreach($f in Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue){
    if($f.Name -ieq 'desktop.ini'){ continue }
    Park-File $f.FullName (Join-Path $park $f.Name)
    Log "startup moved aside [$label]: $($f.Name)"
  }
}

# A same-volume Move-Item is a RENAME: the file keeps the security descriptor it had and never gets its new folder's
# inherited permissions (Explorer adds those by hand; MoveFileEx does not). Secure-Root used to rewrite $Root's
# SYSTEM+Administrators-only ACL at every guard start, which re-propagated it onto every parked shortcut, and the restore
# carried exactly that back into Startup: the owner's unelevated Explorer could not read zebar.exe.lnk / Tailscale.lnk /
# Brother iPSMonitor.lnk and skipped them without a word (the rig's first hardware boot after the VM, 2026-10-17).
# Shortcuts with an EXPLICIT owner ACE (wtq, the AHK scripts) survived - which is why only some went missing.
# So Unpark-File gives a shortcut its Startup folder's file permissions (as explicit ACEs) while it is still in the park,
# then renames it back. SYSTEM never writes a DACL inside a Startup folder: the owner can write there unelevated, and a
# hard link or symlink planted there would aim a SYSTEM ACL write at a file of their choosing. The ACL write is on the
# park copy, which the owner cannot even traverse to (the park dir denies them), so it cannot be swapped under us (no
# TOCTOU); only an entry that is neither a reparse point nor hard-linked is touched. The destination folder is checked
# reparse-free by the caller (Test-SafeDir) and the destination name is refused if it is itself a reparse point.
# tests/test_guard_static.py forbids a Move-Item outside Park-File / Unpark-File and any ACL write outside
# Secure-Root / Unpark-File, and requires the Test-SafeDir gate on both park and restore.
function Park-File([string]$from,[string]$to){ Move-Item -LiteralPath $from -Destination $to -Force }   # a rename: the file is not changed
function Link-Count([string]$path){
  # How many names the file has (fsutil lists them, one per line). -1 = could not tell, which counts as unsafe.
  $o = @(& "$env:SystemRoot\System32\fsutil.exe" hardlink list "$path" 2>$null)
  if($LASTEXITCODE -ne 0){ return -1 }
  return @($o | Where-Object { "$_".Trim() }).Count
}
function File-Rights($rule){
  # A folder ACE's mask as a file ACE gets it: generic bits mapped to the file-specific rights (what inheritance does).
  $m = ([int64][int]$rule.FileSystemRights) -band 4294967295
  $r = $m -band 0x0FFFFFFF
  if($m -band 0x10000000){ $r = $r -bor 0x1F01FF }      # GENERIC_ALL     -> FullControl
  if($m -band 0x20000000){ $r = $r -bor 0x1200A0 }      # GENERIC_EXECUTE -> execute + read attributes + synchronize
  if($m -band 0x40000000){ $r = $r -bor 0x120116 }      # GENERIC_WRITE   -> Write
  if($m -band 2147483648){ $r = $r -bor 0x120089 }      # GENERIC_READ    -> Read
  return [System.Security.AccessControl.FileSystemRights][int]$r
}
function Folder-FileRules([string]$folder){
  # The ACEs a new FILE in $folder would inherit: its object-inheritable ones (CREATOR OWNER/GROUP name the creator - skipped).
  $out = @()
  foreach($r in (Get-Item -LiteralPath $folder -Force).GetAccessControl('Access').GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])){
    if(-not ($r.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit)){ continue }
    if($r.IdentityReference.Value -in @('S-1-3-0','S-1-3-1')){ continue }
    $out += New-Object System.Security.AccessControl.FileSystemAccessRule($r.IdentityReference, (File-Rights $r), 'None', 'None', $r.AccessControlType)
  }
  return $out
}
function Unpark-File([string]$from,[string]$toDir){
  # Grant $toDir's file permissions to the park copy, then rename it into $toDir. $toDir was already checked reparse-free
  # by the caller. Returns the restored path, or $null if it refused (the shortcut then stays in the park).
  $fi = Get-Item -LiteralPath $from -Force
  $to = Join-Path $toDir $fi.Name
  if((Test-Path -LiteralPath $to) -and ((Get-Item -LiteralPath $to -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint)){
    Log "WARN unpark $($fi.Name): the destination name is a reparse point - kept in the park"; return $null }
  if($fi.Attributes -band [System.IO.FileAttributes]::ReparsePoint){ Log "WARN unpark $($fi.Name): a reparse point - restored without new permissions" }
  elseif((Link-Count $from) -ne 1){ Log "WARN unpark $($fi.Name): hard-linked (or its link count is unreadable) - restored without new permissions" }
  else {
    $acl = $fi.GetAccessControl('Access')                 # DACL only: the owner is never rewritten
    foreach($r in (Folder-FileRules $toDir)){ $acl.AddAccessRule($r) }
    $fi.SetAccessControl($acl)
  }
  Move-Item -LiteralPath $from -Destination $to -Force
  return $to
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
    try { Set-Service -Name $n -StartupType (Norm $state.wu.$n) -ErrorAction Stop; Log "WU restored: $n -> $($state.wu.$n)" }
    catch { Log "WU $n left as is (protected; it was never disabled): wanted $($state.wu.$n)" } }
  foreach($id in $VmPolicies.Keys){ $p = $VmPolicies[$id]; $o = Saved-Policy $state $id
    if($null -eq $o){ Log "WARN policy $id : no saved original - left as is"; continue }
    if($o.had){ Ensure-Key $p.key; New-ItemProperty -Path $p.key -Name $p.name -PropertyType DWord -Value $o.value -Force | Out-Null; Log "policy restored: $id -> $($o.value)" }
    else { Remove-ItemProperty -Path $p.key -Name $p.name -ErrorAction SilentlyContinue; Log "policy restored: $id -> (absent)" } }
  if($state.passwordless -ne $null){
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device' -Name DevicePasswordLessBuildVersion -Value $state.passwordless -Type DWord
    Log "DevicePasswordLessBuildVersion restored -> $($state.passwordless)"
  }
  & "$env:SystemRoot\System32\netsh.exe" advfirewall firewall delete rule name="jxn-vm-ssh" *>$null
  Restore-Parked
  Remove-Item -Path $StateFile -Force
  Log "hardware restore complete; state cleared"
  Start-Restored $state
}

function Start-Restored($state){
  # The restore runs at boot, but a boot that RESTORES has already passed its auto-start points while everything was
  # still suppressed: the service manager skipped the (then Disabled) services, boot-triggered tasks missed the boot,
  # and an owner who logged on before this finished (T27 - the laptop, 2026-10-12: no Zebar, wtq, Windhawk, tunnel)
  # got no logon autostarts. So start them now - services and boot tasks always, logon items only for a logged-on owner.
  foreach($n in $state.services.PSObject.Properties.Name){
    if((Norm $state.services.$n) -eq 'Automatic'){ try { Start-Service -Name $n -ErrorAction Stop; Log "started (restored auto service): $n" } catch { Log "WARN start svc $n : $($_.Exception.Message)" } }
  }
  $ownerSid = $null; try { $ownerSid = (Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -eq $ProfilePath }).SID } catch {}
  $loggedOn = $false; $ownerExplorerStart = $null
  if($ownerSid){ foreach($e in @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue)){
    try { if((Invoke-CimMethod -InputObject $e -MethodName GetOwnerSid).Sid -eq $ownerSid){ $loggedOn = $true
      if($e.CreationDate -and (-not $ownerExplorerStart -or $e.CreationDate -lt $ownerExplorerStart)){ $ownerExplorerStart = $e.CreationDate } } } catch {} } }
  foreach($id in $state.tasks){
    $name=Split-Path $id -Leaf; $path=$id.Substring(0,$id.Length-$name.Length)
    $t = Get-ScheduledTask -TaskName $name -TaskPath $path -ErrorAction SilentlyContinue; if(-not $t){ continue }
    $trig = ($t.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ','
    if($trig -match 'Boot' -or ($loggedOn -and $trig -match 'Logon')){
      try { Start-ScheduledTask -TaskName $name -TaskPath $path -ErrorAction Stop; Log "started (restored task, missed its trigger): $id" } catch { Log "WARN start task $id : $($_.Exception.Message)" } }
  }
  # Direct-launch the restored Startup/Run items ONLY when the owner logged on BEFORE they were restored (T27: Explorer
  # already processed Startup/Run while they were still parked, so it missed them). If the owner logs on AFTER the
  # restore, Explorer runs them itself, and launching here too starts a SECOND copy -- the start-menu-reveal
  # "could not close the previous instance" dialog, 2026-10-28. Skip ONLY when we KNOW Explorer started after the
  # restore; any uncertainty errs toward launching, because a missed autostart is worse than a duplicate.
  $explorerAfterRestore = $loggedOn -and $ownerExplorerStart -and $script:restoreStamp -and ($ownerExplorerStart -ge $script:restoreStamp)
  if($loggedOn -and $script:RestoredLaunch.Count -gt 0 -and -not $explorerAfterRestore){
    # Startup .lnks and Run command lines must start INSIDE the owner's session: a one-shot task as the owner.
    # conhost --headless, never powershell -WindowStyle Hidden: Windows Terminal (the default terminal) ignores
    # SW_HIDE and flashes a window on the owner's screen (seen 2026-10-12).
    # A Run value is a raw command line whose program is often an UNQUOTED path with spaces (C:\Program Files\...).
    # `start "" <value>` (the old way) handed that to cmd's start, which split it at the first space and failed with
    # "Windows cannot find 'C:\Program'" at boot (2026-10-28). Split-RunCommand separates the program from its arguments
    # (quoted, or the longest leading prefix that is a real file - the same resolution Windows' Run key does) and
    # Start-Process launches it. The split runs in the OWNER's context so %APPDATA% etc. expand correctly. A .lnk goes
    # straight to Start-Process, which resolves the shortcut.
    # Split-RunCommand (inlined; every line indented so no column-0 brace) separates a Run value's program from its args
    # the way Windows' Run key does: a quoted program as-is, else the longest leading prefix that is a real file.
    $arr = '@(' + (($script:RestoredLaunch | ForEach-Object { "'" + ($_ -replace "'","''") + "'" }) -join ',') + ')'
    $body = @'
 function Split-RunCommand([string]$cmd){
   $cmd = "$cmd".Trim()
   if($cmd.StartsWith('"')){ $e = $cmd.IndexOf('"',1); if($e -lt 0){ return @{ Exe=$cmd.Trim('"'); Args='' } }
     return @{ Exe=$cmd.Substring(1,$e-1); Args=$cmd.Substring($e+1).Trim() } }
   $p = $cmd -split ' '
   for($i=1; $i -le $p.Count; $i++){
     $cand = ($p[0..($i-1)] -join ' ')
     foreach($ext in @('','.exe','.com','.bat','.cmd')){
       if([IO.File]::Exists([Environment]::ExpandEnvironmentVariables($cand+$ext))){
         return @{ Exe=$cand+$ext; Args=(($p[$i..($p.Count-1)]) -join ' ') } } } }
   return @{ Exe=$p[0]; Args=(($p[1..($p.Count-1)]) -join ' ') }
 }
 foreach($x in $ITEMS){
   if($x -match '\.lnk$'){ Start-Process -FilePath $x; continue }
   $s = Split-RunCommand $x
   if($s.Args){ Start-Process -FilePath $s.Exe -ArgumentList $s.Args } else { Start-Process -FilePath $s.Exe }
 }
'@
    $script = "`$ITEMS = $arr`n" + $body
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    try {
      Register-ScheduledTask -TaskName 'jxn-vm-late-start' -TaskPath '\' -Force `
        -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\conhost.exe" -Argument "--headless powershell.exe -NoProfile -EncodedCommand $enc") `
        -Principal (New-ScheduledTaskPrincipal -UserId $ownerSid -LogonType Interactive -RunLevel Limited) | Out-Null
      Start-ScheduledTask -TaskName 'jxn-vm-late-start'; Start-Sleep -Seconds 5
      Log "started $($script:RestoredLaunch.Count) restored Startup/Run item(s) in the owner's session"
    } catch { Log "WARN late start of Startup/Run items: $($_.Exception.Message)" }
    finally { Unregister-ScheduledTask -TaskName 'jxn-vm-late-start' -Confirm:$false -ErrorAction SilentlyContinue }
  } elseif($explorerAfterRestore -and $script:RestoredLaunch.Count -gt 0){ Log "owner logged on after the restore - Explorer runs the $($script:RestoredLaunch.Count) restored Startup/Run item(s); not relaunching" }
  elseif(-not $loggedOn){ Log "owner not logged on yet - logon autostarts will run at the logon" }
}
function Norm($m){ switch -regex ("$m"){ 'Disabled'{'Disabled'} 'Manual'{'Manual'} default{'Automatic'} } }

$script:RestoredLaunch = New-Object System.Collections.Generic.List[string]   # .lnk paths / Run command lines
$script:restoreStamp = $null                                                  # when the parked items were put back (for the Explorer-double-launch guard in Start-Restored)
function Restore-Parked {
  $script:restoreStamp = Get-Date
  # Run entries from the registry park
  foreach($label in @('runHKLM','runHKLM32')){
    $park = Join-Path $RunPark $label
    if(Test-Path $park){ Restore-RunKey $RunKeys[$label] $park $label }
  }
  $uPark = Join-Path $RunPark 'runUser'
  if(Test-Path $uPark){ With-UserHive { param($pfx) if($pfx){ Restore-RunKey "Registry::$pfx\Software\Microsoft\Windows\CurrentVersion\Run" $uPark 'runUser' } } }
  # Startup .lnks from the disk park. A label whose destination is unsafe (a reparse point) is left in the park untouched,
  # never redirected; its park subdir is removed only once its shortcuts are actually restored.
  foreach($k in $StartupDirs.Keys){
    $park = Join-Path $StartupPark $k
    if(-not (Test-Path $park)){ continue }
    $dest = $StartupDirs[$k]
    if(-not (Test-SafeDir $dest)){ Log "WARN startup restore [$k]: $dest is missing or a reparse point - $(@(Get-ChildItem $park -File).Count) shortcut(s) kept in the park"; continue }
    foreach($f in Get-ChildItem $park -File){ $to = Unpark-File $f.FullName $dest; if($to){ $script:RestoredLaunch.Add($to); Log "startup restored [$k]: $($f.Name)" } }
    Remove-Item -Path $park -Recurse -Force -ErrorAction SilentlyContinue
  }
  Remove-Item -Path $RunPark -Recurse -Force -ErrorAction SilentlyContinue
  if((Test-Path $StartupPark) -and -not (Get-ChildItem $StartupPark -Recurse -File -ErrorAction SilentlyContinue)){ Remove-Item -Path $StartupPark -Recurse -Force -ErrorAction SilentlyContinue }
}
function Restore-RunKey([string]$runKey,[string]$park,[string]$label){
  Ensure-Key $runKey
  foreach($p in (Get-ItemProperty -Path $park).PSObject.Properties){
    if($p.Name -like 'PS*'){ continue }
    $kind=(Get-Item $park).GetValueKind($p.Name)
    New-ItemProperty -Path $runKey -Name $p.Name -PropertyType $kind -Value $p.Value -Force | Out-Null
    $script:RestoredLaunch.Add([string]$p.Value)
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
if($RootRewritten -is [string]){ Log "WARN Secure-Root $RootRewritten" }
elseif($RootRewritten){ Log "Secure-Root: $Root was not locked - ACL rewritten (this propagates onto the park)" }
else { Log "Secure-Root: $Root already locked (unchanged)" }
# PreventDeviceEncryption=1 (D3/T4): permanent, both hardware and VM. Stops Windows auto-encrypting C: on the
# hardware (which would break the whole VM scheme and Garuda reading C:). Needs SYSTEM - works from the boot task.
try {
  $bl='HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker'
  if(-not (Test-Path $bl)){ New-Item -Path $bl -Force | Out-Null }
  if((Get-ItemProperty -Path $bl -Name PreventDeviceEncryption -ErrorAction SilentlyContinue).PreventDeviceEncryption -ne 1){
    New-ItemProperty -Path $bl -Name PreventDeviceEncryption -PropertyType DWord -Value 1 -Force | Out-Null
    Log "PreventDeviceEncryption set to 1"
  }
} catch { Log "WARN PreventDeviceEncryption (needs SYSTEM): $($_.Exception.Message)" }
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
