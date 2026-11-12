<#  test-guard-policies.ps1 -- run guard.ps1's policy save/apply/restore functions for real, on scratch keys.
    Windows PowerShell 5.1 (the guard's runtime), any user, no elevation: it touches only HKCU:\Software\jxn-guard-test
    and a temp state file, never the real policies or C:\ProgramData\jxn-vm. Exit 0 = all PASS.
      powershell -NoProfile -ExecutionPolicy Bypass -File test-guard-policies.ps1 [-Guard <path to guard.ps1>]
    Covers both state.json shapes: one written by an older guard (NoAutoUpdate_prev in .wu, no .policies)
    and the current one (.policies); that setting a policy keeps the key's OTHER values; and Run parking across two VM
    boots in a row + a hardware restore into a Run key that already has values (a forced `New-Item` once wiped the
    parked Run entries on the second VM boot); and that a parked Startup shortcut comes back
    with its folder's permissions, not the park's (section E, in a scratch folder under %TEMP%). The Linux suite checks the same code statically (tests/test_guard_static.py).
#>
param([string]$Guard = (Join-Path $PSScriptRoot 'guard.ps1'))
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Guard, [ref]$null, [ref]$null)
$fns = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
foreach ($fn in $fns) { if ($fn.Name -in 'Ensure-Key','Read-Policy','Set-VmPolicy','Saved-Policy','Ensure-PolicyState','Move-RunAway','Restore-RunKey','Park-File','Link-Count','File-Rights','Folder-FileRules','Test-SafeDir','Unpark-File','Move-StartupAway','Restore-Parked') { . ([scriptblock]::Create($fn.Extent.Text)) } }
$restoreFn = $fns | Where-Object Name -eq 'Restore'
$restoreLoop = $restoreFn.Body.FindAll({ $args[0] -is [System.Management.Automation.Language.ForEachStatementAst] -and $args[0].Extent.Text -match 'Saved-Policy' }, $true) | Select-Object -First 1
function Log($m) { $script:log += , $m }
$base = 'HKCU:\Software\jxn-guard-test'; Remove-Item $base -Recurse -Force -ErrorAction SilentlyContinue
$VmPolicies = [ordered]@{
  NoAutoUpdate      = @{ key="$base\AU"; name='NoAutoUpdate'; vm=1 }
  StoreAutoDownload = @{ key="$base\Store"; name='AutoDownload'; vm=2 }
}
$StateFile = "$env:TEMP\jxn-guard-test-state.json"
$script:failed = 0
function Check($what, $ok) { if (-not $ok) { $script:failed++ }; "{0}  {1}" -f $(if ($ok) { "PASS" } else { "FAIL" }), $what }

# A. a state.json from the OLD guard: NoAutoUpdate_prev=null (absent originally), no 'policies'; Store value pre-set to 4
New-Item "$base\Store" -Force | Out-Null; New-ItemProperty "$base\Store" -Name AutoDownload -Value 4 -PropertyType DWord -Force | Out-Null
'{"mode":"vm","wu":{"wuauserv":"Manual","NoAutoUpdate_prev":null},"tasks":[],"services":{}}' | Set-Content $StateFile
$state = Get-Content $StateFile -Raw | ConvertFrom-Json; $script:log = @()
Ensure-PolicyState $state
$saved = Get-Content $StateFile -Raw | ConvertFrom-Json
Check 'A: Store original captured and SAVED before any change (had=true, value=4)' ($saved.policies.StoreAutoDownload.had -and $saved.policies.StoreAutoDownload.value -eq 4)
Check 'A: NoAutoUpdate NOT re-captured (comes from the old wu.NoAutoUpdate_prev)' (-not ($saved.policies.PSObject.Properties.Name -contains 'NoAutoUpdate'))
foreach ($id in $VmPolicies.Keys) { Set-VmPolicy $id }
Check 'A: VM mode set NoAutoUpdate=1, AutoDownload=2' (((Get-ItemProperty "$base\AU").NoAutoUpdate -eq 1) -and ((Get-ItemProperty "$base\Store").AutoDownload -eq 2))
$state = $saved; . ([scriptblock]::Create($restoreLoop.Extent.Text))
Check 'A: restore removed NoAutoUpdate (it was absent)' ($null -eq (Get-ItemProperty "$base\AU" -Name NoAutoUpdate -ErrorAction SilentlyContinue))
Check 'A: restore put AutoDownload back to 4' ((Get-ItemProperty "$base\Store").AutoDownload -eq 4)

# B. the NEW plan shape, re-applied on a 2nd VM boot: nothing re-captured, round-trip exact
Remove-Item $base -Recurse -Force; New-Item "$base\AU" -Force | Out-Null; New-ItemProperty "$base\AU" -Name NoAutoUpdate -Value 0 -PropertyType DWord -Force | Out-Null
$plan = [ordered]@{ mode='vm'; wu=@{}; tasks=@(); services=@{} }; $plan.policies = [ordered]@{}; foreach ($id in $VmPolicies.Keys) { $plan.policies[$id] = Read-Policy $VmPolicies[$id] }
$plan | ConvertTo-Json -Depth 6 | Set-Content $StateFile
$state = Get-Content $StateFile -Raw | ConvertFrom-Json; $before = (Get-Item $StateFile).LastWriteTimeUtc; Start-Sleep -Milliseconds 50
foreach ($i in 1, 2) { Ensure-PolicyState $state; foreach ($id in $VmPolicies.Keys) { Set-VmPolicy $id } }
Check 'B: a complete state is not rewritten on re-apply' ((Get-Item $StateFile).LastWriteTimeUtc -eq $before)
. ([scriptblock]::Create($restoreLoop.Extent.Text))
Check 'B: NoAutoUpdate restored to its original 0' ((Get-ItemProperty "$base\AU").NoAutoUpdate -eq 0)
Check 'B: AutoDownload removed again (it was absent)' ($null -eq (Get-ItemProperty "$base\Store" -Name AutoDownload -ErrorAction SilentlyContinue))
# C. setting a policy keeps the key's OTHER values (the old Set-VmPolicy recreated the key empty)
Remove-Item $base -Recurse -Force; New-Item $base | Out-Null; New-Item "$base\AU" | Out-Null; New-ItemProperty "$base\AU" -Name AUOptions -Value 3 -PropertyType DWord | Out-Null
foreach ($id in $VmPolicies.Keys) { Set-VmPolicy $id }
Check 'C: Set-VmPolicy kept a sibling value (AUOptions=3)' ((Get-ItemProperty "$base\AU").AUOptions -eq 3)

# D. Run parking: VM boot, VM boot again, hardware restore into a Run key that gained a value meanwhile
$RunPark = "$base\park"; $run = "$base\Run"; $script:RestoredLaunch = New-Object System.Collections.Generic.List[string]
New-Item $run | Out-Null
New-ItemProperty $run -Name Steam -Value '"C:\Steam\steam.exe" -silent' -PropertyType String | Out-Null
New-ItemProperty $run -Name Spotify -Value '%APPDATA%\Spotify\Spotify.exe /minimized' -PropertyType ExpandString | Out-Null
Ensure-Key $RunPark; Move-RunAway $run 'runUser'                       # 1st VM boot
Check 'D: 1st VM boot parked both values and emptied Run' ((@((Get-Item "$RunPark\runUser").GetValueNames()).Count -eq 2) -and (@((Get-Item $run).GetValueNames()).Count -eq 0))
Ensure-Key $RunPark; Move-RunAway $run 'runUser'                       # 2nd VM boot in a row: Run is empty now
$names = @((Get-Item "$RunPark\runUser").GetValueNames())
Check 'D: 2nd VM boot in a row kept the parked values' (($names -contains 'Steam') -and ($names -contains 'Spotify'))
Check 'D: the value KIND survives parking (ExpandString)' ((Get-Item "$RunPark\runUser").GetValueKind('Spotify') -eq 'ExpandString')
New-ItemProperty $run -Name OneDrive -Value 'C:\od.exe' -PropertyType String | Out-Null   # added while parked
Restore-RunKey $run "$RunPark\runUser" 'runUser'                      # hardware restore
$live = @((Get-Item $run).GetValueNames())
Check 'D: restore put Steam + Spotify back' (($live -contains 'Steam') -and ($live -contains 'Spotify'))
Check 'D: restore kept a value already in the live Run key' ($live -contains 'OneDrive')
Check 'D: restored value text is exact' ((Get-Item $run).GetValue('Steam') -eq '"C:\Steam\steam.exe" -silent')

# E. Startup .lnk parking keeps each folder's permissions (a shortcut that came back from the park with the park's
#    SYSTEM+Administrators-only DACL - a same-volume move keeps the security descriptor - could not be read by the
#    owner's unelevated Explorer, which skipped it). Unelevated, in %TEMP%:
#    'Startup' grants me FullControl + Everyone ReadAndExecute (inheritable), 'root' plays the locked park (me only).
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$every = New-Object System.Security.Principal.SecurityIdentifier 'S-1-1-0'
$users = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-545'
function Lock-Dir([string]$d, $readers) {   # protected DACL; re-applying it propagates down the tree, as the old Secure-Root did at every guard start
  New-Item -ItemType Directory -Force -Path $d | Out-Null
  $a = Get-Acl -LiteralPath $d; $a.SetAccessRuleProtection($true, $false)
  foreach ($r in @($a.Access)) { [void]$a.RemoveAccessRule($r) }
  $a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
  foreach ($s in $readers) { $a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($s, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))) }
  Set-Acl -LiteralPath $d -AclObject $a }
function Rules([string]$f, [bool]$explicit, [bool]$inherited) { @((Get-Acl -LiteralPath $f).GetAccessRules($explicit, $inherited, [System.Security.Principal.SecurityIdentifier])) }
function Everyone-Reads([string]$f) { [bool](@(Rules $f $true $true | Where-Object { $_.IdentityReference -eq $every -and ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ReadData) })) }
$tmp = Join-Path $env:TEMP 'jxn-guard-acl-test'; Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
$liveDir = "$tmp\Startup"; $parkRoot = "$tmp\root"; $outside = "$tmp\outside"
Lock-Dir $liveDir @($every); Lock-Dir $parkRoot @(); Lock-Dir $outside @()
# control: the bare round trip the old guard did. If this does not lose the ACE, the harness cannot see the trap.
'x' | Set-Content "$liveDir\bare.lnk"
Move-Item "$liveDir\bare.lnk" "$parkRoot\bare.lnk"; Lock-Dir $parkRoot @(); Move-Item "$parkRoot\bare.lnk" "$liveDir\bare.lnk"
Check 'E: control - a bare Move-Item round trip loses the Startup folder''s ACE (the trap is visible)' (-not (Everyone-Reads "$liveDir\bare.lnk"))
Remove-Item "$liveDir\bare.lnk" -Force
# the guard's own park + restore
$StartupDirs = @{ user = $liveDir }; $StartupPark = "$parkRoot\suppressed-startup"; $RunPark = "$base\no-run-park"
$script:RestoredLaunch = New-Object System.Collections.Generic.List[string]
'x' | Set-Content "$liveDir\zebar.exe.lnk"; 'x' | Set-Content "$liveDir\wtq.exe.lnk"
$a = Get-Acl -LiteralPath "$liveDir\wtq.exe.lnk"; $a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($users, 'Write', 'Allow'))); Set-Acl -LiteralPath "$liveDir\wtq.exe.lnk" -AclObject $a
# a hard link planted in Startup that points at a file outside it: the restore must not write ACLs through it
'secret' | Set-Content "$outside\target.txt"; New-Item -ItemType HardLink -Path "$liveDir\planted.lnk" -Target "$outside\target.txt" | Out-Null
Check 'E: setup - a Startup file inherits the folder''s Everyone ACE' (Everyone-Reads "$liveDir\zebar.exe.lnk")
Check 'E: setup - Link-Count sees 1 name for a plain file and 2 for the planted hard link' (((Link-Count "$liveDir\zebar.exe.lnk") -eq 1) -and ((Link-Count "$liveDir\planted.lnk") -eq 2))
Move-StartupAway $liveDir 'user'                                       # VM boot
Check 'E: VM boot parked the shortcuts' ((Test-Path "$StartupPark\user\zebar.exe.lnk") -and (Test-Path "$StartupPark\user\planted.lnk") -and -not (Test-Path "$liveDir\zebar.exe.lnk"))
Lock-Dir $parkRoot @()                                                 # what the old guard start did: strip the parked files
Check 'E: setup - the parked shortcut lost the Everyone ACE (the damaged state)' (-not (Everyone-Reads "$StartupPark\user\zebar.exe.lnk"))
$targetBefore = (Get-Acl -LiteralPath "$outside\target.txt").Sddl
$script:log = @(); Restore-Parked                                      # hardware restore
Check 'E: restored shortcut has the Startup folder''s permissions again' (Everyone-Reads "$liveDir\zebar.exe.lnk")
Check 'E: an explicit ACE survives the round trip' ([bool](@(Rules "$liveDir\wtq.exe.lnk" $true $false | Where-Object { $_.IdentityReference -eq $users })))
Check 'E: restored shortcut keeps inheritance on' (-not (Get-Acl -LiteralPath "$liveDir\zebar.exe.lnk").AreAccessRulesProtected)
Check 'E: the hard-linked entry was restored but NO ACL was written through it' ((Test-Path "$liveDir\planted.lnk") -and ((Get-Acl -LiteralPath "$outside\target.txt").Sddl -eq $targetBefore) -and -not (Everyone-Reads "$outside\target.txt"))
Check 'E: ...and the guard said so' ([bool](@($script:log | Where-Object { $_ -match 'WARN unpark planted\.lnk: hard-linked' })))
Check 'E: the park is gone after the restore' (-not (Test-Path $StartupPark))
# a junctioned Startup folder (the owner can plant one in their own profile): the restore must refuse and NOT move or
# write anything through it, leaving the shortcut in the park. Also a junction as a mid-path component.
$evil = "$tmp\evil-target"; New-Item -ItemType Directory -Force -Path $evil | Out-Null
$jLive = "$tmp\startup-via-junction"; New-Item -ItemType Junction -Path $jLive -Target $evil | Out-Null
$parent = "$tmp\parent"; New-Item -ItemType Directory -Force -Path "$parent\real" | Out-Null
$jParent = "$tmp\via-junction-parent"; New-Item -ItemType Junction -Path $jParent -Target $parent | Out-Null
Check 'E: Test-SafeDir accepts a real dir, rejects a junction and a junctioned parent' ((Test-SafeDir $liveDir) -and -not (Test-SafeDir $jLive) -and -not (Test-SafeDir "$jParent\real"))
$StartupDirs = @{ user = $jLive }; $StartupPark = "$parkRoot\suppressed-startup2"; New-Item -ItemType Directory -Force -Path "$StartupPark\user" | Out-Null
'z' | Set-Content "$StartupPark\user\redir.lnk"; $script:RestoredLaunch = New-Object System.Collections.Generic.List[string]
$script:log = @(); Restore-Parked
Check 'E: a junctioned Startup folder is refused - nothing written or moved through it' ((Test-Path "$StartupPark\user\redir.lnk") -and -not (Test-Path "$evil\redir.lnk"))
Check 'E: ...and the refusal was logged, and the park was kept' (([bool](@($script:log | Where-Object { $_ -match 'startup restore \[user\]: .*reparse point' }))) -and (Test-Path $StartupPark))
# the mirror on the PARK side: a junctioned source Startup folder must not have its target enumerated and moved out
'secret' | Set-Content "$parent\real\do-not-move.txt"; $StartupPark = "$parkRoot\suppressed-startup3"
$script:log = @(); Move-StartupAway "$jParent\real" 'user'
Check 'E: parking refuses a junctioned source folder - the target is not enumerated/moved' ((Test-Path "$parent\real\do-not-move.txt") -and -not (Test-Path "$StartupPark\user\do-not-move.txt"))
Remove-Item $tmp -Recurse -Force

Remove-Item $base -Recurse -Force; Remove-Item $StateFile -Force
if ($script:failed) { "$($script:failed) FAILED"; exit 1 } else { "all PASS" }
