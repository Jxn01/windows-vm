<#  test-guard-policies.ps1 -- run guard.ps1's policy save/apply/restore functions for real, on scratch keys.
    Windows PowerShell 5.1 (the guard's runtime), any user, no elevation: it touches only HKCU:\Software\jxn-guard-test
    and a temp state file, never the real policies or C:\ProgramData\jxn-vm. Exit 0 = all PASS.
      powershell -NoProfile -ExecutionPolicy Bypass -File test-guard-policies.ps1 [-Guard <path to guard.ps1>]
    Covers both state.json shapes: one written by a guard before 2026-10-12 (NoAutoUpdate_prev in .wu, no .policies)
    and the current one (.policies); that setting a policy keeps the key's OTHER values; and Run parking across two VM
    boots in a row + a hardware restore into a Run key that already has values (2026-10-15: the old guard's
    `New-Item -Force` wiped the parked Run entries on the second VM boot). The Linux suite checks the same code statically (tests/test_guard_static.py).
#>
param([string]$Guard = (Join-Path $PSScriptRoot 'guard.ps1'))
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Guard, [ref]$null, [ref]$null)
$fns = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
foreach ($fn in $fns) { if ($fn.Name -in 'Ensure-Key','Read-Policy','Set-VmPolicy','Saved-Policy','Ensure-PolicyState','Move-RunAway','Restore-RunKey') { . ([scriptblock]::Create($fn.Extent.Text)) } }
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
Check 'D: 2nd VM boot in a row kept the parked values (the 2026-10-09 loss)' (($names -contains 'Steam') -and ($names -contains 'Spotify'))
Check 'D: the value KIND survives parking (ExpandString)' ((Get-Item "$RunPark\runUser").GetValueKind('Spotify') -eq 'ExpandString')
New-ItemProperty $run -Name OneDrive -Value 'C:\od.exe' -PropertyType String | Out-Null   # added while parked
Restore-RunKey $run "$RunPark\runUser" 'runUser'                      # hardware restore
$live = @((Get-Item $run).GetValueNames())
Check 'D: restore put Steam + Spotify back' (($live -contains 'Steam') -and ($live -contains 'Spotify'))
Check 'D: restore kept a value already in the live Run key' ($live -contains 'OneDrive')
Check 'D: restored value text is exact' ((Get-Item $run).GetValue('Steam') -eq '"C:\Steam\steam.exe" -silent')

Remove-Item $base -Recurse -Force; Remove-Item $StateFile -Force
if ($script:failed) { "$($script:failed) FAILED"; exit 1 } else { "all PASS" }
