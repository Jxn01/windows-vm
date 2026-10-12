<#  test-guard-policies.ps1 -- run guard.ps1's policy save/apply/restore functions for real, on scratch keys.
    Windows PowerShell 5.1 (the guard's runtime), any user, no elevation: it touches only HKCU:\Software\jxn-guard-test
    and a temp state file, never the real policies or C:\ProgramData\jxn-vm. Exit 0 = all PASS.
      powershell -NoProfile -ExecutionPolicy Bypass -File test-guard-policies.ps1 [-Guard <path to guard.ps1>]
    Covers both state.json shapes: one written by a guard before 2026-10-12 (NoAutoUpdate_prev in .wu, no .policies)
    and the current one (.policies). The Linux suite checks the same code statically (tests/test_guard_static.py).
#>
param([string]$Guard = (Join-Path $PSScriptRoot 'guard.ps1'))
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Guard, [ref]$null, [ref]$null)
$fns = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
foreach ($fn in $fns) { if ($fn.Name -in 'Read-Policy','Set-VmPolicy','Saved-Policy','Ensure-PolicyState') { . ([scriptblock]::Create($fn.Extent.Text)) } }
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
Remove-Item $base -Recurse -Force; Remove-Item $StateFile -Force
if ($script:failed) { "$($script:failed) FAILED"; exit 1 } else { "all PASS" }
