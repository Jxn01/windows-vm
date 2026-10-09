<#  Install the windows-vm VM-mode guard into Windows (run elevated, once).
    Copies guard.ps1 to C:\ProgramData\jxn-vm\ and registers it as a SYSTEM task that runs at every boot.
    Idempotent: re-running replaces the task and the script.  Uninstall: install-guard.ps1 -Uninstall
    This is the ONLY persistent change the guard needs; it changes nothing else on the hardware Windows.
#>
[CmdletBinding()]
param([switch]$Uninstall)
$ErrorActionPreference='Stop'
$Root='C:\ProgramData\jxn-vm'; $TaskName='jxn-vm-guard'
$Dest=Join-Path $Root 'guard.ps1'

if($Uninstall){
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Write-Host "guard task unregistered. (Run guard.ps1 -Mode hardware first if you need the autostarts restored.)"
  return
}

New-Item -ItemType Directory -Force -Path $Root | Out-Null
Copy-Item -Path (Join-Path $PSScriptRoot 'guard.ps1') -Destination $Dest -Force
Write-Host "installed $Dest"

$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
             -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Dest`" -Mode auto -Quiet"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
             -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -StartWhenAvailable -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -TaskPath '\' -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings -Description 'windows-vm VM-mode guard (suppress autostarts in the VM; restore on hardware). ~/Projects/windows-vm' -Force | Out-Null
Write-Host "registered SYSTEM boot task '$TaskName'"
