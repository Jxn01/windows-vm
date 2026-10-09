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
# Lock $Root to SYSTEM + Administrators (inheritance off) BEFORE putting guard.ps1 in it: the guard runs as
# SYSTEM, so a user-writable directory would be a local privilege-escalation vector.
$sys=[System.Security.Principal.SecurityIdentifier]'S-1-5-18'
$adm=[System.Security.Principal.SecurityIdentifier]'S-1-5-32-544'
$acl = Get-Acl -Path $Root
$acl.SetAccessRuleProtection($true,$false)
foreach($r in @($acl.Access)){ [void]$acl.RemoveAccessRule($r) }
$acl.SetOwner($sys)
foreach($sid in @($sys,$adm)){ $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))) }
Set-Acl -Path $Root -AclObject $acl
Write-Host "secured $Root (SYSTEM + Administrators only)"
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

# PreventDeviceEncryption=1 (plan D3/T4): harmless on the hardware, and it guarantees Windows never auto-encrypts
# C: (which would also stop Garuda reading it). Device Encryption cannot trigger in the VM anyway (no TPM / no
# Secure Boot), but this closes it for good.
$bl = 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker'
New-Item -Path $bl -Force | Out-Null
New-ItemProperty -Path $bl -Name PreventDeviceEncryption -PropertyType DWord -Value 1 -Force | Out-Null
Write-Host "set PreventDeviceEncryption=1"

# The guard runs at the NEXT boot. Install this from the HARDWARE Windows (S:\Projects\windows-vm\guest\) so it is
# in place before the VM is ever used - the hardware run detects hardware and does nothing, the first VM boot
# detects the VM and suppresses. (It can also be installed from inside the VM, but the hardware is simplest/safest.)
Write-Host "done. The guard will act at the next boot (VM -> suppress, hardware -> restore)."
