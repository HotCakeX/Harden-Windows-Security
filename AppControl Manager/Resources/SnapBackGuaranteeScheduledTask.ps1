$Action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c `"C:\Program Files\WDACConfig\EnforcedModeSnapBack.cmd`""
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType S4U -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Compatibility Win8 -Priority 0 -Hidden -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 3)
Register-ScheduledTask -TaskName 'EnforcedModeSnapBack' -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force