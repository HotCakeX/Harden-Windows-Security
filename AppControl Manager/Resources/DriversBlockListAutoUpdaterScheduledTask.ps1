$PowerShellCommand = @"
try { Invoke-WebRequest -Uri 'https://aka.ms/VulnerableDriverBlockList' -OutFile 'VulnerableDriverBlockList.zip' -ErrorAction Stop }catch { exit 1 }
Expand-Archive -Path '.\VulnerableDriverBlockList.zip' -DestinationPath 'VulnerableDriverBlockList' -Force
`$SiPolicy_EnforcedFile = Get-ChildItem -Recurse -File -Path '.\VulnerableDriverBlockList' -Filter 'SiPolicy_Enforced.p7b' | Select-Object -First 1
Move-Item -Path `$SiPolicy_EnforcedFile.FullName -Destination (`$env:SystemDrive + '\Windows\System32\CodeIntegrity\SiPolicy.p7b') -Force
citool --refresh -json; Remove-Item -Path '.\VulnerableDriverBlockList' -Recurse -Force; Remove-Item -Path '.\VulnerableDriverBlockList.zip' -Force
"@
$Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -Command $PowerShellCommand"
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1) -RepetitionInterval (New-TimeSpan -Days 7)
$Principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType S4U -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Compatibility Win8 -RunOnlyIfNetworkAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -RestartCount 4 -RestartInterval (New-TimeSpan -Hours 6)
Register-ScheduledTask -TaskName 'MSFT Driver Block list update' -Description 'Microsoft Recommended Driver Block List update' -TaskPath '\MSFT Driver Block list update\' -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force