#Region SYSTEM-priv Intune info gathering
# using schtasks.exe instead of CimInstance/cmdlet wherever it makes the process faster
Write-Verbose -Message 'Collecting Intune applied policy details from the System'
# MDM_BitLocker
[System.String[]]$CimInstancesList = @('MDM_Firewall_DomainProfile02', 'MDM_Firewall_PrivateProfile02', 'MDM_Firewall_PublicProfile02', 'MDM_Policy_Result01_Update02', 'MDM_Policy_Result01_System02')
[System.String]$TaskPathGUID = [System.Guid]::NewGuid().ToString().Replace('-', '')
[System.String]$BaseDirectory = [HardenWindowsSecurity.GlobalVars]::WorkingDir
[System.String]$TaskPath = "CimInstances$TaskPathGUID"
[System.String]$CimInstancesListString = foreach ($MDMName in $CimInstancesList) {
    "'$MDMName',"
}
$CimInstancesListString = $CimInstancesListString.TrimEnd(',')
[System.String]$TaskName = 'CIMInstance'
$Argument = @"
-NoProfile -WindowStyle Hidden -Command "& {foreach (`$Item in @($CimInstancesListString)) { Get-CimInstance -Namespace 'root\cimv2\mdm\dmmap' -ClassName `$Item | ConvertTo-Json -Depth 100 | Out-File -FilePath \"$BaseDirectory\`$Item.json\" -Force }}"
"@

[Microsoft.Management.Infrastructure.CimInstance]$Action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument $Argument
[Microsoft.Management.Infrastructure.CimInstance]$TaskPrincipal = New-ScheduledTaskPrincipal -LogonType S4U -UserId 'S-1-5-18' -RunLevel Highest
$null = Register-ScheduledTask -Action $Action -Principal $TaskPrincipal -TaskPath $TaskPath -TaskName $TaskName -Description $TaskName -Force
[Microsoft.Management.Infrastructure.CimInstance]$TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility 'Win8' -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3)
$null = Set-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Settings $TaskSettings
Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
while ((schtasks.exe /Query /TN "\$TaskPath\$TaskName" /fo CSV | ConvertFrom-Csv).Status -in ('Running', 'Queued')) {
    Write-Debug -Message 'Waiting half a second more before attempting to delete the scheduled task'
    Start-Sleep -Milliseconds 500
}
schtasks.exe /Delete /TN "\$TaskPath\$TaskName" /F # Delete task
schtasks.exe /Delete /TN "$TaskPath" /F *>$null # Delete task path
if ($LASTEXITCODE -ne '0') {
    Write-Verbose -Message "Failed to delete the task with the path '$TaskPath' and name '$TaskName'." -Verbose
}
#Endregion
