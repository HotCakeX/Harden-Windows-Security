# $PSDefaultParameterValues only get read from scope where invocation occurs
# This is why this file is dot-sourced in every other component of the WDACConfig module at the beginning
$PSDefaultParameterValues = @{
    'Invoke-WebRequest:HttpVersion'        = '3.0'
    'Invoke-WebRequest:SslProtocol'        = 'Tls12,Tls13'
    'Invoke-RestMethod:HttpVersion'        = '3.0'
    'Invoke-RestMethod:SslProtocol'        = 'Tls12,Tls13'
    'Import-Module:Verbose'                = $false
    'Export-ModuleMember:Verbose'          = $false
    'Add-Type:Verbose'                     = $false
    'Get-WinEvent:Verbose'                 = $false
    'Confirm-CertCN:Verbose'               = $Verbose
    'Get-AuditEventLogsProcessing:Verbose' = $Verbose
    'Get-FileRules:Verbose'                = $Verbose
    'Get-BlockRulesMeta:Verbose'           = $Verbose
    'Get-GlobalRootDrives:Verbose'         = $Verbose
    'Get-RuleRefs:Verbose'                 = $Verbose
    'Get-SignTool:Verbose'                 = $Verbose
    'Move-UserModeToKernelMode:Verbose'    = $Verbose
    'New-EmptyPolicy:Verbose'              = $Verbose
    'Remove-ZerosFromIDs:Verbose'          = $Verbose
    'Set-LogSize:Verbose'                  = $Verbose
    'Test-FilePath:Verbose'                = $Verbose
    'Update-self:Verbose'                  = $Verbose
    'Write-ColorfulText:Verbose'           = $Verbose
}

