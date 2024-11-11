Function ConvertTo-WDACPolicy {
    [CmdletBinding(
        DefaultParameterSetName = 'All'
    )]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'In-Place Upgrade')]
        [System.IO.FileInfo]$PolicyToAddLogsTo,
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy File Association')]
        [System.IO.FileInfo]$BasePolicyFile,
        [Parameter(Mandatory = $false)][System.String]$Level = 'Auto',
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy GUID Association')]
        [Alias('BaseGUID')][System.Guid]$BasePolicyGUID,
        [Parameter(Mandatory = $false)][System.String]$SuppPolicyName,
        [Parameter(Mandatory = $false)][System.String]$Source = 'LocalEventLogs',
        [Parameter(Mandatory = $false)][System.String[]]$FilterByPolicyNames,
        [Parameter(Mandatory = $false)][System.String]$TimeSpan
    )
    Write-Host -ForegroundColor Green -Object "This function's job has been completely added to the new AppControl Manager app. It offers a complete graphical user interface (GUI) for easy usage. Please refer to this GitHub page to see how to install and use it:`nhttps://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager"
}