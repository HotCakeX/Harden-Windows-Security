Function Get-CIPolicySetting {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)][System.String]$Provider,
        [Parameter(Mandatory = $true)][System.String]$Key,
        [Parameter(Mandatory = $true)][System.String]$ValueName
    )
    Write-Host -ForegroundColor Green -Object "This function's job has been completely added to the new AppControl Manager app. It offers a complete graphical user interface (GUI) for easy usage. Please refer to this GitHub page to see how to install and use it:`nhttps://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager"
}