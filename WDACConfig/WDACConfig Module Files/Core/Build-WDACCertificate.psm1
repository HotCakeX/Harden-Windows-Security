Function Build-WDACCertificate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)][System.String]$CommonName = 'Code Signing Certificate',
        [Parameter(Mandatory = $false)][System.String]$FileName = 'Code Signing Certificate',
        [Parameter(Mandatory = $false)][System.String]$BuildingMethod = 'Method2',
        [Parameter(Mandatory = $false)][System.Security.SecureString]$Password,
        [Parameter(Mandatory = $false)][switch]$Force
    )
    Write-Host -ForegroundColor Green -Object "This function's job has been completely added to the new AppControl Manager app. It offers a complete graphical user interface (GUI) for easy usage. Please refer to this GitHub page to see how to install and use it:`nhttps://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager"
}