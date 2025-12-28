function P {
    Write-Warning -Message "The module you're trying to install has been deprecated; Please install the new Harden System Security app from the Microsoft Store: https://apps.microsoft.com/detail/9P7GGFL7DX57"
}
function AppControl {
    [CmdletBinding()]
    param ([Parameter(Mandatory = $false)][string]$MSIXBundlePath, [Parameter(Mandatory = $False)][string]$SignTool)
    Write-Warning -Message 'Please install the AppControl Manager from the Microsoft Store: https://apps.microsoft.com/detail/9PNG1JDDTGP8'
    Write-Warning -Message 'Additionally, both the AppControl Manager and the Harden System Security apps are now capable to install any app package with any certificate.'
}