function P {
    Write-Warning -Message "The module you're trying to install has been deprecated; Please install the new System Security Studio app from: https://github.com/OFFSECHQ/windows-security-studio/releases"
}
function AppControl {
    [CmdletBinding()]
    param ([Parameter(Mandatory = $false)][string]$MSIXBundlePath, [Parameter(Mandatory = $False)][string]$SignTool)
    Write-Warning -Message 'Please install the App Control Studio from: https://github.com/OFFSECHQ/windows-security-studio/releases'
    Write-Warning -Message 'Both the App Control Studio and the System Security Studio apps are capable of installing any app package with any certificate.'
}