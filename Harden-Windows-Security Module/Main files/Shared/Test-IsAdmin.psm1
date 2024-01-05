Function Test-IsAdmin {
    <#
    .SYNOPSIS
        Function to test if current session has administrator privileges
    .LINK
        https://devblogs.microsoft.com/scripting/use-function-to-determine-elevation-of-powershell-console/
    .INPUTS
        None
    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    param()
    [System.Security.Principal.WindowsIdentity]$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    [System.Security.Principal.WindowsPrincipal]$Principal = New-Object -TypeName 'Security.Principal.WindowsPrincipal' -ArgumentList $Identity
    $Principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Test-IsAdmin' -Verbose:$false
