Function Set-LogSize {
    <#
    .SYNOPSIS
        Increase Code Integrity Operational Event Logs size from the default 1MB to user defined size
    .INPUTS
        System.Int64
    .OUTPUTS
        System.Void
    .PARAMETER LogSize
        Size of the Code Integrity Operational Event Log
    #>
    [CmdletBinding()]
    param (
        [System.Int64]$LogSize
    )
    # Importing the $PSDefaultParameterValues to the current session, prior to everything else
    . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"
    
    Write-Verbose -Message "Setting 'Microsoft-Windows-CodeIntegrity/Operational' log size to $LogSize"
    [System.String]$LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
    [System.Diagnostics.Eventing.Reader.EventLogConfiguration]$Log = New-Object -TypeName System.Diagnostics.Eventing.Reader.EventLogConfiguration -ArgumentList $LogName
    $Log.MaximumSizeInBytes = $LogSize
    $Log.IsEnabled = $true
    $Log.SaveChanges()
}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Set-LogSize'
