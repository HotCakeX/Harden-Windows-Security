Function Set-LogSize {
    <#
    .SYNOPSIS
        Increase Code Integrity Operational Event Logs size from the default 1MB to user defined size
        Also automatically increases the log size by 1MB if the current free space is less than 1MB and the current maximum log size is less than or equal to 10MB.
        This is to prevent infinitely expanding the max log size automatically.
    .PARAMETER LogSize
        Size of the Code Integrity Operational Event Log
    .INPUTS
        System.Int64
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    param (
        [parameter(Mandatory = $false)][System.UInt64]$LogSize
    )
    Begin {
        Write-Verbose -Message 'Set-LogSize function started...'

        [System.String]$LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
        [System.Diagnostics.Eventing.Reader.EventLogConfiguration]$Log = New-Object -TypeName System.Diagnostics.Eventing.Reader.EventLogConfiguration -ArgumentList $LogName
        [System.IO.FileInfo]$LogFilePath = [System.Environment]::ExpandEnvironmentVariables($Log.LogFilePath)
        [System.Double]$CurrentLogFileSize = $LogFilePath.Length
        [System.Double]$CurrentLogMaxSize = $Log.MaximumSizeInBytes
    }
    Process {
        if (-NOT $LogSize) {
            if (($CurrentLogMaxSize - $CurrentLogFileSize) -lt 1MB) {
                if ($CurrentLogMaxSize -le 10MB) {
                    Write-Verbose -Message "Increasing the Code Integrity log size by 1MB because its current free space ($(($CurrentLogMaxSize - $CurrentLogFileSize) / 1MB)) is less than 1MB"
                    $Log.MaximumSizeInBytes = $CurrentLogMaxSize + 1MB
                    $Log.IsEnabled = $true
                    $Log.SaveChanges()
                }
            }
        }
        else {
            Write-Verbose -Message "Setting Code Integrity log size to $LogSize"
            $Log.MaximumSizeInBytes = $LogSize
            $Log.IsEnabled = $true
            $Log.SaveChanges()
        }
    }
}
Export-ModuleMember -Function 'Set-LogSize'
