Function Invoke-CiSigning {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$CiPath,
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$SignToolPathFinal,
        [Parameter(Mandatory = $true)][System.String]$CertCN
    )
    [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false

    # Configure the parameter splat
    [System.Collections.Hashtable]$ProcessParams = @{
        'ArgumentList' = 'sign', '/v' , '/n', "`"$CertCN`"", '/p7', '.', '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'certHash', "$($CiPath.Name)"
        'FilePath'     = $SignToolPathFinal
        'NoNewWindow'  = $true
        'Wait'         = $true
        'ErrorAction'  = 'Stop'
    } # Only show the output of SignTool if Verbose switch is used
    if (!$Verbose) { $ProcessParams['RedirectStandardOutput'] = 'NUL' }

    Write-Verbose -Message 'Signing the base policy with the specified cert'
    Start-Process @ProcessParams
}
Export-ModuleMember -Function 'Invoke-CiSigning'
