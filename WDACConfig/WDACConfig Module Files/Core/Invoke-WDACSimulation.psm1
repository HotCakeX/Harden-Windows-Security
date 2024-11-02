Function Invoke-WDACSimulation {
    [CmdletBinding()]
    Param(
        [ArgumentCompleter([WDACConfig.ArgCompleter.XmlFilePathsPicker])]
        [Alias('X')][Parameter(Mandatory = $true)][string]$XmlFilePath,
        [ArgumentCompleter([WDACConfig.ArgCompleter.FolderPicker])]
        [Alias('D')][Parameter(Mandatory = $false)][string[]]$FolderPath,
        [ArgumentCompleter([WDACConfig.ArgCompleter.MultipleAnyFilePathsPicker])]
        [Alias('F')][Parameter(Mandatory = $false)][string[]]$FilePath,
        [Alias('C')][Parameter(Mandatory = $false)][switch]$CSVOutput,
        [Alias('N')][Parameter(Mandatory = $false)][switch]$NoCatalogScanning,
        [ArgumentCompleter([WDACConfig.ArgCompleter.FolderPicker])]
        [Alias('Cat')][Parameter(Mandatory = $false)][string[]]$CatRootPath,
        [Alias('CPU')][Parameter(Mandatory = $false)][System.UInt32]$ThreadsCount = 2
    )
    [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)
    Update-WDACConfigPSModule -InvocationStatement $MyInvocation.Statement
    $FinalSimulationResults = [WDACConfig.InvokeWDACSimulation]::Invoke($FilePath, $FolderPath, $XmlFilePath, $NoCatalogScanning, $CSVOutput, $CatRootPath, $ThreadsCount)

    # Change the color of the Table header to SkyBlue
    $PSStyle.Formatting.TableHeader = "$($PSStyle.Foreground.FromRGB(135,206,235))"

    if ($FinalSimulationResults.Count -gt 10000) {
        # If the result is too big and the user forgot to use CSV Output then output everything to CSV instead of trying to display on the console
        if (!$CSVOutput) {
            $FinalSimulationResults.Values | Sort-Object -Property IsAuthorized -Descending | Export-Csv -LiteralPath (Join-Path -Path ([WDACConfig.GlobalVars]::UserConfigDir) -ChildPath "WDAC Simulation Output $(Get-Date -Format "MM-dd-yyyy 'at' HH-mm-ss").csv") -Force
        }
        Return "The number of files is too many to display on the console. Saving the results in a CSV file in '$((Join-Path -Path ([WDACConfig.GlobalVars]::UserConfigDir) -ChildPath "WDAC Simulation Output $(Get-Date -Format "MM-dd-yyyy 'at' HH-mm-ss").csv"))'"
    }

    # Return the final main output array as a table
    Return $FinalSimulationResults.Values | Select-Object -Property 'Path',
    @{
        Label      = 'Source'
        Expression =
        { switch ($_.Source) {
                { $_ -eq 'Signer' } { $Color = "$($PSStyle.Foreground.FromRGB(152,255,152))" }
                { $_ -eq 'Hash' } { $Color = "$($PSStyle.Foreground.FromRGB(255,255,49))" }
                { $_ -eq 'Unsigned' } { $Color = "$($PSStyle.Foreground.FromRGB(255,20,147))" }
            }
            "$Color$($_.Source)$($PSStyle.Reset)"
        }
    },
    @{
        Label      = 'IsAuthorized'
        Expression =
        {
            switch ($_.IsAuthorized) {
                { $_ -eq $true } { $Color = "$($PSStyle.Foreground.FromRGB(255,0,255))"; break }
                { $_ -eq $false } { $Color = "$($PSStyle.Foreground.FromRGB(255,165,0))$($PSStyle.Blink)"; break }
            }
            "$Color$($_.IsAuthorized)$($PSStyle.Reset)"
        }
    },
    @{
        Label      = 'MatchCriteria'
        Expression = {
            # If the MatchCriteria starts with 'UnknownError', truncate it to 50 characters. The full string will be displayed in the CSV output file. If it does not then just display it as it is
            $_.MatchCriteria -match 'UnknownError' ? $_.MatchCriteria.Substring(0, 50) + '...' : "$($_.MatchCriteria)"
        }
    },
    @{
        Label      = 'SpecificFileName'
        Expression = {
            $_.SpecificFileNameLevelMatchCriteria
        }
    } | Sort-Object -Property IsAuthorized | Format-Table

    <#
.SYNOPSIS
    Simulates the deployment of the WDAC policy. It can produce a very detailed CSV file that contains the output of the simulation.
    On the console, it can display a table that shows the file path, source, MatchCriteria, and whether the file is allowed or not.
    The console results are color coded for easier reading.

    Properties explanation:

    FilePath:       The name of the file gathered from its full path. (the actual long path of the file is not displayed in the console output, only in the CSV file)
    Source:         The source of the file's MatchCriteria, e.g., 'Signer' (For signed files only), 'Hash' (For signed and unsigned files), 'Unsigned' (For unsigned files only)
    MatchCriteria:  The reason the file is allowed or not. For files authorized by FilePublisher level, it will show the specific file name level that the file is authorized by. (https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#table-3--specificfilenamelevel-options)
    IsAuthorized:   A boolean value that indicates whether the file is allowed or not.
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Invoke-WDACSimulation
.DESCRIPTION
    Simulates the deployment of an App Control policy by analyzing a folder (recursively) or files and checking which of the detected files are allowed by a user selected policy xml file
.PARAMETER FolderPath
    Browse for a folders to include in the simulation
.PARAMETER FilePath
    Browse for files to include in the simulation
.PARAMETER XmlFilePath
    Browse for the App Control policy XML file
.PARAMETER NoCatalogScanning
    Bypass the scanning of the security catalogs on the system
.PARAMETER CatRootPath
    Provide path(s) to directories where security catalog .cat files are located. If not provided, the default path is C:\Windows\System32\CatRoot
.PARAMETER CSVOutput
    Exports the output to a CSV file. The CSV output is saved in the WDACConfig folder: C:\Program Files\WDACConfig
.PARAMETER ThreadsCount
    The number of the concurrent/parallel tasks to use when performing App Control Simulation.
    By default it uses 2 parallel tasks. Minimum allowed value is 1.
.INPUTS
    System.IO.FileInfo[]
    System.IO.DirectoryInfo[]
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.Collections.Generic.List[WDACConfig.SimulationOutput]
.EXAMPLE
    Invoke-WDACSimulation -FolderPath 'C:\Windows\System32' -XmlFilePath 'C:\Users\HotCakeX\Desktop\Policy.xml'
    This example will simulate the deployment of the policy.xml file against the C:\Windows\System32 folder
.NOTES
    WDAC templates such as 'Default Windows' and 'Allow Microsoft' don't have CertPublisher element in their Signers because they don't target a leaf certificate,
    thus they weren't created using FilePublisher level, they were created using Publisher or Root certificate levels to allow Microsoft's wellknown certificates.
#>
}