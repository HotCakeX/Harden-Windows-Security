Function Get-AuditEventLogsProcessing {
    <#
    .SYNOPSIS
        Function to separately capture FileHashes of deleted files and FilePaths of available files from Event Viewer Audit Logs
    .INPUTS
        System.DateTime
    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    param (
        [System.DateTime]$Date
    )

    begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"
        # Importing the required sub-modules
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-GlobalRootDrives.psm1" -Force

        # Get the local disks mappings
        [System.Object[]]$DriveLettersGlobalRootFix = Get-GlobalRootDrives

        # Defining a custom object to store the results and return it at the end
        $AuditEventLogsProcessingResults = [PSCustomObject]@{
            # Defining object properties as arrays that store file paths
            AvailableFilesPaths = [System.IO.FileInfo[]]@()
            DeletedFileHashes   = [System.IO.FileInfo[]]@()
        }
    }

    process {

        # Event Viewer Code Integrity logs scan
        foreach ($event in Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; ID = 3076 } -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_.TimeCreated -ge $Date } ) {

            $Xml = [System.Xml.XmlDocument]$event.toxml()

            $Xml.event.eventdata.data | ForEach-Object -Begin { $Hash = @{} } -Process { $Hash[$_.name] = $_.'#text' } -End { [pscustomobject]$Hash } | ForEach-Object -Process {

                # Define the regex pattern
                [System.String]$Pattern = '\\Device\\HarddiskVolume(\d+)\\(.*)$'

                if ($_.'File Name' -match $Pattern) {
                    [System.Int64]$HardDiskVolumeNumber = $Matches[1]
                    [System.String]$RemainingPath = $Matches[2]
                    [PSCustomObject]$GetLetter = $DriveLettersGlobalRootFix | Where-Object -FilterScript { $_.devicepath -eq "\Device\HarddiskVolume$HardDiskVolumeNumber" }
                    [System.IO.FileInfo]$UsablePath = "$($GetLetter.DriveLetter)$RemainingPath"
                    $_.'File Name' = $_.'File Name' -replace $Pattern, $UsablePath
                }

                # Check if the file is currently on the disk
                if (Test-Path -Path $_.'File Name') {
                    $AuditEventLogsProcessingResults.AvailableFilesPaths += $_.'File Name'
                }

                # If the file is not currently on the disk, extract its hashes from event log
                else {
                    $AuditEventLogsProcessingResults.DeletedFileHashes += $_ | Select-Object -Property FileVersion, 'File Name', PolicyGUID, 'SHA256 Hash', 'SHA256 Flat Hash', 'SHA1 Hash', 'SHA1 Flat Hash'
                }
            }
        }
    }

    end {
        # return the results as an object
        return $AuditEventLogsProcessingResults
    }
}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Get-AuditEventLogsProcessing'
