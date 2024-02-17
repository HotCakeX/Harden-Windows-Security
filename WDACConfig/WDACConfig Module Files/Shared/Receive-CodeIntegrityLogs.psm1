Function Receive-CodeIntegrityLogs {
    <#
    .SYNOPSIS
        A resilient function that retrieves the Code Integrity Operational logs and fixes the paths to the files that are being logged
        Then processes the output based on different criteria
    .PARAMETER Date
        The date from which the logs should be collected. If not specified, all logs will be collected.
        It accepts empty strings, nulls, and whitespace and they are treated as not specified.
    .PARAMETER Type
        The type of logs to be collected. The default value is 'Audit'
    .PARAMETER PostProcessing
        How to process the output for different scenarios
        OnlyExisting: Returns only the logs of files that exist on the disk
        OnlyDeleted: Returns only the hash details of files that do not exist on the disk
        Separate: Returns the file paths of files that exist on the disk and the hash details of files that do not exist on the disk, separately in a nested object
    .PARAMETER PolicyNames
        The names of the policies to filter the logs by
    .INPUTS
        System.String
    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [Parameter(Mandatory = $false)]
        [System.String]$Date,

        [ValidateSet('Audit', 'Blocked')]
        [Parameter(Mandatory = $false)]
        [System.String]$Type = 'Audit',

        [ValidateSet('OnlyExisting', 'OnlyDeleted' , 'Separate')]
        [parameter(mandatory = $false)]
        [System.String]$PostProcessing,

        [AllowEmptyString()]
        [AllowNull()]
        [parameter(mandatory = $false)]
        [System.String[]]$PolicyNames
    )

    Begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Importing the required sub-modules
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-GlobalRootDrives.psm1" -Force

        # Requested and Validated Signing Level Mappings : https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-tag-explanations#requested-and-validated-signing-level
        [System.Collections.Hashtable]$ReqValSigningLevels = @{
            [System.UInt16]0  = "Signing level hasn't yet been checked"
            [System.UInt16]1  = 'File is unsigned or has no signature that passes the active policies'
            [System.UInt16]2  = 'Trusted by Windows Defender Application Control policy'
            [System.UInt16]3  = 'Developer signed code'
            [System.UInt16]4  = 'Authenticode signed'
            [System.UInt16]5  = 'Microsoft Store signed app PPL (Protected Process Light)'
            [System.UInt16]6  = 'Microsoft Store-signed'
            [System.UInt16]7  = 'Signed by an Antimalware vendor whose product is using AMPPL'
            [System.UInt16]8  = 'Microsoft signed'
            [System.UInt16]11 = 'Only used for signing of the .NET NGEN compiler'
            [System.UInt16]12 = 'Windows signed'
            [System.UInt16]14 = 'Windows Trusted Computing Base signed'
        }

        # Validate the date provided if it's not null or empty or whitespace
        if (-NOT ([System.String]::IsNullOrWhiteSpace($Date))) {
            if (-NOT ([System.DateTime]::TryParse($Date, [ref]$Date))) {
                Throw 'The date provided is not in a valid DateTime type.'
            }
        }

        Try {
            # Set a flag indicating that the alternative drive letter mapping method is not necessary unless the primary method fails
            [System.Boolean]$AlternativeDriveLetterFix = $false

            # Get the local disks mappings
            [System.Object[]]$DriveLettersGlobalRootFix = Get-GlobalRootDrives
        }
        catch {
            Write-Verbose -Verbose -Message 'Receive-CodeIntegrityLogs: Could not get the drive mappings from the system using the primary method, trying the alternative method now'

            # Set the flag to true indicating the alternative method is being used
            $AlternativeDriveLetterFix = $true

            # Create a hashtable of partition numbers and their associated drive letters
            [System.Collections.Hashtable]$DriveLetterMappings = @{}

            # Get all partitions and filter out the ones that don't have a drive letter and then add them to the hashtable with the partition number as the key and the drive letter as the value
            foreach ($Drive in (Get-Partition | Where-Object -FilterScript { $_.DriveLetter })) {
                $DriveLetterMappings[[System.String]$Drive.PartitionNumber] = [System.String]$Drive.DriveLetter
            }
        }

        Try {
            Write-Verbose -Message 'Receive-CodeIntegrityLogs: Collecting the Code Integrity Operational logs'
            [System.Diagnostics.Eventing.Reader.EventLogRecord[]]$RawEventLogs = Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-CodeIntegrity/Operational' }
        }
        catch {
            Throw "Receive-CodeIntegrityLogs: Could not collect the Code Integrity Operational logs, the number of logs collected is $($RawEventLogs.Count)"
        }

        # A variable to store the events after filtering
        [System.Diagnostics.Eventing.Reader.EventLogRecord[]]$EventLogs = @()

        # For performance reasons, only use one pass to filter the logs based on the date and the type
        if ($Date) {
            if ($Type -eq 'Audit') {
                $EventLogs = $RawEventLogs | Where-Object -FilterScript { ($_.TimeCreated -ge $Date) -and ($_.Id -eq '3076') }
                Write-Verbose -Message "Receive-CodeIntegrityLogs: Collected $($EventLogs.Count) Audit logs from the Code Integrity Operational since $Date"
            }
            elseif ($Type -eq 'Blocked') {
                $EventLogs = $RawEventLogs | Where-Object -FilterScript { ($_.TimeCreated -ge $Date) -and ($_.Id -eq '3077') }
                Write-Verbose -Message "Receive-CodeIntegrityLogs: Collected $($EventLogs.Count) Blocked logs from the Code Integrity Operational since $Date"
            }
            else {
                $EventLogs = $RawEventLogs | Where-Object -FilterScript { $_.TimeCreated -ge $Date }
                Write-Verbose -Message "Receive-CodeIntegrityLogs: Collected $($EventLogs.Count) logs from the Code Integrity Operational since $Date"
            }
        }
        else {
            if ($Type -eq 'Audit') {
                $EventLogs = $RawEventLogs | Where-Object -FilterScript { $_.Id -eq '3076' }
                Write-Verbose -Message "Receive-CodeIntegrityLogs: Collected $($EventLogs.Count) Audit logs from the Code Integrity Operational."
            }
            elseif ($Type -eq 'Blocked') {
                $EventLogs = $RawEventLogs | Where-Object -FilterScript { $_.Id -eq '3077' }
                Write-Verbose -Message "Receive-CodeIntegrityLogs: Collected $($EventLogs.Count) Blocked logs from the Code Integrity Operational."
            }
            else {
                $EventLogs = $RawEventLogs
                Write-Verbose -Message "Receive-CodeIntegrityLogs: Collected $($EventLogs.Count) logs from the Code Integrity Operational."
            }
        }

        # Output object to return including all the logs
        [PSCustomObject[]]$Output = @()

        # Output object to return that includes only the logs of files that exist on the disk
        [PSCustomObject[]]$ExistingOutput = @()

        # Output object tp return that includes details such as hashes of files no longer on the disk
        [PSCustomObject[]]$DeletedOutput = @()

        # Output object to return that includes FilePaths of files on the disk and details of files not on the disk
        $SeparatedOutput = [PSCustomObject]@{
            AvailableFilesPaths = [System.IO.FileInfo[]]@()
            DeletedFileHashes   = [PSCustomObject[]]@()
        }
    }

    Process {

        # Loop over each event
        foreach ($Event in $EventLogs ) {

            # Convert the event to XML object
            $Xml = [System.Xml.XmlDocument]$Event.ToXml()

            # Place each event data in a hashtable and repackage it into a custom object at the end for further processing
            [PSCustomObject[]]$ProcessedEvents = $Xml.event.EventData.data | ForEach-Object -Begin { $Hash = @{} } -Process { $Hash[$_.name] = $_.'#text' } -End { [pscustomobject]$Hash }

            # Loop over each event data object
            foreach ($Log in $ProcessedEvents) {

                # Add the TimeCreated property to the $Log object
                $Log | Add-Member -NotePropertyName 'TimeCreated' -NotePropertyValue $Event.TimeCreated

                # Filter the logs based on the policy that generated them
                if (-NOT ([System.String]::IsNullOrWhiteSpace($PolicyNames))) {
                    if ($Log.PolicyName -notin $PolicyNames) {
                        continue
                    }
                }

                # Define the regex pattern for the device path
                [System.Text.RegularExpressions.Regex]$Pattern = '\\Device\\HarddiskVolume(?<HardDiskVolumeNumber>\d+)\\(?<RemainingPath>.*)$'

                # replace the device path with the drive letter if it matches the pattern
                if ($Log.'File Name' -match $Pattern) {

                    if ($AlternativeDriveLetterFix -eq $false) {

                        [System.UInt32]$HardDiskVolumeNumber = $Matches['HardDiskVolumeNumber']
                        [System.String]$RemainingPath = $Matches['RemainingPath']
                        [PSCustomObject]$GetLetter = $DriveLettersGlobalRootFix | Where-Object -FilterScript { $_.DevicePath -eq "\Device\HarddiskVolume$HardDiskVolumeNumber" }
                        [System.IO.FileInfo]$UsablePath = "$($GetLetter.DriveLetter)$RemainingPath"
                        $Log.'File Name' = $Log.'File Name' -replace $Pattern, $UsablePath
                    }
                    else {
                        $Log.'File Name' = $Log.'File Name' -replace "\\Device\\HarddiskVolume$($Matches['HardDiskVolumeNumber'])", "$($DriveLetterMappings[$Matches['HardDiskVolumeNumber']]):"
                    }
                }
                # sometimes the file name begins with System32 so we prepend the Windows directory to create a full resolvable path
                # https://learn.microsoft.com/en-us/dotnet/api/system.string.startswith
                elseif ($Log.'File Name'.StartsWith('System32', $true, [System.Globalization.CultureInfo]::InvariantCulture)) {
                    $Log.'File Name' = Join-Path -Path $Env:WinDir -ChildPath ($Log.'File Name')
                }

                # Replace these numbers in the logs with user-friendly strings that represent the signature level at which the code was verified
                $Log.'Requested Signing Level' = $ReqValSigningLevels[[System.UInt16]$Log.'Requested Signing Level']
                $Log.'Validated Signing Level' = $ReqValSigningLevels[[System.UInt16]$Log.'Validated Signing Level']

                # Replace the SI Signing Scenario numbers with a user-friendly string
                $Log.'SI Signing Scenario' = $Log.'SI Signing Scenario' -eq '0' ? 'Kernel-Mode' : 'User-Mode'

                # Process the logs if the PostProcessing parameter was used
                if ($PostProcessing) {
                    if (Test-Path -Path $Log.'File Name') {
                        $ExistingOutput += $Log
                        $SeparatedOutput.AvailableFilesPaths += $Log.'File Name'
                    }
                    # If the file is not currently on the disk, extract its hashes from the log
                    else {
                        $TempDeletedOutput = $Log | Select-Object -Property FileVersion, 'File Name', PolicyGUID, 'SHA256 Hash', 'SHA256 Flat Hash', 'SHA1 Hash', 'SHA1 Flat Hash'
                        $SeparatedOutput.DeletedFileHashes += $TempDeletedOutput
                        $DeletedOutput += $TempDeletedOutput
                    }
                }
                # If PostProcessing parameter was not used then assign the log as is to the output object
                else {
                    $Output += $Log
                }
            }
        }
    }

    End {

        if ($PostProcessing -eq 'Separate') {
            Write-Verbose -Message "Receive-CodeIntegrityLogs: Returning $($SeparatedOutput.AvailableFilesPaths.Count) Code Integrity logs for files on the disk."
            Write-Verbose -Message "Receive-CodeIntegrityLogs: Returning $($SeparatedOutput.DeletedFileHashes.Count) Code Integrity logs for files not on the disk."
            Return $SeparatedOutput
        }
        elseif ($PostProcessing -eq 'OnlyExisting') {
            Write-Verbose -Message "Receive-CodeIntegrityLogs: Returning $($ExistingOutput.Count) Code Integrity logs."
            Return $ExistingOutput
        }
        elseif ($PostProcessing -eq 'OnlyDeleted') {
            Write-Verbose -Message "Receive-CodeIntegrityLogs: Returning $($DeletedOutput.Count) Code Integrity logs."
            Return $DeletedOutput
        }
        else {
            Write-Verbose -Message "Receive-CodeIntegrityLogs: Returning $($Output.Count) Code Integrity logs."
            Return $Output
        }
    }
}
Export-ModuleMember -Function 'Receive-CodeIntegrityLogs'
