Function Receive-CodeIntegrityLogs {
    <#
    .SYNOPSIS
        A high-performance function that:
        Retrieves the Code Integrity Operational logs and App Locker logs
        Fixes the paths to the files that are being logged
        Separates events based on their type: Audit or Blocked
        Separates events based on their file paths: existing or deleted
        For Code Integrity logs: Finds correlated events with ID 3089 and adds them to the main event (IDs 3076 and 3077)
        For App Locker logs: Finds correlated events with ID 8038 and adds them to the main event (IDs 8028 and 8029)
        Replaces many numbers in the logs with user-friendly strings
        Performs precise de-duplication of the logs so that the output will always have unique logs
        Then processes the output based on different criteria
    .PARAMETER Date
        The date from which the logs should be collected. If not specified, all logs will be collected.
    .PARAMETER Type
        The type of logs to be collected. Audit, Blocked, All. The default value is 'All'
    .PARAMETER PostProcessing
        How to process the output for different scenarios
        OnlyExisting: Returns only the logs of files that exist on the disk
    .PARAMETER PolicyNames
        The names of the policies to filter the logs by
    .PARAMETER Category
        The category of logs to be collected. Code Integrity, AppLocker, or All. The default value is 'All'
    .PARAMETER LogSource
        The source of the logs. EVTXFiles or LocalLogs. The default value is 'LocalLogs'
    .PARAMETER EVTXFilePaths
        The file paths of the EVTX files to collect the logs from. It accepts an array of FileInfo objects
    .INPUTS
        System.String
        System.DateTime
        System.String[]
        System.IO.FileInfo[]
    .OUTPUTS
        System.Collections.Hashtable
    .NOTES
        The extra functionalities for post processing such as Separated output and Deleted outputs have been commented
        out because they are not used anymore by the module.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [System.DateTime]$Date,

        [ValidateSet('Audit', 'Blocked', 'All')]
        [Parameter(Mandatory = $false)]
        [System.String]$Type = 'All',

        [ValidateSet('OnlyExisting')]
        [parameter(mandatory = $false)]
        [System.String]$PostProcessing,

        [AllowEmptyString()]
        [AllowNull()]
        [parameter(mandatory = $false)]
        [System.String[]]$PolicyNames,

        [ValidateSet('CodeIntegrity', 'AppLocker', 'All')]
        [Parameter(mandatory = $false)][System.String]$Category = 'All',

        [ValidateSet('EVTXFiles', 'LocalLogs')]
        [Parameter(Mandatory = $false)][System.String]$LogSource = 'LocalLogs',

        [Parameter(Mandatory = $false)][System.IO.FileInfo[]]$EVTXFilePaths
    )
    Begin {
        Function Test-NotEmpty ($Data) {
            <#
            .SYNOPSIS
                Tests if the data is not null, empty, or whitespace
            #>
            if ((-NOT ([System.String]::IsNullOrWhiteSpace($Data)))) {
                if ($Data.count -ge 1) {
                    return $true
                }
                else {
                    return $false
                }
            }
            else {
                return $false
            }
        }

        #Region Global Root Drive Fix
        Try {
            # Set a flag indicating that the alternative drive letter mapping method is not necessary unless the primary method fails
            [System.Boolean]$AlternativeDriveLetterFix = $false

            # Get the local disks mappings
            [WDACConfig.DriveLetterMapper+DriveMapping[]]$DriveLettersGlobalRootFix = [WDACConfig.DriveLetterMapper]::GetGlobalRootDrives()
        }
        catch {
            [WDACConfig.Logger]::Write('Receive-CodeIntegrityLogs: Could not get the drive mappings from the system using the primary method, trying the alternative method now')

            # Set the flag to true indicating the alternative method is being used
            $AlternativeDriveLetterFix = $true
        }

        # Create a hashtable of partition numbers and their associated drive letters
        [System.Collections.Hashtable]$DriveLetterMappings = @{}

        # Get all partitions and filter out the ones that don't have a drive letter and then add them to the hashtable with the partition number as the key and the drive letter as the value
        foreach ($Drive in (Get-Partition | Where-Object -FilterScript { $_.DriveLetter })) {
            $DriveLetterMappings[[System.String]$Drive.PartitionNumber] = [System.String]$Drive.DriveLetter
        }
        #Endregion Global Root Drive Fix

        if ($Category -in 'All', 'CodeIntegrity') {
            Try {
                [WDACConfig.Logger]::Write('Receive-CodeIntegrityLogs: Collecting the Code Integrity Operational logs')
                switch ($LogSource) {
                    'EVTXFiles' {
                        # Get all of the Code Integrity logs from the specified EVTX files
                        [System.Diagnostics.Eventing.Reader.EventLogRecord[]]$CiRawEventLogs = Get-WinEvent -FilterHashtable @{Path = $EVTXFilePaths; ID = '3076', '3077', '3089' }
                    }
                    'LocalLogs' {
                        # Get all of the Code Integrity logs from the local machine
                        [System.Diagnostics.Eventing.Reader.EventLogRecord[]]$CiRawEventLogs = Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-CodeIntegrity/Operational' }
                    }
                }
            }
            catch {
                [WDACConfig.Logger]::Write("Receive-CodeIntegrityLogs: Could not collect the Code Integrity Operational logs, the number of logs collected is $($CiRawEventLogs.Count)")
            }

            [Microsoft.PowerShell.Commands.GroupInfo[]]$CiGroupedEvents = $CiRawEventLogs | Group-Object -Property ActivityId
            [WDACConfig.Logger]::Write("Receive-CodeIntegrityLogs: Grouped the Code Integrity logs by ActivityId. The total number of groups is $($CiGroupedEvents.Count) and the total number of logs in the groups is $($CiGroupedEvents.Group.Count)")
        }
        else {
            [WDACConfig.Logger]::Write('Receive-CodeIntegrityLogs: Skipping the collection of the Code Integrity logs')
        }

        if ($Category -in 'All', 'AppLocker') {
            Try {
                [WDACConfig.Logger]::Write('Receive-CodeIntegrityLogs: Collecting the AppLocker logs')
                switch ($LogSource) {
                    'EVTXFiles' {
                        # Get all of the AppLocker logs from the specified EVTX files
                        [System.Diagnostics.Eventing.Reader.EventLogRecord[]]$AppLockerRawEventLogs = Get-WinEvent -FilterHashtable @{Path = $EVTXFilePaths; ID = '8028', '8029', '8038' }
                    }
                    'LocalLogs' {
                        # Get all of the AppLocker logs from the local machine
                        [System.Diagnostics.Eventing.Reader.EventLogRecord[]]$AppLockerRawEventLogs = Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-AppLocker/MSI and Script' }
                    }
                }
            }
            catch {
                [WDACConfig.Logger]::Write("Receive-CodeIntegrityLogs: Could not collect the AppLocker logs, the number of logs collected is $($AppLockerRawEventLogs.Count)")
            }

            [Microsoft.PowerShell.Commands.GroupInfo[]]$AppLockerGroupedEvents = $AppLockerRawEventLogs | Group-Object -Property ActivityId
            [WDACConfig.Logger]::Write("Receive-CodeIntegrityLogs: Grouped the AppLocker logs by ActivityId. The total number of groups is $($AppLockerGroupedEvents.Count) and the total number of logs in the groups is $($AppLockerGroupedEvents.Group.Count)")
        }
        else {
            [WDACConfig.Logger]::Write('Receive-CodeIntegrityLogs: Skipping the collection of the AppLocker logs')
        }

        # Add Code Integrity and AppLocker logs to a single array based on the selected category
        $AccumulatedGroupedEvents = ($Category -eq 'All') ? ($CiGroupedEvents + $AppLockerGroupedEvents) : (($Category -eq 'CodeIntegrity') ? $CiGroupedEvents : $AppLockerGroupedEvents)

        # Create a list of HashTables to store the event log data
        $EventPackageCollection = New-Object -TypeName 'System.Collections.Generic.List[System.Collections.Hashtable]'

        # Loop over each group of logs to identify Audit/Block events and also gather correlated events of each main event
        Foreach ($RawLogGroup in $AccumulatedGroupedEvents) {

            # Process Audit events
            if (($RawLogGroup.Group.Id -contains '3076') -or ($RawLogGroup.Group.Id -contains '8028')) {

                # Finding the main event in the group - If there are more than 1, selecting the first one because that means the same event was triggered by multiple deployed policies
                [System.Diagnostics.Eventing.Reader.EventLogRecord]$AuditTemp = $RawLogGroup.Group.Where({ $_.Id -in '3076', '8028' }) | Select-Object -First 1

                # If the main event is older than the specified date, skip it
                if ($null -ne $Date -and $AuditTemp.TimeCreated -lt $Date) {
                    continue
                }

                # Create a local hashtable to store the main event and the correlated events
                [System.Collections.Hashtable]$LocalAuditEventPackageCollections = @{}

                $LocalAuditEventPackageCollections['MainEventData'] = $AuditTemp
                $LocalAuditEventPackageCollections['CorrelatedEventsData'] = $RawLogGroup.Group.Where({ $_.Id -in '3089', '8038' })
                $LocalAuditEventPackageCollections['Type'] = 'Audit'

                # Add the main event along with the correlated events as a nested hashtable to the list
                $EventPackageCollection.Add($LocalAuditEventPackageCollections)
            }

            # Process Blocked events
            if (($RawLogGroup.Group.Id -contains '3077') -or ($RawLogGroup.Group.Id -contains '8029')) {

                # Finding the main event in the group - If there are more than 1, selecting the first one because that means the same event was triggered by multiple deployed policies
                [System.Diagnostics.Eventing.Reader.EventLogRecord]$BlockedTemp = $RawLogGroup.Group.Where({ $_.Id -in '3077', '8029' }) | Select-Object -First 1

                # If the main event is older than the specified date, skip it
                if ($null -ne $Date -and $BlockedTemp.TimeCreated -lt $Date) {
                    continue
                }

                # Create a local hashtable to store the main event and the correlated events
                [System.Collections.Hashtable]$LocalBlockedEventPackageCollections = @{}

                $LocalBlockedEventPackageCollections['MainEventData'] = $BlockedTemp
                $LocalBlockedEventPackageCollections['CorrelatedEventsData'] = $RawLogGroup.Group.Where({ $_.Id -in '3089', '8038' })
                $LocalBlockedEventPackageCollections['Type'] = 'Blocked'

                # Add the main event along with the correlated events as a nested hashtable to the list
                $EventPackageCollection.Add($LocalBlockedEventPackageCollections)
            }
        }

        # Hashtable that contains the entire output
        [System.Collections.Hashtable]$Output = @{
            # all the logs without post-processing
            All      = @{
                Audit   = @{}
                Blocked = @{}
            }
            # only the logs of files that exist on the disk
            Existing = @{
                Audit   = @{}
                Blocked = @{}
            }
        }

        # Making the hashtable thread-safe by synchronizing it and allowing the Foreach-Object -Parallel to write back data to it safely in real time with $Using scope modifier
        # ForEach-Object -Parallel is Thread Session so the scriptblock inside of it can modify parent scope variables since they are references instead of independent copies
        # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_variables#other-situations-where-the-using-scope-modifier-is-needed
        # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_scopes#the-using-scope-modifier
        $Output = [System.Collections.Hashtable]::Synchronized($Output)
    }

    Process {

        if ($EventPackageCollection.count -eq 0) {
            [WDACConfig.Logger]::Write('Receive-CodeIntegrityLogs: No logs were collected')
            return
        }

        # Split the main hashtable into 5 arrays to run the main loop in parallel
        # https://learn.microsoft.com/en-us/dotnet/api/system.linq.enumerable.chunk
        $SplitArrays = [System.Linq.Enumerable]::Chunk($EventPackageCollection, [System.Math]::Ceiling($EventPackageCollection.Count / 5))

        # Running the main loop in parallel
        $SplitArrays | ForEach-Object -Parallel {

            # Making the parent scope variables available in the parallel child scope as references

            # Only variable modified from within the thread session
            $Output = $using:Output

            # Variables that are not modified from within the thread session
            $DriveLettersGlobalRootFix = $using:DriveLettersGlobalRootFix
            $AlternativeDriveLetterFix = $using:AlternativeDriveLetterFix
            $DriveLetterMappings = $using:DriveLetterMappings
            $LogSource = $using:LogSource

            # Loop over each event package in the collection
            foreach ($EventPackage in $_.GetEnumerator()) {

                # Extract the main event data
                [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event = $EventPackage.MainEventData

                # Convert the main event data to XML object
                $Xml = [System.Xml.XmlDocument]$Event.ToXml()

                if ($null -eq $Xml.event.EventData.data) {
                    [WDACConfig.Logger]::Write("Receive-CodeIntegrityLogs: Skipping Main event data for: $($Log['File Name'])")
                    continue
                }

                # Place each main event data in a hashtable
                [System.Collections.Hashtable]$Log = @{}
                foreach ($Item in $Xml.event.EventData.data) {
                    $Log[$Item.Name] = $Item.'#text'
                }

                # Add the TimeCreated property to the $Log hashtable
                $Log['TimeCreated'] = $Event.TimeCreated
                # Add the ActivityId property to the $Log hashtable
                $Log['ActivityId'] = $Event.ActivityId
                # Add the UserId property to the $Log hashtable
                $Log['UserId'] = $Event.UserId
                # Add the ProviderName property to the $Log hashtable
                $Log['ProviderName'] = $Event.ProviderName

                # Filter the logs based on the policy that generated them
                if (-NOT ([System.String]::IsNullOrWhiteSpace($PolicyNames))) {
                    if ($Log.PolicyName -notin $PolicyNames) {
                        continue
                    }
                }

                # Define the regex pattern for the device path
                [System.Text.RegularExpressions.Regex]$Pattern = '\\Device\\HarddiskVolume(?<HardDiskVolumeNumber>\d+)\\(?<RemainingPath>.*)$'

                # These are the properties that are different in AppLocker so they need to be manually set to be compliant with the expected output of this function
                if ($Log['ProviderName'] -eq 'Microsoft-Windows-AppLocker') {

                    # Replace File Name property with the FilePath property and then remove the FilePath property
                    $Log['File Name'] = $Log['FilePath']
                    $Log.Remove('FilePath')

                    $Log['SHA256 Hash'] = $Log['Sha256Hash']
                    $Log.Remove('Sha256Hash')

                    $Log['SHA1 Hash'] = $Log['Sha1Hash']
                    $Log.Remove('Sha1Hash')
                }

                # replace the device path with the drive letter if it matches the pattern
                # Only if the log source is local logs
                if (($LogSource -eq 'LocalLogs') -and ($Log['File Name'] -match $Pattern)) {

                    # Use the primary method to fix the drive letter mappings
                    if ($AlternativeDriveLetterFix -eq $false) {

                        [System.UInt32]$HardDiskVolumeNumber = $Matches['HardDiskVolumeNumber']
                        [System.String]$RemainingPath = $Matches['RemainingPath']
                        [WDACConfig.DriveLetterMapper+DriveMapping]$GetLetter = $DriveLettersGlobalRootFix | Where-Object -FilterScript { $_.DevicePath -eq "\Device\HarddiskVolume$HardDiskVolumeNumber" }
                        [System.IO.FileInfo]$UsablePath = "$($GetLetter.DriveLetter)$RemainingPath"
                        $Log['File Name'] = $Log['File Name'] -replace $Pattern, $UsablePath
                    }
                    # Use the alternative method to fix the drive letter mappings
                    else {
                        $Log['File Name'] = $Log['File Name'] -replace "\\Device\\HarddiskVolume$($Matches['HardDiskVolumeNumber'])", "$($DriveLetterMappings[$Matches['HardDiskVolumeNumber']]):"
                    }
                }
                # sometimes the file name begins with System32 so we prepend the Windows directory to create a full resolvable path
                # https://learn.microsoft.com/en-us/dotnet/api/system.string.startswith
                elseif ($Log['File Name'].StartsWith('System32', $true, [System.Globalization.CultureInfo]::InvariantCulture)) {
                    $Log['File Name'] = Join-Path -Path $Env:WinDir -ChildPath ($Log['File Name'])
                }

                # Replace these numbers in the logs with user-friendly strings that represent the signature level at which the code was verified
                $Log['Requested Signing Level'] = [WDACConfig.CILogIntel]::ReqValSigningLevels[[System.UInt16]$Log['Requested Signing Level']]
                $Log['Validated Signing Level'] = [WDACConfig.CILogIntel]::ReqValSigningLevels[[System.UInt16]$Log['Validated Signing Level']]

                # Replace the SI Signing Scenario numbers with a user-friendly string
                $Log['SI Signing Scenario'] = $Log['SI Signing Scenario'] -eq '0' ? 'Kernel-Mode' : 'User-Mode'

                # if the log source is local logs
                if ($LogSource -eq 'LocalLogs') {

                    # Translate the SID to a UserName if it's not null
                    if ($null -ne $Log.UserId) {
                        Try {
                            [System.Security.Principal.SecurityIdentifier]$ObjSID = New-Object -TypeName System.Security.Principal.SecurityIdentifier($Log.UserId)
                            $Log.UserId = [System.String]($ObjSID.Translate([System.Security.Principal.NTAccount])).Value
                        }
                        Catch {
                            [WDACConfig.Logger]::Write("Receive-CodeIntegrityLogs: Could not translate the SID $($Log.UserId) to a username for the Activity ID $($Log['ActivityId']) for the file $($Log['File Name'])")
                        }
                    }
                    else {
                        [WDACConfig.Logger]::Write("Receive-CodeIntegrityLogs: The UserId property is null for the Activity ID $($Log['ActivityId']) for the file $($Log['File Name'])")
                    }
                }

                # If there are correlated events, then process them
                if ($null -ne $EventPackage.CorrelatedEventsData) {

                    # A hashtable for storing the correlated logs
                    [System.Collections.Hashtable]$CorrelatedLogs = @{}

                    # Store the unique publisher name in HashSet
                    $Publishers = [System.Collections.Generic.HashSet[System.String]]@()

                    # Looping over each correlated event data
                    # There are more than 1 if the file has multiple signers/publishers
                    foreach ($CorrelatedEvent in $EventPackage.CorrelatedEventsData) {

                        # Convert the main event data to XML object
                        $XmlCorrelated = [System.Xml.XmlDocument]$CorrelatedEvent.ToXml()

                        if ($null -eq $XmlCorrelated.event.EventData.data) {
                            [WDACConfig.Logger]::Write("Receive-CodeIntegrityLogs: Skipping Publisher check for: '$($Log['File Name'])' due to missing correlated event data")
                            continue
                        }

                        # Place each event data in a hashtable
                        [System.Collections.Hashtable]$CorrelatedLog = @{}
                        foreach ($Item in $XmlCorrelated.event.EventData.data) {
                            $CorrelatedLog[$Item.Name] = $Item.'#text'
                        }

                        # Skip signers that don't have PublisherTBSHash (aka LeafCertificate TBS Hash)
                        # They have "Unknown" as their IssuerName and PublisherName too
                        if ($null -eq $CorrelatedLog.PublisherTBSHash) {
                            Continue
                        }

                        # Replace the properties with their user-friendly strings
                        $CorrelatedLog.SignatureType = [WDACConfig.CILogIntel]::SignatureTypeTable[[System.UInt16]$CorrelatedLog.SignatureType]
                        $CorrelatedLog.ValidatedSigningLevel = [WDACConfig.CILogIntel]::ReqValSigningLevels[[System.UInt16]$CorrelatedLog.ValidatedSigningLevel]
                        $CorrelatedLog.VerificationError = [WDACConfig.CILogIntel]::VerificationErrorTable[[System.UInt16]$CorrelatedLog.VerificationError]

                        # Create a unique key for each Publisher
                        [System.String]$PublisherKey = $CorrelatedLog.PublisherTBSHash + '|' +
                        $CorrelatedLog.PublisherName + '|' +
                        $CorrelatedLog.IssuerTBSHash + '|' +
                        $CorrelatedLog.IssuerName

                        # Add the Correlated Log to the array of Correlated Logs if it doesn't already exist there
                        if (-NOT $CorrelatedLogs.ContainsKey($PublisherKey)) {
                            $CorrelatedLogs[$PublisherKey] = $CorrelatedLog
                        }

                        # Add the unique publisher name to the array of Publishers if it doesn't already exist there
                        if (-NOT $Publishers.Contains($CorrelatedLog.PublisherName)) {
                            [System.Void]$Publishers.Add($CorrelatedLog.PublisherName)
                        }
                    }

                    # This creates too much noise in the logs and verbose messages, either make it more useful or keep it commented
                    # [WDACConfig.Logger]::Write("Receive-CodeIntegrityLogs: The number of unique publishers in the correlated events is $($Publishers.Count)")

                    $Log['Publishers'] = $Publishers

                    # Add a new property to detect whether this log is signed or not
                    # Primarily used by the BuildSignerAndHashObjects Method and for Evtx log sources
                    $Log['SignatureStatus'] = $Publishers.Count -ge 1 ? 'Signed' : 'Unsigned'

                    # This creates too much noise in the logs and verbose messages, either make it more useful or keep it commented
                    # [WDACConfig.Logger]::Write("Receive-CodeIntegrityLogs: The number of correlated events is $($CorrelatedLogs.Count)")
                    $Log['SignerInfo'] = $CorrelatedLogs
                }

                # Add the Type property to the log object
                $Log['Type'] = $EventPackage.Type

                #Region Post-processing for the logs

                # Creating a unique string key for the current log
                # The key ending up being too long doesn't matter and doesn't affect the performance
                # Since all keys are hashed in a hashtable
                [System.String]$UniqueLogKey = $Log['File Name'] + '|' +
                $Log.ProductName + '|' +
                $Log.FileVersion + '|' +
                $Log.OriginalFileName + '|' +
                $Log.FileDescription + '|' +
                $Log.InternalName + '|' +
                $Log.PackageFamilyName + '|' +
                $Log.Publishers + '|' +
                $Log['SHA256 Hash'] + '|' +
                $Log['SHA256 Flat Hash']

                try {

                    # Using the SyncRoot property to lock the $Output hashtable during the check-and-add sequence, making it atomic and thread-safe
                    # This ensures that only one thread at a time can execute the code within the try block, thus preventing race conditions
                    [System.Threading.Monitor]::Enter($using:Output.SyncRoot)

                    if ($Log.Type -eq 'Audit') {

                        # Add the log to the output hashtable if it has Audit type and doesn't already exist there
                        if (-NOT $Output.All.Audit.ContainsKey($UniqueLogKey)) {
                            $Output.All.Audit[$UniqueLogKey] = $Log
                        }

                        # If the file the log is referring to is currently on the disk
                        if ([System.IO.File]::Exists($Log['File Name'])) {

                            if (-NOT $Output.Existing.Audit.ContainsKey($UniqueLogKey)) {
                                $Output.Existing.Audit[$UniqueLogKey] = $Log
                            }
                        }
                    }

                    elseif ($Log.Type -eq 'Blocked') {

                        # Add the log to the output hashtable if it has Blocked type and doesn't already exist there
                        if (-NOT $Output.All.Blocked.ContainsKey($UniqueLogKey)) {
                            $Output.All.Blocked[$UniqueLogKey] = $Log
                        }

                        # If the file the log is referring to is currently on the disk
                        if ([System.IO.File]::Exists($Log['File Name'])) {

                            if (-NOT $Output.Existing.Blocked.ContainsKey($UniqueLogKey)) {
                                $Output.Existing.Blocked[$UniqueLogKey] = $Log
                            }
                        }
                    }
                    #Endregion Post-processing for the logs
                }
                catch {
                    Throw $_
                }
                # Always ensures the lock is released
                finally {
                    [System.Threading.Monitor]::Exit($using:Output.SyncRoot)
                }
            }
        } -ThrottleLimit 5
    }

    End {
        # Assigning null to the variables that are empty since users of this function need null values for empty variables
        if (-NOT (Test-NotEmpty -Data $Output.All.Audit)) { $Output.All.Audit = $null }
        if (-NOT (Test-NotEmpty -Data $Output.All.Blocked)) { $Output.All.Blocked = $null }
        if (-NOT (Test-NotEmpty -Data $Output.Existing.Audit)) { $Output.Existing.Audit = $null }
        if (-NOT (Test-NotEmpty -Data $Output.Existing.Blocked)) { $Output.Existing.Blocked = $null }

        Switch ($PostProcessing) {
            'OnlyExisting' {
                Switch ($Type) {
                    'Audit' {
                        [WDACConfig.Logger]::Write("Receive-CodeIntegrityLogs: Returning $($Output.Existing.Audit.Values.Count) Audit Code Integrity logs for files on the disk.")
                        Return $Output.Existing.Audit.Values
                    }
                    'Blocked' {
                        [WDACConfig.Logger]::Write("Receive-CodeIntegrityLogs: Returning $($Output.Existing.Blocked.Values.Count) Blocked Code Integrity logs for files on the disk.")
                        Return $Output.Existing.Blocked.Values
                    }
                    'All' {
                        $AllOutput = $Output.Existing.Blocked.Values + $Output.Existing.Audit.Values
                        [WDACConfig.Logger]::Write("Receive-CodeIntegrityLogs: Returning $($AllOutput.Count) Code Integrity logs for files on the disk.")
                        Return $AllOutput
                    }
                }
            }
            Default {
                Switch ($Type) {
                    'Audit' {
                        [WDACConfig.Logger]::Write("Receive-CodeIntegrityLogs: Returning $($Output.All.Audit.Values.Count) Audit Code Integrity logs.")
                        Return $Output.All.Audit.Values
                    }
                    'Blocked' {
                        [WDACConfig.Logger]::Write("Receive-CodeIntegrityLogs: Returning $($Output.All.Blocked.Values.Count) Blocked Code Integrity logs.")
                        Return $Output.All.Blocked.Values
                    }
                    'All' {
                        $AllOutput = $Output.All.Audit.Values + $Output.All.Blocked.Values
                        [WDACConfig.Logger]::Write("Receive-CodeIntegrityLogs: Returning $($AllOutput.Count) Code Integrity logs.")
                        Return $AllOutput
                    }
                }
            }
        }
    }
}
Export-ModuleMember -Function 'Receive-CodeIntegrityLogs'
