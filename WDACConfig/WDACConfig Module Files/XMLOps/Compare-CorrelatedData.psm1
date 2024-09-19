Function Compare-CorrelatedData {
    <#
    .SYNOPSIS
        Finds the correlated events in the new CSV data and groups them together based on the EtwActivityId
        Ensures that each Audit or Blocked event has its correlated Signing information events grouped together as nested HashTables

        The correlated data of each log is unique based on 4 main properties, Publisher TBS and name, Issuer TBS and name

        The output of this function does not contain duplicates. Neither duplicate files nor duplicate signer information for each file.

        If 2 logs for the same file exist and one of them contains the signing information while the other one doesn't, the one with signing information is kept.
    .PARAMETER OptimizedCSVData
        The CSV data to be processed, they should be the output of the Optimize-MDECSVData function
    .PARAMETER StagingArea
        The path to the directory where the debug CSV file will be saved which are the outputs of this function
    .PARAMETER Debug
        A switch parameter to enable debugging actions such as exporting the correlated event data to a JSON file
    .PARAMETER StartTime
        A DateTime object that specifies the start time of the logs to be processed. If this parameter is not specified, all logs will be processed.
    .PARAMETER PolicyNamesToFilter
        An array of strings that specifies the policy names to filter the logs by. If this parameter is not specified, all logs will be processed.
    .PARAMETER LogType
        A string that specifies the type of logs to process. The only valid values are 'Audit' and 'Blocked'
    .INPUTS
        System.Collections.Hashtable[]
        System.DateTime
        System.String[]
        System.String
    .OUTPUTS
        System.Collections.Hashtable
        #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    Param (
        [Parameter(Mandatory = $true)][System.Collections.Hashtable[]]$OptimizedCSVData,
        [Parameter(Mandatory = $true)][System.IO.DirectoryInfo]$StagingArea,
        [Parameter(Mandatory = $false)][System.DateTime]$StartTime,
        [AllowNull()]
        [Parameter(Mandatory = $false)][System.String[]]$PolicyNamesToFilter,
        [ValidateSet('Audit', 'Blocked', 'All')]
        [Parameter(Mandatory = $true)][System.String]$LogType
    )
    Begin {
        # Group the events based on the EtwActivityId, which is the unique identifier for each group of correlated events
        [Microsoft.PowerShell.Commands.GroupInfo[]]$GroupedEvents = $OptimizedCSVData | Group-Object -Property EtwActivityId

        [WDACConfig.Logger]::Write("Compare-CorrelatedData: Total number of groups: $($GroupedEvents.Count)")

        # Create a collection to store the packages of logs to return at the end
        [System.Collections.Hashtable]$EventPackageCollections = @{}
    }

    Process {

        # Loop over each group of logs
        Foreach ($RawLogGroup in $GroupedEvents) {

            # Store the group data in a HashTable array
            [System.Collections.Hashtable[]]$GroupData = $RawLogGroup.Group

            if ($StartTime) {
                try {
                    # Try to prase the TimeStamp string as DateTime type
                    [System.DateTime]$CurrentEventTimeStamp = [System.DateTime]::Parse((($GroupData.Timestamp) | Select-Object -First 1))

                    # If the current log's TimeStamp is older than the time frame specified by the user then skip this iteration/log completely
                    if ($CurrentEventTimeStamp -lt $StartTime ) {
                        Continue
                    }
                }
                Catch {
                    [WDACConfig.Logger]::Write("Event Timestamp for the file '$($GroupData.FileName)' was invalid")
                }
            }

            # Detect the Audit events only if the LogType parameter is set to 'Audit'
            if ($LogType -in 'Audit', 'All') {

                # Process Audit events for Code Integrity and AppLocker
                if (($GroupData.ActionType -contains 'AppControlCodeIntegrityPolicyAudited') -or ($GroupData.ActionType -contains 'AppControlCIScriptAudited')) {

                    # Create a temporary HashTable to store the main event, its correlated events and its type
                    [System.Collections.Hashtable]$TempAuditHashTable = @{
                        CorrelatedEventsData = @{}
                        Type                 = 'Audit'
                        SignatureStatus      = ''
                    }

                    # Finding the main Audit event in the group
                    # Only selecting the first event because when multiple Audit policies of the same type are deployed on the system, they same event is generated for each of them
                    [System.Collections.Hashtable]$AuditTemp = $GroupData |
                    Where-Object -FilterScript { $_['ActionType'] -in ('AppControlCodeIntegrityPolicyAudited', 'AppControlCIScriptAudited') } | Select-Object -First 1

                    # If the user provided policy names to filter the logs by
                    if ($null -ne $PolicyNamesToFilter) {
                        # Skip this iteration if the policy name of the current log is not in the list of policy names to filter by
                        if ($AuditTemp.PolicyName -notin $PolicyNamesToFilter) {
                            Continue
                        }
                    }

                    # Generating a unique key for the hashtable based on file's properties
                    [System.String]$UniqueAuditMainEventDataKey = $AuditTemp.FileName + '|' + $AuditTemp.SHA256 + '|' + $AuditTemp.SHA1 + '|' + $AuditTemp.FileVersion

                    # Adding the main event to the temporary HashTable, each key/value pair
                    foreach ($Data in $AuditTemp.GetEnumerator()) {
                        $TempAuditHashTable[$Data.Key] = $Data.Value
                    }

                    # Looping over the signer infos and adding the unique publisher/issuer pairs to the correlated events data
                    foreach ($SignerInfo in ($GroupData | Where-Object -FilterScript { $_.ActionType -eq 'AppControlCodeIntegritySigningInformation' })) {

                        # If the PublisherTBSHash or IssuerTBSHash is null, skip this iteration, usually in these situations the Issuer name and Publisher names are set to 'unknown'
                        if (($null -eq $SignerInfo.PublisherTBSHash) -or ($null -eq $SignerInfo.IssuerTBSHash)) {
                            Continue
                        }

                        [System.String]$UniqueAuditSignerKey = $SignerInfo.PublisherTBSHash + '|' +
                        $SignerInfo.PublisherName + '|' +
                        $SignerInfo.IssuerName + '|' +
                        $SignerInfo.IssuerTBSHash

                        if (-NOT $TempAuditHashTable['CorrelatedEventsData'].Contains($UniqueAuditSignerKey)) {
                            $TempAuditHashTable['CorrelatedEventsData'][$UniqueAuditSignerKey] = $SignerInfo
                        }
                    }

                    # Determining whether this log package is signed or unsigned
                    $TempAuditHashTable['SignatureStatus'] = $TempAuditHashTable.CorrelatedEventsData.Count -eq 0 ? 'Unsigned' : 'Signed'

                    # Check see if the main hashtable already contains the same file (key)
                    if ($EventPackageCollections.ContainsKey($UniqueAuditMainEventDataKey)) {

                        # If it does, check if the current log is signed and the main log is unsigned
                        if (($EventPackageCollections[$UniqueAuditMainEventDataKey]['SignatureStatus'] -eq 'Unsigned') -and ($TempAuditHashTable['SignatureStatus'] -eq 'Signed')) {

                            [WDACConfig.Logger]::Write("The unsigned log of the file $($TempAuditHashTable['FileName']) is being replaced with its signed log.")

                            # Remove the Unsigned log from the main HashTable
                            $EventPackageCollections.Remove($UniqueAuditMainEventDataKey)

                            # Add the current Audit event with a unique identifiable key to the main HashTable
                            # This way we are replacing the Unsigned log with the Signed log that has more data, for the same file, providing the ability to create signature based rules for that file instead of hash based rule
                            $EventPackageCollections[$UniqueAuditMainEventDataKey] += $TempAuditHashTable
                        }
                    }
                    else {
                        # Add the current Audit event with a unique identifiable key to the main HashTable
                        $EventPackageCollections[$UniqueAuditMainEventDataKey] += $TempAuditHashTable
                    }
                }
            }

            # Detect the blocked events only if the LogType parameter is set to 'Blocked'
            if ($LogType -in 'Blocked', 'All') {

                # Process Blocked events for Code Integrity and AppLocker
                if (($GroupData.ActionType -contains 'AppControlCodeIntegrityPolicyBlocked') -or ($GroupData.ActionType -contains 'AppControlCIScriptBlocked')) {

                    # Create a temporary HashTable to store the main event, its correlated events and its type
                    [System.Collections.Hashtable]$TempBlockedHashTable = @{
                        CorrelatedEventsData = @{}
                        Type                 = 'Blocked'
                        SignatureStatus      = ''
                    }

                    # Finding the main block event in the group
                    # Only selecting the first event because when multiple enforced policies of the same type are deployed on the system, they same event might be generated for each of them
                    [System.Collections.Hashtable]$BlockedTemp = $GroupData |
                    Where-Object -FilterScript { $_['ActionType'] -in ('AppControlCodeIntegrityPolicyBlocked', 'AppControlCIScriptBlocked') } | Select-Object -First 1

                    # If the user provided policy names to filter the logs by
                    if ($null -ne $PolicyNamesToFilter) {
                        # Skip this iteration if the policy name of the current log is not in the list of policy names to filter by
                        if ($BlockedTemp.PolicyName -notin $PolicyNamesToFilter) {
                            Continue
                        }
                    }

                    # Generating a unique key for the hashtable based on file's properties
                    [System.String]$UniqueBlockedMainEventDataKey = $BlockedTemp.FileName + '|' + $BlockedTemp.SHA256 + '|' + $BlockedTemp.SHA1 + '|' + $BlockedTemp.FileVersion

                    # Adding the main event to the temporary HashTable, each key/value pair
                    foreach ($Data in $BlockedTemp.GetEnumerator()) {
                        $TempBlockedHashTable[$Data.Key] = $Data.Value
                    }

                    # Looping over the signer infos and adding the unique publisher/issuer pairs to the correlated events data
                    foreach ($SignerInfo in ($GroupData | Where-Object -FilterScript { $_.ActionType -eq 'AppControlCodeIntegritySigningInformation' })) {

                        # If the PublisherTBSHash or IssuerTBSHash is null, skip this iteration, usually in these situations the Issuer name and Publisher names are set to 'unknown'
                        if (($null -eq $SignerInfo.PublisherTBSHash) -or ($null -eq $SignerInfo.IssuerTBSHash)) {
                            Continue
                        }

                        [System.String]$UniqueBlockedSignerKey = $SignerInfo.PublisherTBSHash + '|' +
                        $SignerInfo.PublisherName + '|' +
                        $SignerInfo.IssuerName + '|' +
                        $SignerInfo.IssuerTBSHash

                        if (-NOT $TempBlockedHashTable['CorrelatedEventsData'].Contains($UniqueBlockedSignerKey)) {
                            $TempBlockedHashTable['CorrelatedEventsData'][$UniqueBlockedSignerKey] = $SignerInfo
                        }
                    }

                    # Determining whether this log package is signed or unsigned
                    $TempBlockedHashTable['SignatureStatus'] = $TempBlockedHashTable.CorrelatedEventsData.Count -eq 0 ? 'Unsigned' : 'Signed'

                    # Check see if the main hashtable already contains the same file (key)
                    if ($EventPackageCollections.ContainsKey($UniqueBlockedMainEventDataKey)) {

                        # If it does, check if the current log is signed and the main log is unsigned
                        if (($EventPackageCollections[$UniqueBlockedMainEventDataKey]['SignatureStatus'] -eq 'Unsigned') -and ($TempBlockedHashTable['SignatureStatus'] -eq 'Signed')) {

                            [WDACConfig.Logger]::Write("The unsigned log of the file $($TempBlockedHashTable['FileName']) is being replaced with its signed log.")

                            # Remove the Unsigned log from the main HashTable
                            $EventPackageCollections.Remove($UniqueBlockedMainEventDataKey)

                            # Add the current Audit event with a unique identifiable key to the main HashTable
                            # This way we are replacing the Unsigned log with the Signed log that has more data, for the same file, providing the ability to create signature based rules for that file instead of hash based rule
                            $EventPackageCollections[$UniqueBlockedMainEventDataKey] += $TempBlockedHashTable
                        }
                    }
                    else {
                        # Add the current Audit event with a unique identifiable key to the main HashTable
                        $EventPackageCollections[$UniqueBlockedMainEventDataKey] += $TempBlockedHashTable
                    }
                }
            }
        }
    }

    End {

        if ([WDACConfig.GlobalVars]::DebugPreference) {
            [WDACConfig.Logger]::Write('Compare-CorrelatedData: Debug parameter was used, exporting data to Json...')

            # Outputs the entire data to a JSON file for debugging purposes with max details
            $EventPackageCollections | ConvertTo-Json -Depth 100 | Set-Content -Path (Join-Path -Path $StagingArea -ChildPath 'Pass2.Json') -Force
        }

        Return $EventPackageCollections
    }
}
Export-ModuleMember -Function 'Compare-CorrelatedData'
