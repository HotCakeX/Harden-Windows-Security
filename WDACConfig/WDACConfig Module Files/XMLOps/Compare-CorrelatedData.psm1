Function Compare-CorrelatedData {
    <#
    .SYNOPSIS
        Finds the correlated events in the new CSV data and groups them together based on the EtwActivityId
        Ensures that each Audit or Blocked event has its correlated Signing information events grouped together as nested HashTables
    .PARAMETER OptimizedCSVData
        The CSV data to be processed, they should be the output of the Optimize-MDECSVData function
    .PARAMETER StagingArea
        The path to the directory where the debug CSV file will be saved which are the outputs of this function
    .PARAMETER Debug
        A switch parameter to enable debugging actions such as exporting the correlated event data to a JSON file
    .INPUTS
        System.Collections.Hashtable[]
    .OUTPUTS
        System.Collections.Hashtable[]
        #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable[]])]
    Param (
        [Parameter(Mandatory = $true)][System.Collections.Hashtable[]]$OptimizedCSVData,
        [Parameter(Mandatory = $true)][System.IO.DirectoryInfo]$StagingArea
    )

    Begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Detecting if Debug switch is used
        $PSBoundParameters.Debug.IsPresent ? ([System.Boolean]$Debug = $true) : ([System.Boolean]$Debug = $false) | Out-Null

        # Group the events based on the EtwActivityId, which is the unique identifier for each group of correlated events
        [Microsoft.PowerShell.Commands.GroupInfo[]]$GroupedEvents = $OptimizedCSVData | Group-Object -Property EtwActivityId

        Write-Verbose -Message "Compare-CorrelatedData: Total number of groups: $($GroupedEvents.Count)"

        # Create a collection to store the packages of logs to return at the end
        [System.Collections.Hashtable[]]$EventPackageCollections = $null
    }

    Process {

        # Loop over each group of logs
        Foreach ($RawLogGroup in $GroupedEvents) {

            # Store the group data in a HashTable array
            [System.Collections.Hashtable[]]$GroupData = $RawLogGroup.Group

            # Process Audit events for Code Integrity and AppLocker
            if (($GroupData.ActionType -contains 'AppControlCodeIntegrityPolicyAudited') -or ($GroupData.ActionType -contains 'AppControlCIScriptAudited')) {

                # Create a temporary HashTable to store the main event, its correlated events and its type
                [System.Collections.Hashtable]$TempAuditHashTable = @{
                    MainEventData        = @{}
                    CorrelatedEventsData = @{}
                    Type                 = 'Audit'
                    SignatureStatus      = ''
                }

                # Finding the main Audit event in the group
                # Only selecting the first event because when multiple Audit policies of the same type are deployed on the system, they same event is generated for each of them
                [System.Collections.Hashtable]$AuditTemp = $GroupData |
                Where-Object -FilterScript { $_['ActionType'] -in ('AppControlCodeIntegrityPolicyAudited', 'AppControlCIScriptAudited') } | Select-Object -First 1

                # Generating a unique key for the hashtable based on file's properties
                [System.String]$UniqueAuditMainEventDataKey = $AuditTemp.FileName + '|' + $AuditTemp.SHA256 + '|' + $AuditTemp.SHA1 + '|' + $AuditTemp.FileVersion

                # Adding the main event to the temporary HashTable
                if (-NOT $TempAuditHashTable['MainEventData'].Contains($UniqueAuditMainEventDataKey)) {
                    $TempAuditHashTable['MainEventData'][$UniqueAuditMainEventDataKey] = $AuditTemp
                }

                # Looping over the signer infos and adding the unique publisher/issuer pairs to the correlated events data
                foreach ($SignerInfo in ($GroupData | Where-Object -FilterScript { $_.ActionType -eq 'AppControlCodeIntegritySigningInformation' })) {

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

                # Add the temporary HashTable to the main HashTable Array
                $EventPackageCollections += $TempAuditHashTable
            }

            # Process Blocked events for Code Integrity and AppLocker
            if (($GroupData.ActionType -contains 'AppControlCodeIntegrityPolicyBlocked') -or ($GroupData.ActionType -contains 'AppControlCIScriptBlocked')) {

                # Create a temporary HashTable to store the main event, its correlated events and its type
                [System.Collections.Hashtable]$TempBlockedHashTable = @{
                    MainEventData        = @{}
                    CorrelatedEventsData = @{}
                    Type                 = 'Blocked'
                    SignatureStatus      = ''
                }

                # Finding the main block event in the group
                # Only selecting the first event because when multiple enforced policies of the same type are deployed on the system, they same event might be generated for each of them
                [System.Collections.Hashtable]$BlockedTemp = $GroupData |
                Where-Object -FilterScript { $_['ActionType'] -in ('AppControlCodeIntegrityPolicyBlocked', 'AppControlCIScriptBlocked') } | Select-Object -First 1

                # Generating a unique key for the hashtable based on file's properties
                [System.String]$UniqueBlockedMainEventDataKey = $BlockedTemp.FileName + '|' + $BlockedTemp.SHA256 + '|' + $BlockedTemp.SHA1 + '|' + $BlockedTemp.FileVersion

                # Adding the main event to the temporary HashTable
                if (-NOT $TempBlockedHashTable['MainEventData'].Contains($UniqueBlockedMainEventDataKey)) {
                    $TempBlockedHashTable['MainEventData'][$UniqueBlockedMainEventDataKey] = $BlockedTemp
                }

                # Looping over the signer infos and adding the unique publisher/issuer pairs to the correlated events data
                foreach ($SignerInfo in ($GroupData | Where-Object -FilterScript { $_.ActionType -eq 'AppControlCodeIntegritySigningInformation' })) {

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

                # Add the temporary HashTable to the main HashTable Array
                $EventPackageCollections += $TempBlockedHashTable
            }
        }
    }

    End {

        if ($Debug) {
            Write-Verbose -Message 'Compare-CorrelatedData: Debug parameter was used, exporting data to Json...'

            # Max detail
            $EventPackageCollections | ConvertTo-Json -Depth 100 | Set-Content -Path (Join-Path -Path $StagingArea -ChildPath 'Pass2.Json') -Force
        }

        Return $EventPackageCollections
    }
}
Export-ModuleMember -Function 'Compare-CorrelatedData'
