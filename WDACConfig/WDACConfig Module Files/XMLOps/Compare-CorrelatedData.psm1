Function Compare-CorrelatedData {
    <#
    .SYNOPSIS
        Finds the correlated events in the new CSV data and groups them together based on the EtwActivityId
        Ensures that each Audit or Blocked event has its correlated AppControlCodeIntegritySigningInformation events grouped together as nested properties
    .PARAMETER OptimizedCSVData
        The CSV data to be processed, they should be the output of the Optimize-MDECSVData function
    .PARAMETER StagingArea
        The path to the directory where the debug CSV file will be saved which are the outputs of this function
    .PARAMETER Debug
        A switch parameter to enable debugging actions such as exporting the correlated event data to a CSV file
    .INPUTS
        PSCustomObject[]
    .OUTPUTS
        PSCustomObject[]
        #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param (
        [Parameter(Mandatory = $true)][PSCustomObject[]]$OptimizedCSVData,
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
        [PSCustomObject[]]$EventPackageCollections = @()
    }

    Process {

        # Loop over each group of logs
        Foreach ($RawLogGroup in $GroupedEvents) {

            # Create a new array to store the group data
            [PSCustomObject[]]$GroupData = $RawLogGroup.Group

            # Process Audit events
            if (($GroupData.ActionType -contains 'AppControlCodeIntegrityPolicyAudited') -or ($GroupData.ActionType -contains 'AppControlCIScriptAudited')) {

                # Finding the main Audit event in the group
                # De-duplicating based on multiple properties
                [PSCustomObject]$AuditTemp = $GroupData |
                Where-Object -FilterScript { $_.ActionType -in ('AppControlCodeIntegrityPolicyAudited', 'AppControlCIScriptAudited') } |
                Group-Object -Property FileName, SHA256, SHA1 | ForEach-Object { $_.Group | Select-Object -First 1 }

                # Adding this warning message but later logic will be added to handle the situation
                # For now there is no case where this warning will be triggered
                if ($AuditTemp.count -gt 1) {
                    Write-Warning -Message "Multiple main audit events with different attributes were found for the same file: $($AuditTemp.FileName), It cannot be processed"
                }

                # Create a temporary object for storing the main event along with the correlated events as nested properties
                $TempAuditObject = [PSCustomObject]@{
                    CorrelatedEventsData = $GroupData | Where-Object -FilterScript { $_.ActionType -eq 'AppControlCodeIntegritySigningInformation' }
                    Type                 = 'Audit'
                }

                # Iterate through each property of the main audit event and add its properties to the temporary object
                foreach ($Property in $AuditTemp.PSObject.Properties) {
                    $TempAuditObject | Add-Member -NotePropertyName $Property.Name -NotePropertyValue $Property.Value
                }

                # Add the main event along with the correlated events to the collection
                $EventPackageCollections += $TempAuditObject
            }

            # Process Blocked events
            if (($GroupData.ActionType -contains 'AppControlCodeIntegrityPolicyBlocked') -or ($GroupData.ActionType -contains 'AppControlCIScriptBlocked')) {

                # Finding the main block event in the group
                [PSCustomObject]$BlockedTemp = $GroupData
                | Where-Object -FilterScript { $_.ActionType -in ('AppControlCodeIntegrityPolicyBlocked', 'AppControlCIScriptBlocked') } |
                Group-Object -Property FileName, SHA256, SHA1 | ForEach-Object { $_.Group | Select-Object -First 1 }

                # Adding this warning message but later logic will be added to handle the situation
                # For now there is no case where this warning will be triggered
                if ($BlockedTemp.count -gt 1) {
                    Write-Warning -Message "Multiple main blocked events with different attributes were found for the same file: $($BlockedTemp.FileName), It cannot be processed"
                }

                # Create a temporary object for storing the main block event along with the correlated events as nested properties
                $TempBlockObject = [PSCustomObject]@{
                    CorrelatedEventsData = $GroupData | Where-Object -FilterScript { $_.ActionType -eq '' }
                    Type                 = 'Blocked'
                }

                # Iterate through each property of the main block event and add its properties to the temporary object
                foreach ($Property in $BlockedTemp.PSObject.Properties) {
                    $TempBlockObject | Add-Member -NotePropertyName $Property.Name -NotePropertyValue $Property.Value
                }

                # Add the main event along with the correlated events to the collection
                $EventPackageCollections += $TempBlockObject
            }
        }
    }

    End {

        if ($Debug) {

            Write-Verbose -Message 'Compare-CorrelatedData: Debug parameter was used, exporting the new array to a CSV file...'

            # Initialize a list to keep track of all property names
            [System.String[]]$PropertyNames = @()

            # Loop through each object in the new updated CSV data to find and add any new property names to the list that are not already present
            # These are the property names from the AdditionalFields
            foreach ($Obj in $EventPackageCollections) {
                foreach ($Prop in $Obj.PSObject.Properties) {
                    if ($Prop.Name -notin $PropertyNames) {
                        $PropertyNames += $Prop.Name
                    }
                }
            }

            # Max detail - included correlated data
            $EventPackageCollections | Select-Object -Property $PropertyNames | Export-Csv -Path (Join-Path -Path $StagingArea -ChildPath 'Pass2.csv') -Force
        }

        Return $EventPackageCollections
    }
}
Export-ModuleMember -Function 'Compare-CorrelatedData'
