Function Optimize-MDECSVData {
    <#
        .SYNOPSIS
            Optimizes the MDE CSV data by adding the nested properties in the "AdditionalFields" property to the parent record as first-level properties
        .DESCRIPTION
            The function runs each CSV file in parallel for fast processing based on the number of CPU cores available
        .PARAMETER CSVPaths
            The path to the CSV file containing the Microsoft Defender for Endpoint Advanced Hunting data
        .PARAMETER Debug
            A switch parameter to enable debugging actions such as exporting the new array to a CSV file
        .PARAMETER StagingArea
            The path to the directory where the debug CSV file will be saved which are the outputs of this function
        .INPUTS
            System.IO.FileInfo[]
        .OUTPUTS
            System.Collections.Hashtable[]
        #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable[]])]
    Param (
        [Parameter(Mandatory = $true)][System.IO.FileInfo[]]$CSVPaths,
        [Parameter(Mandatory = $true)][System.IO.DirectoryInfo]$StagingArea
    )
    Begin {
        Try {
            # Get the number of enabled CPU cores
            $CPUEnabledCores = [System.Int64](Get-CimInstance -ClassName Win32_Processor -Verbose:$false).NumberOfEnabledCore
        }
        Catch {
            [WDACConfig.Logger]::Write('Optimize-MDECSVData: Unable to detect the number of enabled CPU cores, defaulting to 5...')
        }
    }

    Process {

        # Create a new HashTable array to hold the updated data from the original CSVs
        [System.Collections.Hashtable[]]$NewCsvData = $CSVPaths | ForEach-Object -ThrottleLimit ($CPUEnabledCores ?? 5) -Parallel {

            # Read the initial MDE AH CSV export and save them into a variable
            [System.Object[]]$CsvData += Import-Csv -Path $_

            # Add the nested properties in the "AdditionalFields" property to the parent record as first-level properties
            foreach ($Row in $CsvData) {

                # Create a new HashTable for the combined data
                [System.Collections.Hashtable]$CurrentRowHashTable = @{}

                # For each row in the CSV data, create a new object to hold the updated properties, except for the "AdditionalFields" property
                foreach ($Property in $Row.PSObject.Properties) {
                    if ($Property.Name -ne 'AdditionalFields') {
                        $CurrentRowHashTable[$Property.Name] = $Property.Value
                    }
                }

                # Convert the AdditionalFields JSON string to a HashTable
                [System.Collections.Hashtable]$JsonConverted = $Row.AdditionalFields | ConvertFrom-Json -AsHashtable

                # Add each Key/Value pairs from the additional fields HashTable to the CurrentRow HashTable
                foreach ($Item in $JsonConverted.GetEnumerator()) {
                    $CurrentRowHashTable[$Item.Name] = $Item.Value
                }

                # Send the new HashTable to the pipeline to be saved in the HashTable Array
                [System.Collections.Hashtable]$CurrentRowHashTable
            }
        }
    }

    End {

        if ([WDACConfig.GlobalVars]::DebugPreference) {

            [WDACConfig.Logger]::Write('Optimize-MDECSVData: Debug parameter was used, exporting the new array to a CSV file...')

            # Initialize a HashSet to keep track of all property names (aka keys in the HashTable Array)
            $PropertyNames = [System.Collections.Generic.HashSet[System.String]] @()

            # Loop through each HashTable's keys in the new updated CSV data to find and add any new key names to the list that are not already present
            # These are the property names from the AdditionalFields
            foreach ($Obj in $NewCsvData.Keys) {
                if (-NOT $PropertyNames.Contains($Obj)) {
                    $PropertyNames += $Obj
                }
            }

            # Export the new array to a CSV file containing all of the original properties and the new properties from the AdditionalFields
            # guarantees that no property gets lost during CSV export
            $NewCsvData | Select-Object -Property $PropertyNames | Export-Csv -Path (Join-Path -Path $StagingArea -ChildPath 'Pass1.csv') -Force
        }

        Return $NewCsvData
    }
}
Export-ModuleMember -Function 'Optimize-MDECSVData'
