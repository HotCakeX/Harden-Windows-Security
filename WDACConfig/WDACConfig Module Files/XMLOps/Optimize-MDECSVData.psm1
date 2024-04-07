Function Optimize-MDECSVData {
    <#
        .SYNOPSIS
            Optimizes the MDE CSV data by adding the nested properties in the "AdditionalFields" property to the parent record as first-level properties
        .DESCRIPTION
            The function runs each CSV file in parallel for fast processing based on the number of CPU cores available
        .PARAMETER CSVPath
            The path to the CSV file containing the Microsoft Defender for Endpoint Advanced Hunting data
        .PARAMETER Debug
            A switch parameter to enable debugging actions such as exporting the new array to a CSV file
        .INPUTS
            System.IO.FileInfo[]
        .OUTPUTS
            PSCustomObject[]
        #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param (
        [Parameter(Mandatory = $true)][System.IO.FileInfo[]]$CSVPaths
    )

    Begin {
        # Detecting if Debug switch is used
        $PSBoundParameters.Debug.IsPresent ? ([System.Boolean]$Debug = $true) : ([System.Boolean]$Debug = $false) | Out-Null

        Try {
            # Get the number of enabled CPU cores
            $CPUEnabledCores = [System.Int64](Get-CimInstance -ClassName Win32_Processor -Verbose:$false).NumberOfEnabledCore
        }
        Catch {
            Write-Verbose -Message 'Optimize-MDECSVData: Unable to detect the number of enabled CPU cores, defaulting to 5...'
        }
    }

    Process {

        # Create a new array to hold the updated objects from the original CSVs
        [PSCustomObject[]]$NewCsvData = $CSVPaths | ForEach-Object -ThrottleLimit ($CPUEnabledCores ?? 5) -Parallel {

            # Read the initial MDE AH CSV export and save them into a variable
            [System.Object[]]$CsvData += Import-Csv -Path $_

            # Add the nested properties in the "AdditionalFields" property to the parent record as first-level properties
            foreach ($Row in $CsvData) {

                # Create a new object for the combined data
                [PSCustomObject]$NewObject = New-Object -TypeName PSCustomObject

                # For each row in the CSV data, create a new object to hold the updated properties, except for the "AdditionalFields" property
                foreach ($Property in $Row.PSObject.Properties) {
                    if ($Property.Name -ne 'AdditionalFields') {
                        $NewObject | Add-Member -NotePropertyName $Property.Name -NotePropertyValue $Property.Value
                    }
                }

                # Convert the AdditionalFields JSON string to a PowerShell object
                [PSCustomObject]$JsonConverted = $Row.AdditionalFields | ConvertFrom-Json

                # Add each property from the additional fields to the new object as main property
                foreach ($Property in $JsonConverted.PSObject.Properties) {
                    $NewObject | Add-Member -NotePropertyName $Property.Name -NotePropertyValue $Property.Value
                }

                # Send the new object to the pipeline to be saved in the new array
                [PSCustomObject]$NewObject
            }
        }
    }

    End {

        if ($Debug) {

            Write-Verbose -Message 'Optimize-MDECSVData: Debug parameter was used, exporting the new array to a CSV file...'

            # Initialize a list to keep track of all property names
            [System.String[]]$PropertyNames = @()

            # Loop through each object in the new updated CSV data to find and add any new property names to the list that are not already present
            # These are the property names from the AdditionalFields
            foreach ($Obj in $NewCsvData) {
                foreach ($Prop in $Obj.PSObject.Properties) {
                    if ($Prop.Name -notin $PropertyNames) {
                        $PropertyNames += $Prop.Name
                    }
                }
            }

            # Export the new array to a CSV file containing all of the original properties and the new properties from the AdditionalFields
            # guarantees that no property gets lost during CSV export
            $NewCsvData | Select-Object -Property $PropertyNames | Export-Csv -Path 'C:\Users\HotCakeX\Downloads\Pass1.csv'
        }

        Return $NewCsvData
    }
}