Function Split-SignedUnsignedData {
    <#
    .SYNOPSIS
        Splits the correlated event data into signed and unsigned data by identifying which data can be used to create Signer objects and which data cannot
        De-duplicates the unsigned data based on SHA256 Authenticode hash
        Determines which data in the MDE CSV logs are signed and which are unsigned
    .PARAMETER EventPackageCollections
        The correlated event data to be processed, they should be the output of the Compare-CorrelatedData function
    .INPUTS
        PSCustomObject[]
    .OUTPUTS
        PSCustomObject
        #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)][PSCustomObject[]]$EventPackageCollections
    )

    Begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Detecting if Debug switch is used
        $PSBoundParameters.Debug.IsPresent ? ([System.Boolean]$Debug = $true) : ([System.Boolean]$Debug = $false) | Out-Null

        [PSCustomObject[]]$SignedData = @()
        [PSCustomObject[]]$UnsignedData = @()
    }

    Process {

        foreach ($Data in $EventPackageCollections) {

            # Check if the current pipeline object has correlated data
            if ($Null -ne $Data.CorrelatedEventsData) {

                # Make sure the data group has valid Signer data and then get the unique signers based on their publisher TBS hash (aka leaf certificate's hash)
                $PossibleSignerData = $Data.CorrelatedEventsData | Where-Object -FilterScript { -NOT ([System.String]::IsNullOrWhiteSpace($_.PublisherTBSHash)) } | Group-Object -Property PublisherTBSHash | ForEach-Object -Process { $_.Group[0] }

                if ($Null -ne $PossibleSignerData) {

                    if ($PossibleSignerData.count -gt 1) {
                        Write-Verbose -Message "Multiple signers found for the same file: $($Data.FileName)"
                    }

                    # If there was a valid signer, replace it with the current pipeline object's signers (aka correlated data)
                    $Data.CorrelatedEventsData = $PossibleSignerData

                    # Add the current pipeline object to the signed data after correcting and replacing its correlated data (aka singers information)
                    $SignedData += $Data
                }
                else {
                    Write-Warning "No valid signer found for the file: $($Data.FileName)"

                    # Setting the unsigned correlated data's property to null since it won't need need to create hash rules
                    $Data.CorrelatedEventsData = $Null

                    # Add the current pipeline object to the unsigned data after setting its correlated data to null
                    $UnsignedData += $Data
                }
            }
            else {
                # If the current pipeline object has no correlated data, add it to the unsigned data and set its correlated data property to null
                $Data.CorrelatedEventsData = $Null
                $UnsignedData += $Data
            }
        }

        # Getting unique values only
        $SignedData = $SignedData | Group-Object -Property SHA256 | ForEach-Object -Process { $_.Group[0] }
        $UnsignedData = $UnsignedData | Group-Object -Property SHA256 | ForEach-Object -Process { $_.Group[0] }

        # De-duplicate the Unsigned data, if there is any Signed data in the array, by removing the logs of the same exact files that have valid signatures but are also found in the unsigned data
        # They are very few usually

        if (($Null -ne $SignedData) -and ($SignedData.count -ne 0)) {

            Write-Verbose -Message "The total number of unsigned data before deduplication: $($UnsignedData.Count)"

            $UnsignedData = $UnsignedData | Where-Object -FilterScript { $_.SHA256 -notin $SignedData.SHA256 }

            Write-Verbose -Message "The total number of unsigned data after deduplication: $($UnsignedData.Count)"
        }
    }

    End {

        if ($Debug) {

            Write-Verbose -Message 'Split-SignedUnsignedData: Debug parameter was used, exporting the Signed and Unsigned data to separate CSV files...'

            $SignedData | Export-Csv -Path 'C:\Users\HotCakeX\Downloads\SignedData.csv'
            $UnsignedData | Export-Csv -Path 'C:\Users\HotCakeX\Downloads\UnsignedData.csv'
        }

        Return [PSCustomObject]@{
            SignedData   = [PSCustomObject[]]$SignedData
            UnsignedData = [PSCustomObject[]]$UnsignedData
        }
    }
}
Export-ModuleMember -Function 'Split-SignedUnsignedData'
