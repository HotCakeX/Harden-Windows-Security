Function Invoke-WDACSimulation {
    [CmdletBinding(
        PositionalBinding = $false,
        SupportsShouldProcess = $true
    )]
    Param(
        [ValidateScript({ Test-Path -Path $_ -PathType 'Container' }, ErrorMessage = 'The path you selected is not a folder path.')]
        [Parameter(Mandatory = $true)][System.IO.DirectoryInfo]$FolderPath,

        [ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' }, ErrorMessage = 'The path you selected is not a file path.')]
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )

    begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"
        # Importing resources such as functions by dot-sourcing so that they will run in the same scope and their variables will be usable
        . "$ModuleRootPath\Resources\Resources2.ps1"

        # Importing the required sub-modules
        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Update-self.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force

        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        # if -SkipVersionCheck wasn't passed, run the updater
        # Redirecting the Update-Self function's information Stream to $null because Write-Host
        # Used by Write-ColorfulText outputs to both information stream and host console
        if (-NOT $SkipVersionCheck) { Update-self 6> $null }

        # The total number of the main steps for the progress bar to render
        [System.Int16]$TotalSteps = 4
        [System.Int16]$CurrentStep = 0
    }

    process {
        # Store the processed results of the valid Signed files
        [System.Object[]]$SignedResult = @()

        # File paths of the files allowed by Signer/certificate
        [System.IO.FileInfo[]]$AllowedSignedFilePaths = @()

        # File paths of the files allowed by Hash
        [System.IO.FileInfo[]]$AllowedUnsignedFilePaths = @()

        # Stores the final object of all of the results
        [System.Object[]]$MegaOutputObject = @()

        # File paths of the Signed files with HashMismatch Status
        [System.IO.FileInfo[]]$SignedHashMismatchFilePaths = @()

        # File paths of the Signed files with a status that doesn't fall into any other category
        [System.IO.FileInfo[]]$SignedButUnknownFilePaths = @()

        # Hash Sha256 values of all the file rules based on hash in the supplied xml policy file
        Write-Verbose -Message 'Getting the Sha256 Hash values of all the file rules based on hash in the supplied xml policy file'

        $CurrentStep++
        Write-Progress -Id 0 -Activity 'Getting the Sha256 Hash values from the XML file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

        [System.String[]]$SHA256HashesFromXML = (Get-FileRuleOutput -xmlPath $XmlFilePath).hashvalue

        # Get all of the file paths of the files that WDAC supports, from the user provided directory
        Write-Verbose -Message 'Getting all of the file paths of the files that WDAC supports, from the user provided directory'

        $CurrentStep++
        Write-Progress -Id 0 -Activity "Getting the supported files' paths" -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

        [System.IO.FileInfo[]]$CollectedFiles = (Get-ChildItem -Recurse -Path $FolderPath -File -Include '*.sys', '*.exe', '*.com', '*.dll', '*.ocx', '*.msp', '*.mst', '*.msi', '*.js', '*.vbs', '*.ps1', '*.appx').FullName

        # Make sure the selected directory contains files with the supported extensions
        if (!$CollectedFiles) { Throw 'There are no files in the selected directory that are supported by the WDAC engine.' }

        try {

            # Loop through each file
            Write-Verbose -Message 'Looping through each supported file'

            $CurrentStep++
            Write-Progress -Id 0 -Activity 'Looping through each supported file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            # The total number of the sub steps for the progress bar to render
            [System.Int64]$TotalSubSteps = $CollectedFiles.Count
            [System.Int64]$CurrentSubStep = 0

            foreach ($CurrentFilePath in $CollectedFiles) {

                Write-Verbose -Message "Processing file: $CurrentFilePath"

                $CurrentSubStep++
                Write-Progress -Id 1 -ParentId 0 -Activity "Processing file $CurrentSubStep/$TotalSubSteps" -Status "$CurrentFilePath" -PercentComplete ($CurrentSubStep / $TotalSubSteps * 100)

                # Check see if the file's hash exists in the XML file regardless of whether it's signed or not
                # This is because WDAC policies sometimes have hash rules for signed files too
                # So here we prioritize being authorized by file hash over being authorized by Signature
                try {
                    Write-Verbose -Message 'Using Get-AppLockerFileInformation to retrieve the hashes of the file'
                    [System.String]$CurrentFilePathHash = (Get-AppLockerFileInformation -Path $CurrentFilePath -ErrorAction Stop).hash -replace 'SHA256 0x', ''
                }
                catch {
                    Write-Verbose -Message 'Get-AppLockerFileInformation failed, using New-CIPolicyRule cmdlet...'
                    [System.Collections.ArrayList]$CurrentHashOutput = New-CIPolicyRule -Level hash -Fallback none -AllowFileNameFallbacks -UserWriteablePaths -DriverFilePath $CurrentFilePath
                    [System.String]$CurrentFilePathHash = ($CurrentHashOutput | Where-Object -FilterScript { $_.name -like '*Hash Sha256*' }).attributes.hash
                }

                # if the file's hash exists in the XML file then add the file's path to the allowed files and do not check anymore that whether the file is signed or not
                if ($CurrentFilePathHash -in $SHA256HashesFromXML) {
                    Write-Verbose -Message 'Hash of the file exists in the supplied XML file'
                    $AllowedUnsignedFilePaths += $CurrentFilePath
                }
                # If the file's hash does not exist in the supplied XML file, then check its signature
                else {
                    # Get the status of file's signature
                    switch ((Get-AuthenticodeSignature -FilePath $CurrentFilePath).Status) {
                        # If the file is signed and valid
                        'valid' {
                            # Use the function in Resources2.ps1 file to process it
                            Write-Verbose -Message 'The file is signed and has valid signature'
                            $SignedResult += Compare-SignerAndCertificate -XmlFilePath $XmlFilePath -SignedFilePath $CurrentFilePath | Where-Object -FilterScript { ($_.CertRootMatch -eq $true) -and ($_.CertNameMatch -eq $true) -and ($_.CertPublisherMatch -eq $true) }
                            break
                        }
                        # If the file is signed but is tampered
                        'HashMismatch' {
                            Write-Warning -Message 'The file has hash mismatch, it is most likely tampered.'
                            $SignedHashMismatchFilePaths += $CurrentFilePath
                            break
                        }
                        # If the file is signed but has unknown signature status
                        default {
                            Write-Verbose -Message 'The file has unknown signature status'
                            $SignedButUnknownFilePaths += $CurrentFilePath
                            break
                        }
                    }
                }
            }
        }
        catch {
            # Complete the main progress bar because there was an error
            Write-Progress -Id 0 -Activity 'WDAC Simulation interrupted.' -Completed
            # Throw whatever error that was encountered
            throw $_
        }
        finally {
            # Complete the nested progress bar whether there was an error or not
            Write-Progress -Id 1 -Activity 'All of the files have been processed.' -Completed
        }

        $CurrentStep++
        Write-Progress -Id 0 -Activity 'Preparing the output' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

        # File paths of the files allowed by Signer/certificate, Unique
        [System.Object[]]$AllowedSignedFilePaths = $SignedResult.FilePath | Get-Unique

        if ($AllowedUnsignedFilePaths) {
            # Loop through the first array and create output objects with the file path and source
            Write-Verbose -Message 'Looping through the array of files allowed by hash'
            foreach ($Path in $AllowedUnsignedFilePaths) {
                # Create a hash table with the file path and source
                [System.Collections.Hashtable]$Object = @{
                    FilePath   = $Path
                    Source     = 'Hash'
                    Permission = 'Allowed'
                }
                # Convert the hash table to a PSObject and add it to the output array
                $MegaOutputObject += New-Object -TypeName PSObject -Property $Object
            }
        }

        # For valid Signed files
        if ($AllowedSignedFilePaths) {
            # Loop through the second array and create output objects with the file path and source
            Write-Verbose -Message 'Looping through the array of files allowed by valid signature'
            foreach ($Path in $AllowedSignedFilePaths) {
                # Create a hash table with the file path and source properties
                [System.Collections.Hashtable]$Object = @{
                    FilePath   = $Path
                    Source     = 'Signer'
                    Permission = 'Allowed'
                }
                # Convert the hash table to a PSObject and add it to the output array
                $MegaOutputObject += New-Object -TypeName PSObject -Property $Object
            }
        }

        # For Signed files with mismatch signature status
        if ($SignedHashMismatchFilePaths) {
            Write-Verbose -Message 'Looping through the array of signed files with hash mismatch'
            # Loop through the second array and create output objects with the file path and source
            foreach ($Path in $SignedHashMismatchFilePaths) {
                # Create a hash table with the file path and source properties
                [System.Collections.Hashtable]$Object = @{
                    FilePath   = $Path
                    Source     = 'Signer'
                    Permission = 'Not Allowed - Hash Mismatch'
                }
                # Convert the hash table to a PSObject and add it to the output array
                $MegaOutputObject += New-Object -TypeName PSObject -Property $Object
            }
        }

        # For Signed files with Unknown signature status
        if ($SignedButUnknownFilePaths) {
            Write-Verbose -Message 'Looping through the array of files with unknown signature status'
            # Loop through the second array and create output objects with the file path and source
            foreach ($Path in $SignedButUnknownFilePaths) {
                # Create a hash table with the file path and source properties
                [System.Collections.Hashtable]$Object = @{
                    FilePath   = $Path
                    Source     = 'Signer'
                    Permission = 'Not Allowed - Expired or unknown'
                }
                # Convert the hash table to a PSObject and add it to the output array
                $MegaOutputObject += New-Object -TypeName PSObject -Property $Object
            }
        }

        # Unique number of files allowed by hash - used for counting only
        $UniqueFilesAllowedByHash = $MegaOutputObject | Select-Object -Property FilePath, source, Permission -Unique | Where-Object -FilterScript { $_.source -eq 'hash' }

        # To detect files that are not allowed

        # Check if any supported files were found in the user provided directory and any of them was processed by signer or was allowed by hash
        if ($($MegaOutputObject.Filepath) -and $CollectedFiles) {
            # Compare the paths of all of the supported files found in user provided directory with the array of files that were processed by Signer or allowed by hash in the policy
            # Then save the output to a different array
            [System.Object[]]$FinalComparisonForFilesNotAllowed = Compare-Object -ReferenceObject $($MegaOutputObject.Filepath) -DifferenceObject $CollectedFiles -PassThru | Where-Object -FilterScript { $_.SideIndicator -eq '=>' }
        }

        # If there are any files in the user selected directory that is not allowed by the policy
        if ($FinalComparisonForFilesNotAllowed) {
            Write-Verbose -Message 'Looping through the array of files not allowed by the policy'
            foreach ($Path in $FinalComparisonForFilesNotAllowed) {
                # Create a hash table with the file path and source properties
                [System.Collections.Hashtable]$Object = @{
                    FilePath   = $Path
                    Source     = 'N/A'
                    Permission = 'Not Allowed'
                }
                # Convert the hash table to a PSObject and add it to the output array
                $MegaOutputObject += New-Object -TypeName PSObject -Property $Object
            }
        }
    }

    end {
        # Change the color of the Table header
        $PSStyle.Formatting.TableHeader = "$($PSStyle.Foreground.FromRGB(255,165,0))"

        # Display the final main output array as a table - allowed files
        $MegaOutputObject | Select-Object -Property FilePath,

        @{
            Label      = 'Source'
            Expression =
            { switch ($_.source) {
                    { $_ -eq 'Signer' } { $color = "$($PSStyle.Foreground.FromRGB(152,255,152))" } # Use PSStyle to set the color
                    { $_ -eq 'Hash' } { $color = "$($PSStyle.Foreground.FromRGB(255,255,49))" } # Use PSStyle to set the color
                    { $_ -eq 'N/A' } { $color = "$($PSStyle.Foreground.FromRGB(255,20,147))" } # Use PSStyle to set the color
                }
                "$color$($_.source)$($PSStyle.Reset)" # Use PSStyle to reset the color
            }
        }, Permission -Unique | Sort-Object -Property Permission | Format-Table -Property FilePath, Source, Permission

        # Showing Signature based allowed file details
        Write-ColorfulText -Color Lavender -InputText "`n$($AllowedSignedFilePaths.count) File(s) Inside the Selected Folder Are Allowed by Signatures by Your Policy."

        # Showing Hash based allowed file details
        Write-ColorfulText -Color Lavender -InputText "$($UniqueFilesAllowedByHash.count) File(s) Inside the Selected Folder Are Allowed by Hashes by Your Policy.`n"

        # Export the output as CSV
        $MegaOutputObject | Select-Object -Property FilePath, source, Permission -Unique | Sort-Object -Property Permission | Export-Csv -Path .\WDACSimulationOutput.csv -Force

        Write-Progress -Id 0 -Activity 'WDAC Simulation completed.' -Completed
    }

    <#
.SYNOPSIS
    Simulates the deployment of the WDAC policy.

.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Invoke-WDACSimulation

.DESCRIPTION
    Simulates the deployment of the WDAC policy by analyzing a folder and checking which of the files in the folder are allowed by a user selected policy xml file

.COMPONENT
    Windows Defender Application Control, ConfigCI PowerShell module

.FUNCTIONALITY
    Simulates the deployment of the WDAC policy

.PARAMETER FolderPath
    Provide path to a folder where you want WDAC simulation to take place

.PARAMETER XmlFilePath
    Provide path to a policy xml file that you want the cmdlet to simulate its deployment and running files against it

.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
    It is used by the entire Cmdlet.

.INPUTS
    System.IO.FileInfo
    System.IO.DirectoryInfo
.OUTPUTS
    System.Object[]

#>
}

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\Resources\ArgumentCompleters.ps1"
Register-ArgumentCompleter -CommandName 'Invoke-WDACSimulation' -ParameterName 'FolderPath' -ScriptBlock $ArgumentCompleterFolderPathsPicker
Register-ArgumentCompleter -CommandName 'Invoke-WDACSimulation' -ParameterName 'XmlFilePath' -ScriptBlock $ArgumentCompleterXmlFilePathsPicker
