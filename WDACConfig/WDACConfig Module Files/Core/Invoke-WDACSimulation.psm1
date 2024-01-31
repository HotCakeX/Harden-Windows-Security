Function Invoke-WDACSimulation {
    [CmdletBinding()]
    Param(
        [ValidateScript({ Test-Path -Path $_ -PathType 'Container' }, ErrorMessage = 'The path you selected is not a valid folder path.')]
        [Parameter(Mandatory = $false)][System.IO.DirectoryInfo]$FolderPath,

        [ValidateScript({
                # Ensure the selected path is a file path
                if (Test-Path -Path $_ -PathType 'Leaf') {
                    # Ensure the selected file has a supported extension
                    [System.IO.FileInfo]$SelectedFile = Get-ChildItem -File -Path $_ -Include '*.sys', '*.exe', '*.com', '*.dll', '*.ocx', '*.msp', '*.mst', '*.msi', '*.js', '*.vbs', '*.ps1', '*.appx'
                    # If the selected file has a supported extension, return $true
                    if ($SelectedFile) {
                        $true
                    }
                    else {
                        Throw 'The selected file is not supported by the WDAC engine.'
                    }
                }
                else { $false }
            }, ErrorMessage = 'The path you selected is not a file path.')]
        [Parameter(Mandatory = $false)][System.IO.FileInfo]$FilePath,

        [ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' }, ErrorMessage = 'The path you selected is not a valid file path.')]
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$BooleanOutput,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )

    begin {
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Importing the required sub-modules
        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Update-self.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\WDACSimulation\Compare-SignerAndCertificate.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\WDACSimulation\Get-FileRuleOutput.psm1" -Force

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-self -InvocationStatement $MyInvocation.Statement }

        # The total number of the main steps for the progress bar to render
        [System.Int16]$TotalSteps = 4
        [System.Int16]$CurrentStep = 0

        # Make sure either -FolderPath or -FilePath is specified, but not both
        if (-not ($PSBoundParameters.ContainsKey('FolderPath') -xor $PSBoundParameters.ContainsKey('FilePath'))) {
            # Write an error message
            Write-Error -Message 'You must specify either -FolderPath or -FilePath, but not both.' -Category InvalidArgument
        }
    }

    process {
        # Store the file paths of valid Allowed Signed files - FilePublisher level
        [System.IO.FileInfo[]]$SignedFilePublisherFilePaths = @()

        # Store the file paths of valid Allowed Signed files - Publisher level
        [System.IO.FileInfo[]]$SignedPublisherFilePaths = @()

        # Store the paths of files allowed by Hash
        [System.IO.FileInfo[]]$AllowedByHashFilePaths = @()

        # Store the paths of Signed files with HashMismatch Status
        [System.IO.FileInfo[]]$SignedHashMismatchFilePaths = @()

        # Store the paths of Signed files with a status that doesn't fall into any other category
        [System.IO.FileInfo[]]$SignedButUnknownFilePaths = @()

        # Store the paths of Unsigned files that are not allowed by hash
        [System.IO.FileInfo[]]$UnsignedNotAllowedFilePaths = @()

        # Store the final object of all of the results
        [System.Object[]]$MegaOutputObject = @()       

        # Hash Sha256 values of all the file rules based on hash in the supplied xml policy file
        Write-Verbose -Message 'Getting the Sha256 Hash values of all the file rules based on hash in the supplied xml policy file'

        $CurrentStep++
        Write-Progress -Id 0 -Activity 'Getting the Sha256 Hash values from the XML file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

        [System.String[]]$SHA256HashesFromXML = (Get-FileRuleOutput -xmlPath $XmlFilePath).hashvalue

        # Get all of the file paths of the files that WDAC supports, from the user provided directory
        Write-Verbose -Message 'Getting all of the file paths of the files that WDAC supports, from the user provided directory'

        $CurrentStep++
        Write-Progress -Id 0 -Activity "Getting the supported files' paths" -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

        if ($FilePath) {
            [System.IO.FileInfo]$CollectedFiles = Get-ChildItem -File -Path $FilePath
        }
        else {
            [System.IO.FileInfo[]]$CollectedFiles = (Get-ChildItem -Recurse -Path $FolderPath -File -Include '*.sys', '*.exe', '*.com', '*.dll', '*.ocx', '*.msp', '*.mst', '*.msi', '*.js', '*.vbs', '*.ps1', '*.appx').FullName
        }

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
                    if ($AllowedByHashFilePaths -notcontains $CurrentFilePath) { 
                        $AllowedByHashFilePaths += $CurrentFilePath
                    }
                }
                # If the file's hash does not exist in the supplied XML file, then check its signature
                else {
                    # Get the status of file's signature
                    switch ((Get-AuthenticodeSignature -FilePath $CurrentFilePath).Status) {
                        # If the file is signed and valid
                        'valid' {
                            # Use the Compare-SignerAndCertificate function to process it
                            [System.Object[]]$ComparisonResult = Compare-SignerAndCertificate -XmlFilePath $XmlFilePath -SignedFilePath $CurrentFilePath

                            # Filter out the results looking for file path that is allowed by the policy using FilePublisher level
                            [System.IO.FileInfo]$ComparisonResultFilePublisher = $ComparisonResult | Where-Object -FilterScript { ($_.CertRootMatch -eq $true) -and ($_.CertNameMatch -eq $true) -and ($_.CertPublisherMatch -eq $true) } | Select-Object -ExpandProperty FilePath -Unique
                            # Filter out the results looking for file path that is allowed by the policy using Publisher level
                            [System.IO.FileInfo]$ComparisonResultPublisher = $ComparisonResult | Where-Object -FilterScript { ($_.CertRootMatch -eq $true) -and ($_.CertNameMatch -eq $true) } | Select-Object -ExpandProperty FilePath -Unique

                            # First check if the file is allowed by the policy using FilePublisher level
                            if ($ComparisonResultFilePublisher) {
                                Write-Verbose -Message 'The file is signed and valid, and allowed by the policy using FilePublisher level'
                                
                                if ($SignedFilePublisherFilePaths -notcontains $ComparisonResultFilePublisher) { 
                                    $SignedFilePublisherFilePaths += $ComparisonResultFilePublisher
                                }
                            }
                            # If the file is not allowed by FilePublisher level, then check if it's allowed by Publisher level
                            elseif ($ComparisonResultPublisher) {
                                Write-Verbose -Message 'The file is signed and valid, and allowed by the policy using Publisher level'
                                
                                if ($SignedPublisherFilePaths -notcontains $ComparisonResultPublisher) { 
                                    $SignedPublisherFilePaths += $ComparisonResultPublisher
                                }                            
                            }
                            # If the file is not allowed by Publisher level, then it's not allowed by the policy
                            else {
                                Write-Verbose -Message 'The file is signed and valid, but not allowed by the policy using either FilePublisher or Publisher levels'
                                if ($SignedButUnknownFilePaths -notcontains $CurrentFilePath) { 
                                    $SignedButUnknownFilePaths += $CurrentFilePath
                                }  
                            }
                            # Break out of the switch statement
                            break
                        }
                        # If the file is signed but is tampered
                        'HashMismatch' {
                            Write-Warning -Message 'The file has hash mismatch, it is most likely tampered.'
                            if ($SignedHashMismatchFilePaths -notcontains $CurrentFilePath) { 
                                $SignedHashMismatchFilePaths += $CurrentFilePath
                            }     
                            # Break out of the switch statement
                            break
                        }
                        # If the file is not signed
                        'NotSigned' {
                            Write-Warning -Message 'The file is not signed and is not allowed by hash'
                            if ($UnsignedNotAllowedFilePaths -notcontains $CurrentFilePath) { 
                                $UnsignedNotAllowedFilePaths += $CurrentFilePath
                            }  
                            # Break out of the switch statement
                            break                            
                        }
                        # If the file is signed but has unknown signature status
                        default {
                            Write-Verbose -Message 'The file has unknown signature status'
                            if ($SignedButUnknownFilePaths -notcontains $CurrentFilePath) { 
                                $SignedButUnknownFilePaths += $CurrentFilePath
                            } 
                            # Break out of the switch statement
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

        if ($AllowedByHashFilePaths) {
            Write-Verbose -Message 'Looping through the array of files allowed by hash'
            foreach ($Path in $AllowedByHashFilePaths) {
                # Create a hash table with the file path and source
                [System.Collections.Hashtable]$Object = @{
                    FilePath     = $Path
                    Source       = 'Hash'
                    Permission   = 'Allowed'
                    IsAuthorized = $true
                }
                # Convert the hash table to a PSObject and add it to the output array
                $MegaOutputObject += New-Object -TypeName PSObject -Property $Object
            }
        }

        # For valid allowed Signed files - FilePublisher level
        if ($SignedFilePublisherFilePaths) {            
            Write-Verbose -Message 'Looping through the array of files allowed by valid signature - FilePublisher Level'
            foreach ($Path in $SignedFilePublisherFilePaths) {
                # Create a hash table with the file path and source properties
                [System.Collections.Hashtable]$Object = @{
                    FilePath     = $Path
                    Source       = 'Signer'
                    Permission   = 'Allowed - FilePublisher Level'
                    IsAuthorized = $true
                }
                # Convert the hash table to a PSObject and add it to the output array
                $MegaOutputObject += New-Object -TypeName PSObject -Property $Object
            }
        }

        # For valid allowed Signed files - Publisher level
        if ($SignedPublisherFilePaths) {
            Write-Verbose -Message 'Looping through the array of files allowed by valid signature - Publisher Level'
            foreach ($Path in $SignedPublisherFilePaths) {
                # Create a hash table with the file path and source properties
                [System.Collections.Hashtable]$Object = @{
                    FilePath     = $Path
                    Source       = 'Signer'
                    Permission   = 'Allowed - Publisher Level'
                    IsAuthorized = $true
                }
                # Convert the hash table to a PSObject and add it to the output array
                $MegaOutputObject += New-Object -TypeName PSObject -Property $Object
            }
        }

        # For Signed files with hash mismatch signature status
        if ($SignedHashMismatchFilePaths) {
            Write-Verbose -Message 'Looping through the array of signed files with hash mismatch'
            foreach ($Path in $SignedHashMismatchFilePaths) {
                # Create a hash table with the file path and source properties
                [System.Collections.Hashtable]$Object = @{
                    FilePath     = $Path
                    Source       = 'Signer'
                    Permission   = 'Not Allowed - Hash Mismatch'
                    IsAuthorized = $false
                }
                # Convert the hash table to a PSObject and add it to the output array
                $MegaOutputObject += New-Object -TypeName PSObject -Property $Object
            }
        }

        # For Signed files with Unknown signature status
        if ($SignedButUnknownFilePaths) {
            Write-Verbose -Message 'Looping through the array of files with unknown signature status'
            foreach ($Path in $SignedButUnknownFilePaths) {
                # Create a hash table with the file path and source properties
                [System.Collections.Hashtable]$Object = @{
                    FilePath     = $Path
                    Source       = 'Signer'
                    Permission   = 'Not Allowed - Expired or Unknown'
                    IsAuthorized = $false
                }
                # Convert the hash table to a PSObject and add it to the output array
                $MegaOutputObject += New-Object -TypeName PSObject -Property $Object
            }
        }
       
        # For Unsigned files not allowed by hash
        if ($UnsignedNotAllowedFilePaths) {
            Write-Verbose -Message 'Looping through the array of files not allowed by the policy'
            foreach ($Path in $UnsignedNotAllowedFilePaths) {
                # Create a hash table with the file path and source properties
                [System.Collections.Hashtable]$Object = @{
                    FilePath     = $Path
                    Source       = 'Unsigned'
                    Permission   = 'Not Allowed'
                    IsAuthorized = $false
                }
                # Convert the hash table to a PSObject and add it to the output array
                $MegaOutputObject += New-Object -TypeName PSObject -Property $Object
            }
        }
    }

    end {
        # If the user selected the -BooleanOutput switch, then return a boolean value and don't display any more output
        if ($BooleanOutput) {
            # Get all of the allowed files
            $AllAllowedRules = $MegaOutputObject | Where-Object -FilterScript { $_.IsAuthorized -eq $true }
            # Get all of the blocked files
            $BlockedRules = $MegaOutputObject | Where-Object -FilterScript { $_.IsAuthorized -eq $false }

            Write-Verbose -Message "Allowed files: $($AllAllowedRules.count)"
            Write-Verbose -Message "Blocked files: $($BlockedRules.count)"

            # If the array of allowed files is not empty
            if (-NOT ([System.String]::IsNullOrWhiteSpace($AllAllowedRules))) {

                # If the array of blocked files is empty
                if ([System.String]::IsNullOrWhiteSpace($BlockedRules)) {
                    Write-Progress -Id 0 -Activity 'WDAC Simulation completed.' -Completed
                    Return $true
                }
                else {
                    Write-Progress -Id 0 -Activity 'WDAC Simulation completed.' -Completed
                    Return $false
                }
            }
            else {
                Write-Progress -Id 0 -Activity 'WDAC Simulation completed.' -Completed
                Return $false
            }
        }
        
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
        }, Permission, IsAuthorized | Sort-Object -Property Permission | Format-Table -Property FilePath, Source, Permission, IsAuthorized


        # Number of files allowed by hash - used for counting only
        $UniqueFilesAllowedByHash = $MegaOutputObject | Select-Object -Property FilePath, source, Permission, IsAuthorized | Where-Object -FilterScript { $_.source -eq 'hash' }

        Write-ColorfulText -Color Lavender -InputText "$($SignedFilePublisherFilePaths.count) File(s) Are Allowed by Signatures by Your Policy With FilePublisher Level."
        Write-ColorfulText -Color Lavender -InputText "$($SignedPublisherFilePaths.count) File(s) Are Allowed by Signatures by Your Policy With Publisher Level."
        Write-ColorfulText -Color Lavender -InputText "$($UniqueFilesAllowedByHash.count) File(s) Are Allowed by Hashes by Your Policy."

        # Export the output as CSV
        $MegaOutputObject | Select-Object -Property FilePath, Source, Permission, IsAuthorized | Sort-Object -Property Permission | Export-Csv -Path .\WDACSimulationOutput.csv -Force

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
.PARAMETER Verbose
    Can be used with any parameter to show verbose output
.PARAMETER BooleanOutput
    Can be used with any parameter to return a boolean value instead of displaying the output
.INPUTS
    System.IO.FileInfo
    System.IO.DirectoryInfo
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.Object[]
    System.String
    System.Boolean
.EXAMPLE
    Invoke-WDACSimulation -FolderPath 'C:\Windows\System32' -XmlFilePath 'C:\Users\HotCakeX\Desktop\Policy.xml'
    This example will simulate the deployment of the policy.xml file against the C:\Windows\System32 folder
#>
}

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\Resources\ArgumentCompleters.ps1"
Register-ArgumentCompleter -CommandName 'Invoke-WDACSimulation' -ParameterName 'FolderPath' -ScriptBlock $ArgumentCompleterFolderPathsPicker
Register-ArgumentCompleter -CommandName 'Invoke-WDACSimulation' -ParameterName 'XmlFilePath' -ScriptBlock $ArgumentCompleterXmlFilePathsPicker
Register-ArgumentCompleter -CommandName 'Invoke-WDACSimulation' -ParameterName 'FilePath' -ScriptBlock $ArgumentCompleterAnyFilePathsPicker

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBuhv9D0tzOFH0g
# wdl4ncTJJIks2yAkKB5vMlchQKJJg6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
# LDQz/68TAAAAAAAEMA0GCSqGSIb3DQEBDQUAME8xEzARBgoJkiaJk/IsZAEZFgNj
# b20xIjAgBgoJkiaJk/IsZAEZFhJIT1RDQUtFWC1DQS1Eb21haW4xFDASBgNVBAMT
# C0hPVENBS0VYLUNBMCAXDTIzMTIyNzExMjkyOVoYDzIyMDgxMTEyMTEyOTI5WjB5
# MQswCQYDVQQGEwJVSzEeMBwGA1UEAxMVSG90Q2FrZVggQ29kZSBTaWduaW5nMSMw
# IQYJKoZIhvcNAQkBFhRob3RjYWtleEBvdXRsb29rLmNvbTElMCMGCSqGSIb3DQEJ
# ARYWU3B5bmV0Z2lybEBvdXRsb29rLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAKb1BJzTrpu1ERiwr7ivp0UuJ1GmNmmZ65eckLpGSF+2r22+7Tgm
# pEifj9NhPw0X60F9HhdSM+2XeuikmaNMvq8XRDUFoenv9P1ZU1wli5WTKHJ5ayDW
# k2NP22G9IPRnIpizkHkQnCwctx0AFJx1qvvd+EFlG6ihM0fKGG+DwMaFqsKCGh+M
# rb1bKKtY7UEnEVAsVi7KYGkkH+ukhyFUAdUbh/3ZjO0xWPYpkf/1ldvGes6pjK6P
# US2PHbe6ukiupqYYG3I5Ad0e20uQfZbz9vMSTiwslLhmsST0XAesEvi+SJYz2xAQ
# x2O4n/PxMRxZ3m5Q0WQxLTGFGjB2Bl+B+QPBzbpwb9JC77zgA8J2ncP2biEguSRJ
# e56Ezx6YpSoRv4d1jS3tpRL+ZFm8yv6We+hodE++0tLsfpUq42Guy3MrGQ2kTIRo
# 7TGLOLpayR8tYmnF0XEHaBiVl7u/Szr7kmOe/CfRG8IZl6UX+/66OqZeyJ12Q3m2
# fe7ZWnpWT5sVp2sJmiuGb3atFXBWKcwNumNuy4JecjQE+7NF8rfIv94NxbBV/WSM
# pKf6Yv9OgzkjY1nRdIS1FBHa88RR55+7Ikh4FIGPBTAibiCEJMc79+b8cdsQGOo4
# ymgbKjGeoRNjtegZ7XE/3TUywBBFMf8NfcjF8REs/HIl7u2RHwRaUTJdAgMBAAGj
# ggJzMIICbzA8BgkrBgEEAYI3FQcELzAtBiUrBgEEAYI3FQiG7sUghM++I4HxhQSF
# hqV1htyhDXuG5sF2wOlDAgFkAgEIMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1Ud
# DwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYB
# BQUHAwMwHQYDVR0OBBYEFOlnnQDHNUpYoPqECFP6JAqGDFM6MB8GA1UdIwQYMBaA
# FICT0Mhz5MfqMIi7Xax90DRKYJLSMIHUBgNVHR8EgcwwgckwgcaggcOggcCGgb1s
# ZGFwOi8vL0NOPUhPVENBS0VYLUNBLENOPUhvdENha2VYLENOPUNEUCxDTj1QdWJs
# aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
# LERDPU5vbkV4aXN0ZW50RG9tYWluLERDPWNvbT9jZXJ0aWZpY2F0ZVJldm9jYXRp
# b25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwgccG
# CCsGAQUFBwEBBIG6MIG3MIG0BggrBgEFBQcwAoaBp2xkYXA6Ly8vQ049SE9UQ0FL
# RVgtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZp
# Y2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Tm9uRXhpc3RlbnREb21haW4sREM9Y29t
# P2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0
# aG9yaXR5MA0GCSqGSIb3DQEBDQUAA4ICAQA7JI76Ixy113wNjiJmJmPKfnn7brVI
# IyA3ZudXCheqWTYPyYnwzhCSzKJLejGNAsMlXwoYgXQBBmMiSI4Zv4UhTNc4Umqx
# pZSpqV+3FRFQHOG/X6NMHuFa2z7T2pdj+QJuH5TgPayKAJc+Kbg4C7edL6YoePRu
# HoEhoRffiabEP/yDtZWMa6WFqBsfgiLMlo7DfuhRJ0eRqvJ6+czOVU2bxvESMQVo
# bvFTNDlEcUzBM7QxbnsDyGpoJZTx6M3cUkEazuliPAw3IW1vJn8SR1jFBukKcjWn
# aau+/BE9w77GFz1RbIfH3hJ/CUA0wCavxWcbAHz1YoPTAz6EKjIc5PcHpDO+n8Fh
# t3ULwVjWPMoZzU589IXi+2Ol0IUWAdoQJr/Llhub3SNKZ3LlMUPNt+tXAs/vcUl0
# 7+Dp5FpUARE2gMYA/XxfU9T6Q3pX3/NRP/ojO9m0JrKv/KMc9sCGmV9sDygCOosU
# 5yGS4Ze/DJw6QR7xT9lMiWsfgL96Qcw4lfu1+5iLr0dnDFsGowGTKPGI0EvzK7H+
# DuFRg+Fyhn40dOUl8fVDqYHuZJRoWJxCsyobVkrX4rA6xUTswl7xYPYWz88WZDoY
# gI8AwuRkzJyUEA07IYtsbFCYrcUzIHME4uf8jsJhCmb0va1G2WrWuyasv3K/G8Nn
# f60MsDbDH1mLtzGCAxgwggMUAgEBMGYwTzETMBEGCgmSJomT8ixkARkWA2NvbTEi
# MCAGCgmSJomT8ixkARkWEkhPVENBS0VYLUNBLURvbWFpbjEUMBIGA1UEAxMLSE9U
# Q0FLRVgtQ0ECEx4AAAAEjzQsNDP/rxMAAAAAAAQwDQYJYIZIAWUDBAIBBQCggYQw
# GAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQx
# IgQgZ/zTMd4vHTATZg/dbCnYHPravfGeTNOcSzqG/NrrJZowDQYJKoZIhvcNAQEB
# BQAEggIAIexDYlsvEW+grR4STm0HpjdCPDGeMIBKgO7lw+CsxUdIXnRaB52GGmJm
# tJolY9AdMP6O9DVMmtdN1pM/ooWDKFg91/2et4Tvzw9AWvpeq6rbEfFDphOmbx7t
# ifFOAtexswZtycWlADi4I7qFNUDxslU21eHORfrtugEJojfcwXG9AJZsZZtzfEf7
# xjeu2IltRpxDHUn5CQYP4OQG9GOgwnWMWF48cUc/F7oWEaoh3BjW9snXbtA8HyBN
# /+o2jXXg6veZf1ZwmSPvB/mCL5LalcCG+SQtW/NMCjpp1i3nqnHe7PAxdLgtP2hO
# 2JvQo8CHQWJITqRqK4rovGg7fb18oDePd0bS0AwzygcdDRjy/FlRemFTyPrupYZY
# 23KaPmSoiH2+gcGYQWuTwO561lqLQoEyW5UhomUfJXnpXC8YsNwxKsyTPmIg8y1R
# 8vdeJLv7LXcADuBe1la7Mz8LH5maCVFasfAkt5TejiGm45X/nqNe+IOrL/DStzcL
# CJGYgqNNz1Z+AD/xrCWRil4m3y3CQd/gaVRy2iakF6rj4jq/ELVLTxuw5OrB7dBU
# P8sZTQW6azz1+QqpGdUBzM1+G96uANNyGhRpslcvPH9RwgMJCDbR3Y2tqQbvE+qC
# +9cl0UXv05uXkRwOUZjuTQoJZGJ+ukDwMGfyXN+ngJUlYjISU60=
# SIG # End signature block
