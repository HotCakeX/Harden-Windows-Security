Function Build-SignerAndHashObjects {
    <#
    .SYNOPSIS
        Creates Signer and Hash objects from the input data
        2 types of Signers are created: FilePublisher and Publisher signers

        FilePublisher Signers are created for files that have the necessary details for a FilePublisher rule
        Publisher Signers are created for files that don't have the necessary details for a FilePublisher rule
        Hashes are created for the unsigned data

        The output is a single object with nested properties for the Signers and Hashes

        Both Publisher and FilePublisher signers first check if the file has both Issuer and Publisher TBS hashes, if they are present then both of them will be used to create the Signer.
        If the file is missing the Issuer TBS hash, then the Publisher certificate will be used for both Publisher and Issuer details (TBS and Name)
        This will essentially create the Signers based on LeafCertificate Level.

        The New-FilePublisherLevelRules and New-PublisherLevelRules functions both are able to create rules based on different signer WDAC levels.

        The other way around, where Publisher TBS hash is missing but Issuer TBS is present, would create a PCACertificate level Signer, but that is not implemented yet.
        Its use case is not clear yet and there haven't been any files with that condition yet.
    .PARAMETER Data
        The Data to be processed. These are the logs selected by the user and contain both signed and unsigned data.
        They will be separated into 2 arrays.
    .PARAMETER IncomingDataType
        The type of data that is being processed. This is used to determine the property names in the input data.
        The default value is 'MDEAH' (Microsoft Defender Application Guard Event and Hash) and the other value is 'EVTX' (Event Log evtx files).
    .PARAMETER PubLisherToHash
        It will pass any publisher rules to the hash array. This is used when sandboxing-like behavior using Macros and AppIDs are used.
    .INPUTS
        PSCustomObject[]
    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)][PSCustomObject[]]$Data,
        [ValidateSet('MDEAH', 'EVTX')]
        [Parameter(Mandatory = $false)][System.String]$IncomingDataType,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$PubLisherToHash
    )
    Begin {
        . "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\PSDefaultParameterValues.ps1"

        # An array to store the Signers created with FilePublisher Level
        $FilePublisherSigners = New-Object -TypeName System.Collections.Generic.List[WDACConfig.FilePublisherSignerCreator]

        # An array to store the Signers created with Publisher Level
        $PublisherSigners = New-Object -TypeName System.Collections.Generic.List[WDACConfig.PublisherSignerCreator]

        # An array to store the FileAttributes created using Hash Level
        $CompleteHashes = New-Object -TypeName System.Collections.Generic.List[WDACConfig.HashCreator]

        # Defining the arrays to store the signed and unsigned data
        $SignedData = New-Object -TypeName System.Collections.Generic.List[PSCustomObject]
        $UnsignedData = New-Object -TypeName System.Collections.Generic.List[PSCustomObject]


        # Loop through the data and separate the signed and unsigned data
        foreach ($Item in $Data) {
            if ($Item.SignatureStatus -eq 'Signed') {

                $SignedData.Add($Item)
            }
            else {
                $UnsignedData.Add($Item)
            }
        }
    }

    Process {

        if ($Null -ne $SignedData -and $SignedData.Count -gt 0) {

            # Process the signed data
            Foreach ($CurrentData in $SignedData) {

                # Create a new FilePublisherSignerCreator object
                $CurrentFilePublisherSigner = New-Object -TypeName 'WDACConfig.FilePublisherSignerCreator'
                # Create a new PublisherSignerCreator object
                $CurrentPublisherSigner = New-Object -TypeName 'WDACConfig.PublisherSignerCreator'

                # Loop through each correlated event and process the certificate details
                foreach ($CorData in ($IncomingDataType -eq 'MDEAH' ? $CurrentData.CorrelatedEventsData.Values : $CurrentData.SignerInfo.Values)) {

                    # If the file doesn't have Issuer TBS hash (aka Intermediate certificate hash), use the leaf cert's TBS hash and CN instead (aka publisher TBS hash)
                    # This is according to the ConfigCI's workflow when encountering specific files
                    # MDE doesn't generate Issuer TBS hash for some files
                    # For those files, the FilePublisher rule will be created with the file's leaf Certificate details only (Publisher certificate)
                    if (([System.String]::IsNullOrWhiteSpace($CorData.IssuerTBSHash)) -and (-NOT (([System.String]::IsNullOrWhiteSpace($CorData.PublisherTBSHash))))) {

                        Write-Warning -Message "Build-SignerAndHashObjects: Intermediate Certificate TBS hash is empty for the file: $($IncomingDataType -eq 'MDEAH' ? $CurrentData.FileName : $CurrentData.'File Name'), using the leaf certificate TBS hash instead"

                        $CurrentCorData = [WDACConfig.CertificateDetailsCreator]::New(
                            $CorData.PublisherTBSHash,
                            $CorData.PublisherName,
                            $CorData.PublisherTBSHash,
                            $CorData.PublisherName
                        )
                    }
                    else {
                        $CurrentCorData = [WDACConfig.CertificateDetailsCreator]::New(
                            $CorData.IssuerTBSHash,
                            $CorData.IssuerName,
                            $CorData.PublisherTBSHash,
                            $CorData.PublisherName
                        )
                    }

                    # Add the Certificate details to both the FilePublisherSignerCreator and PublisherSignerCreator objects
                    # Because later we will determine if the $CurrentData is suitable for FilePublisher or Publisher level
                    $CurrentFilePublisherSigner.CertificateDetails.Add($CurrentCorData)
                    $CurrentPublisherSigner.CertificateDetails.Add($CurrentCorData)
                }

                # If the file's version is empty or it has no file attribute, then add it to the Publishers array
                # because FilePublisher rule cannot be created for it
                if (
                    (
        ([System.String]::IsNullOrWhiteSpace($CurrentData.OriginalFileName)) -and
        ([System.String]::IsNullOrWhiteSpace($CurrentData.InternalName)) -and
        ([System.String]::IsNullOrWhiteSpace($CurrentData.FileDescription)) -and
        ([System.String]::IsNullOrWhiteSpace($CurrentData.ProductName))
                    ) -or (
           ([System.String]::IsNullOrWhiteSpace($CurrentData.FileVersion))
                    )
                ) {
                    # If the switch to pass Publisher rules to the hash array is not set, then add the current data to the Publisher array as expected
                    if (-NOT $PubLisherToHash) {
                        $CurrentPublisherSigner.FileName = $IncomingDataType -eq 'MDEAH' ? $CurrentData.FileName : $CurrentData.'File Name'
                        $CurrentPublisherSigner.AuthenticodeSHA256 = $IncomingDataType -eq 'MDEAH' ? $CurrentData.SHA256 : $CurrentData.'SHA256 Hash'
                        $CurrentPublisherSigner.AuthenticodeSHA1 = $IncomingDataType -eq 'MDEAH' ? $CurrentData.SHA1 : $CurrentData.'SHA1 Hash'
                        $CurrentPublisherSigner.SiSigningScenario = $IncomingDataType -eq 'MDEAH' ? $CurrentData.SiSigningScenario : ($CurrentData.'SI Signing Scenario' -eq 'Kernel-Mode' ? '0' : '1')
                        $PublisherSigners.Add($CurrentPublisherSigner)
                    }
                    # Otherwise, add the current data to the hash array instead despite being eligible for Publisher level
                    else {
                        Write-Verbose -Message "Build-SignerAndHashObjects: Passing Publisher rule to the hash array for the file: $($IncomingDataType -eq 'MDEAH' ? $CurrentData.FileName : $CurrentData.'File Name')"

                        # Add the new object to the CompleteHashes array
                        $CompleteHashes.Add([WDACConfig.HashCreator]::New(
                        ($IncomingDataType -eq 'MDEAH' ? $CurrentData.SHA256 : $CurrentData.'SHA256 Hash'),
                        ($IncomingDataType -eq 'MDEAH' ? $CurrentData.SHA1 : $CurrentData.'SHA1 Hash'),
                        ($IncomingDataType -eq 'MDEAH' ? $CurrentData.FileName : $CurrentData.'File Name'),
                        ($IncomingDataType -eq 'MDEAH' ? $CurrentData.SiSigningScenario : ($CurrentData.'SI Signing Scenario' -eq 'Kernel-Mode' ? '0' : '1'))
                            ))
                    }
                }

                # If the file has some of the necessary details for a FilePublisher rule then add it to the FilePublisher array
                else {
                    $CurrentFilePublisherSigner.FileVersion = $CurrentData.FileVersion
                    $CurrentFilePublisherSigner.FileDescription = $CurrentData.FileDescription
                    $CurrentFilePublisherSigner.InternalName = $CurrentData.InternalName
                    $CurrentFilePublisherSigner.OriginalFileName = $CurrentData.OriginalFileName
                    $CurrentFilePublisherSigner.ProductName = $CurrentData.ProductName
                    $CurrentFilePublisherSigner.FileName = $IncomingDataType -eq 'MDEAH' ? $CurrentData.FileName : $CurrentData.'File Name'
                    $CurrentFilePublisherSigner.AuthenticodeSHA256 = $IncomingDataType -eq 'MDEAH' ? $CurrentData.SHA256 : $CurrentData.'SHA256 Hash'
                    $CurrentFilePublisherSigner.AuthenticodeSHA1 = $IncomingDataType -eq 'MDEAH' ? $CurrentData.SHA1 : $CurrentData.'SHA1 Hash'
                    $CurrentFilePublisherSigner.SiSigningScenario = $IncomingDataType -eq 'MDEAH' ? $CurrentData.SiSigningScenario : ($CurrentData.'SI Signing Scenario' -eq 'Kernel-Mode' ? '0' : '1')

                    # Some checks to make sure the necessary details are not empty
                    if (([System.String]::IsNullOrWhiteSpace($IncomingDataType -eq 'MDEAH' ? $CurrentData.SHA256 : $CurrentData.'SHA256 Hash'))) {
                        Write-Warning "SHA256 is empty for the file: $($IncomingDataType -eq 'MDEAH' ? $CurrentData.FileName : $CurrentData.'File Name')"
                    }

                    if (([System.String]::IsNullOrWhiteSpace($IncomingDataType -eq 'MDEAH' ? $CurrentData.SHA1 : $CurrentData.'SHA1 Hash'))) {
                        Write-Warning "SHA1 is empty for the file: $($IncomingDataType -eq 'MDEAH' ? $CurrentData.FileName : $CurrentData.'File Name')"
                    }

                    # Add the new object to the FilePublisherSigners array
                    $FilePublisherSigners.Add($CurrentFilePublisherSigner)
                }
            }
        }

        if ($Null -ne $UnsignedData -and $UnsignedData.Count -gt 0) {

            # Processing the unsigned data
            Foreach ($HashData in $UnsignedData) {

                # Add the new object to the CompleteHashes array
                $CompleteHashes.Add([WDACConfig.HashCreator]::New(
                    ($IncomingDataType -eq 'MDEAH' ? $HashData.SHA256 : $HashData.'SHA256 Hash'),
                    ($IncomingDataType -eq 'MDEAH' ? $HashData.SHA1 : $HashData.'SHA1 Hash'),
                    ($IncomingDataType -eq 'MDEAH' ? $HashData.FileName : $HashData.'File Name'),
                    ($IncomingDataType -eq 'MDEAH' ? $HashData.SiSigningScenario : ($HashData.'SI Signing Scenario' -eq 'Kernel-Mode' ? '0' : '1'))
                    ))
            }
        }

    }
    End {
        # Return the created objects as nested properties of a single object
        Return [PSCustomObject]@{
            FilePublisherSigners = $FilePublisherSigners
            PublisherSigners     = $PublisherSigners
            CompleteHashes       = $CompleteHashes
        }
    }
}
Export-ModuleMember -Function 'Build-SignerAndHashObjects'
