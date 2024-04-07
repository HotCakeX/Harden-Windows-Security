Function Build-SignerAndHashObjects {
    <#
    .SYNOPSIS
        Creates Signer and Hash objects from the signed and unsigned data
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
    .PARAMETER SignedData
        The signed data to be processed
    .PARAMETER UnsignedData
        The unsigned data to be processed
    .INPUTS
        PSCustomObject[]
    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $false)][PSCustomObject[]]$SignedData,
        [Parameter(Mandatory = $false)][PSCustomObject[]]$UnsignedData
    )
    Begin {

        Class CertificateDetailsCreator {
            [System.String]$IntermediateCertTBS
            [System.String]$IntermediateCertName
            [System.String]$LeafCertTBS
            [System.String]$LeafCertName
        }

        Class FilePublisherSignerCreator {
            [CertificateDetailsCreator[]]$CertificateDetails
            [System.Version]$FileVersion
            [System.String]$FileDescription
            [System.String]$InternalName
            [System.String]$OriginalFileName
            [System.String]$PackageFamilyName
            [System.String]$ProductName
            [System.String]$FileName
            [System.String]$AuthenticodeSHA256
            [System.String]$AuthenticodeSHA1
            [System.Int32]$SiSigningScenario
        }

        Class PublisherSignerCreator {
            [CertificateDetailsCreator[]]$CertificateDetails
            [System.String]$FileName
            [System.String]$AuthenticodeSHA256
            [System.String]$AuthenticodeSHA1
            [System.Int32]$SiSigningScenario
        }

        Class HashCreator {
            [System.String]$AuthenticodeSHA256
            [System.String]$AuthenticodeSHA1
            [System.String]$FileName
            [System.Int32]$SiSigningScenario
        }

        # An array to store the Signers created with FilePublisher Level
        [FilePublisherSignerCreator[]]$FilePublisherSigners = @()

        # An array to store the Signers created with Publisher Level
        [PublisherSignerCreator[]]$PublisherSigners = @()

        # An array to store the FileAttributes created using Hash Level
        [HashCreator[]]$CompleteHashes = @()

    }

    Process {

        if ($Null -ne $SignedData -and $SignedData.Count -gt 0) {

            # Process the signed data
            Foreach ($CurrentData in $SignedData) {

                # Create a new FilePublisherSignerCreator object
                [FilePublisherSignerCreator]$CurrentFilePublisherSigner = New-Object -TypeName FilePublisherSignerCreator
                # Create a new PublisherSignerCreator object
                [PublisherSignerCreator]$CurrentPublisherSigner = New-Object -TypeName PublisherSignerCreator

                # Loop through each correlated event and process the certificate details
                foreach ($CorData in $CurrentData.CorrelatedEventsData) {

                    # Create a new CertificateDetailsCreator object to store the certificate details
                    [CertificateDetailsCreator]$CurrentCorData = New-Object -TypeName CertificateDetailsCreator

                    # Add the certificate details to the new object
                    $CurrentCorData.LeafCertTBS = $CorData.PublisherTBSHash
                    $CurrentCorData.LeafCertName = $CorData.PublisherName
                    $CurrentCorData.IntermediateCertTBS = $CorData.IssuerTBSHash
                    $CurrentCorData.IntermediateCertName = $CorData.IssuerName

                    # If the file doesn't have Issuer TBS hash (aka Intermediate certificate hash), use the leaf cert's TBS hash and CN instead (aka publisher TBS hash)
                    # This is according to the ConfigCI's workflow when encountering specific files
                    # MDE doesn't generate Issuer TBS hash for some files
                    # For those files, the FilePublisher rule will be created with the file's leaf Certificate details only (Publisher certificate)
                    if (([System.String]::IsNullOrWhiteSpace($CurrentCorData.IntermediateCertTBS)) -and (-NOT (([System.String]::IsNullOrWhiteSpace($CurrentCorData.LeafCertTBS))))) {

                        Write-Warning -Message "Intermediate Certificate TBS hash is empty for the file: $($CurrentData.FileName), using the leaf certificate TBS hash instead"

                        $CurrentCorData.IntermediateCertName = $CurrentCorData.LeafCertName

                        $CurrentCorData.IntermediateCertTBS = $CurrentCorData.LeafCertTBS

                    }

                    # Add the Certificate details to both the FilePublisherSignerCreator and PublisherSignerCreator objects
                    # Because later we will determine if the $CurrentData is suitable for FilePublisher or Publisher level
                    $CurrentFilePublisherSigner.CertificateDetails += $CurrentCorData
                    $CurrentPublisherSigner.CertificateDetails += $CurrentCorData
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
                    $CurrentPublisherSigner.FileName = $CurrentData.FileName
                    $CurrentPublisherSigner.AuthenticodeSHA256 = $CurrentData.SHA256
                    $CurrentPublisherSigner.AuthenticodeSHA1 = $CurrentData.SHA1
                    $CurrentPublisherSigner.SiSigningScenario = $CurrentData.SiSigningScenario

                    $PublisherSigners += $CurrentPublisherSigner
                }

                # If the file has some of the necessary details for a FilePublisher rule then add it to the FilePublisher array

                else {
                    $CurrentFilePublisherSigner.FileVersion = $CurrentData.FileVersion
                    $CurrentFilePublisherSigner.FileDescription = $CurrentData.FileDescription
                    $CurrentFilePublisherSigner.InternalName = $CurrentData.InternalName
                    $CurrentFilePublisherSigner.OriginalFileName = $CurrentData.OriginalFileName
                    $CurrentFilePublisherSigner.ProductName = $CurrentData.ProductName
                    $CurrentFilePublisherSigner.FileName = $CurrentData.FileName
                    $CurrentFilePublisherSigner.AuthenticodeSHA256 = $CurrentData.SHA256
                    $CurrentFilePublisherSigner.AuthenticodeSHA1 = $CurrentData.SHA1
                    $CurrentFilePublisherSigner.SiSigningScenario = $CurrentData.SiSigningScenario

                    # Some checks to make sure the necessary details are not empty
                    if (([System.String]::IsNullOrWhiteSpace($CurrentData.SHA256))) {
                        Write-Warning "SHA256 is empty for the file: $($CurrentData.FileName)"
                    }

                    if (([System.String]::IsNullOrWhiteSpace($CurrentData.SHA1))) {
                        Write-Warning "SHA1 is empty for the file: $($CurrentData.FileName)"
                    }

                    # Add the new object to the FilePublisherSigners array
                    $FilePublisherSigners += $CurrentFilePublisherSigner
                }
            }

        }

        if ($Null -ne $UnsignedData -and $UnsignedData.Count -gt 0) {

            # Processing the unsigned data
            Foreach ($HashData in $UnsignedData) {

                # Create a new HashCreator object
                [HashCreator]$CurrentHash = New-Object -TypeName HashCreator

                # Add the hash details to the new object
                $CurrentHash.AuthenticodeSHA256 = $HashData.SHA256
                $CurrentHash.AuthenticodeSHA1 = $HashData.SHA1
                $CurrentHash.FileName = $HashData.FileName
                $CurrentHash.SiSigningScenario = $HashData.SiSigningScenario

                # Add the new object to the CompleteHashes array
                $CompleteHashes += $CurrentHash
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