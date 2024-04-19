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
        [Parameter(Mandatory = $false)][System.String]$IncomingDataType
    )
    Begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

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

        # Defining the arrays to store the signed and unsigned data
        [PSCustomObject[]]$SignedData = @()
        [PSCustomObject[]]$UnsignedData = @()

        # Loop through the data and separate the signed and unsigned data
        foreach ($Item in $Data) {
            if ($Item.SignatureStatus -eq 'Signed') {
                $SignedData += $Item
            }
            else {
                $UnsignedData += $Item
            }
        }
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
                foreach ($CorData in ($IncomingDataType -eq 'MDEAH' ? $CurrentData.CorrelatedEventsData.Values : $CurrentData.SignerInfo.Values)) {

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

                        Write-Warning -Message "Intermediate Certificate TBS hash is empty for the file: $($IncomingDataType -eq 'MDEAH' ? $CurrentData.FileName : $CurrentData.'File Name'), using the leaf certificate TBS hash instead"

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
                    $CurrentPublisherSigner.FileName = $IncomingDataType -eq 'MDEAH' ? $CurrentData.FileName : $CurrentData.'File Name'
                    $CurrentPublisherSigner.AuthenticodeSHA256 = $IncomingDataType -eq 'MDEAH' ? $CurrentData.SHA256 : $CurrentData.'SHA256 Hash'
                    $CurrentPublisherSigner.AuthenticodeSHA1 = $IncomingDataType -eq 'MDEAH' ? $CurrentData.SHA1 : $CurrentData.'SHA1 Hash'
                    $CurrentPublisherSigner.SiSigningScenario = $IncomingDataType -eq 'MDEAH' ? $CurrentData.SiSigningScenario : ($CurrentData.'SI Signing Scenario' -eq 'Kernel-Mode' ? '0' : '1')
                    $PublisherSigners += $CurrentPublisherSigner
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
                $CurrentHash.AuthenticodeSHA256 = $IncomingDataType -eq 'MDEAH' ? $HashData.SHA256 : $HashData.'SHA256 Hash'
                $CurrentHash.AuthenticodeSHA1 = $IncomingDataType -eq 'MDEAH' ? $HashData.SHA1 : $HashData.'SHA1 Hash'
                $CurrentHash.FileName = $IncomingDataType -eq 'MDEAH' ? $HashData.FileName : $HashData.'File Name'
                $CurrentHash.SiSigningScenario = $IncomingDataType -eq 'MDEAH' ? $HashData.SiSigningScenario : ($HashData.'SI Signing Scenario' -eq 'Kernel-Mode' ? '0' : '1')

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
Export-ModuleMember -Function 'Build-SignerAndHashObjects'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCBjfSTCPR8lxdR
# D1Pd4OZEQVQpd/fIjlehp65GLp00j6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQge9/vjiEobgoKkZ2Fbr9O84FUXZpRh53RBX/FsQl8H9EwDQYJKoZIhvcNAQEB
# BQAEggIATUI4JK8zOb0YNETHq+53Xc6GuMHsc0cTHOEpBsBJFiZEbirpxGzL0gPP
# 0yPBqUksFfo/sGcVOQLijyyRkRO4gSXp8qkQohLxTE7bJE6ql1PMXsilQ316u8Cp
# GIOxhILAxfKfNxbMmxun8xf/FgC9F+G1a0C2CsaB2FHSDCLmEXgIjuUhw8dq+0/5
# hnFNlr3d6ymiL5iU3g8vk4X19RwiYojKNSLc26rbM6vpIgGnBTCZ6Y87f4GfGNpT
# b//6RpRuy8yxCy2dDY3E5ikj8xyJmJ/Uth8Y0sbVddVkIzkRtl2iQNQ2OmnysLs7
# KKxFo/0qHMQS4vL2gv7lW41Wr5KIj39NnVPpM0weIlL3GMH3Nc80ar6JOikA8GDc
# IPOdnHzekNunZn3SriwWUNG0j6GHCSgh3I4LJmBFsRlu8BLJ4iCxGv0UYlWsiC9B
# pk/F741tspWe5t+Xp5gefHeyrRMd1OQko51h2jgDL5rkKB2a7XJgUVMHP4D18PEQ
# N3W3n0bm15/y3qHQ5Gwxhfwjj1I6fO+Gf+DotxYXnGBIG1w7pyxqvSLikdaHKCgq
# grvSzL5sF51NQCW2Ccml24m5dLwulAhJTcMSHvfQX9qyWJpxANaaMeZNhJAB9lsJ
# 206pdAvv7oWRUWuxduvYAz6D399csJb5mGeSnq2zWUqhrlvqZKg=
# SIG # End signature block
