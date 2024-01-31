Function Get-CertificateDetails {
    <#
    .SYNOPSIS
        A function to detect Root, Intermediate and Leaf certificates
        It returns a compound object that contains 2 nested objects for Intermediate and Leaf certificates
    .INPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2
        System.IO.FileInfo
        System.String
    .OUTPUTS
        System.Object[]
    .PARAMETER FilePath
        Path to a signed file
    .PARAMETER X509Certificate2
        An X509Certificate2 object
    .PARAMETER LeafCNOfTheNestedCertificate
        This is used only for when -X509Certificate2 parameter is used, so that we can filter out the Leaf certificate and only get the Intermediate certificates at the end of this function
    #>
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param (
        [Parameter(ParameterSetName = 'Based on File Path', Mandatory = $true)]
        [System.IO.FileInfo]$FilePath,

        [Parameter(ParameterSetName = 'Based on Certificate', Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$X509Certificate2,

        [Parameter(ParameterSetName = 'Based on Certificate')]
        [System.String]$LeafCNOfTheNestedCertificate
    )

    begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Importing the required sub-modules
        Import-Module -FullyQualifiedName "$ModuleRootPath\WDACSimulation\Get-TBSCertificate.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\WDACSimulation\Get-SignedFileCertificates.psm1" -Force

        if ($FilePath) {
            # Get all the certificates from the file path using the Get-SignedFileCertificates function
            [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$CertCollection = Get-SignedFileCertificates -FilePath $FilePath | Where-Object -FilterScript { $_.EnhancedKeyUsageList.FriendlyName -ne 'Time Stamping' }
        }
        elseif ($X509Certificate2) {
            # The "| Where-Object -FilterScript {$_ -ne 0}" part is used to filter the output coming from Get-AuthenticodeSignatureEx function that gets nested certificate
            [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$CertCollection = Get-SignedFileCertificates -X509Certificate2 $X509Certificate2 | Where-Object -FilterScript { ($_.EnhancedKeyUsageList.FriendlyName -ne 'Time Stamping') -and ($_ -ne 0) }
        }
        else {
            throw 'Either FilePath or X509Certificate2 parameter must be specified'
        }
    }

    process {

        # An array to hold certificate elements objects
        [System.Object[]]$Obj = @()

        # Loop through each certificate in the collection and call this function recursively with the certificate object as an input
        foreach ($Cert in $CertCollection) {

            # Build the certificate chain
            [System.Security.Cryptography.X509Certificates.X509Chain]$Chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain

            # Set the chain policy properties

            # https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509revocationmode
            $chain.ChainPolicy.RevocationMode = 'NoCheck'

            # https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509revocationflag
            $chain.ChainPolicy.RevocationFlag = 'EndCertificateOnly'

            # https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509verificationflags
            $Chain.ChainPolicy.VerificationFlags = 'NoFlag'

            [System.Void]$Chain.Build($Cert)

            # Verify the certificate using the base policy
            [System.Boolean]$Result = $Cert.Verify()

            if ($Result -ne $true) {
                Write-Verbose -Message "WARNING: The certificate $($Cert.Subject) is not valid"
            }

            # Loop through all chain elements and display all certificates
            foreach ($Element in $Chain.ChainElements) {

                # Extract the data after CN= in the subject and issuer properties
                # When a common name contains a comma ',' then it will automatically be wrapped around double quotes. E.g., "App Software USA, Inc."
                # The methods below are conditional regex. Different patterns are used based on the availability of at least one double quote in the CN field, indicating that it had comma in it so it had been enclosed with double quotes by system

                $Element.Certificate.Subject -match 'CN=(?<InitialRegexTest2>.*?),.*' | Out-Null
                [System.String]$SubjectCN = $matches['InitialRegexTest2'] -like '*"*' ? ($Element.Certificate.Subject -split 'CN="(.+?)"')[1] : $matches['InitialRegexTest2']

                $Element.Certificate.Issuer -match 'CN=(?<InitialRegexTest3>.*?),.*' | Out-Null
                [System.String]$IssuerCN = $matches['InitialRegexTest3'] -like '*"*' ? ($Element.Certificate.Issuer -split 'CN="(.+?)"')[1] : $matches['InitialRegexTest3']

                # Get the TBS value of the certificate
                [System.String]$TbsValue = Get-TBSCertificate -cert $Element.Certificate

                # Create a custom object with the extracted properties and the TBS value and add it to the array
                $Obj += [pscustomobject]@{
                    SubjectCN = $SubjectCN
                    IssuerCN  = $IssuerCN
                    NotAfter  = $element.Certificate.NotAfter
                    TBSValue  = $TbsValue
                }
            }
        }

        # An object to hold the final output that will be returned by the function
        $FinalObj = [PSCustomObject]@{}

        # An array to hold the Intermediate certificates
        $IntermediateCerts = @()

        if ($FilePath) {

            #Region Intermediate-Certificates-Processing

            # The reason the commented code below is not used is because some files such as C:\Windows\System32\xcopy.exe or d3dcompiler_47.dll that are signed by Microsoft report a different Leaf certificate common name when queried using Get-AuthenticodeSignature
            # (Get-AuthenticodeSignature -FilePath $FilePath).SignerCertificate.Subject -match 'CN=(?<InitialRegexTest4>.*?),.*' | Out-Null

            [System.Security.Cryptography.X509Certificates.X509Certificate]$CertificateUsingAlternativeMethod = [System.Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($FilePath)
            $CertificateUsingAlternativeMethod.Subject -match 'CN=(?<InitialRegexTest4>.*?),.*' | Out-Null

            [System.String]$TestAgainst = $matches['InitialRegexTest4'] -like '*"*' ? ((Get-AuthenticodeSignature -FilePath $FilePath).SignerCertificate.Subject -split 'CN="(.+?)"')[1] : $matches['InitialRegexTest4']

            # ($_.SubjectCN -ne $_.IssuerCN) -> To omit Root certificate from the result
            # ($_.SubjectCN -ne $TestAgainst) -> To omit the Leaf certificate
            $Obj | Where-Object -FilterScript { ($_.SubjectCN -ne $_.IssuerCN) -and ($_.SubjectCN -ne $TestAgainst) } |

            # To make sure the output values are unique based on TBSValue property
            Group-Object -Property TBSValue | ForEach-Object -Process { $_.Group[0] } |

            # Add each intermediate certificate to the nested object of the final object
            ForEach-Object -Process {
                $IntermediateCerts += [PSCustomObject]@{
                    SubjectCN = $_.SubjectCN
                    IssuerCN  = $_.IssuerCN
                    NotAfter  = $_.NotAfter
                    TBSValue  = $_.TbsValue
                }
            }

            Write-Verbose -Message "The Primary Signer's Root Certificate common name is: $($($Obj | Where-Object -FilterScript { ($_.SubjectCN -eq $_.IssuerCN) }).SubjectCN | Select-Object -First 1)"
            Write-Verbose -Message "The Primary Signer has $($IntermediateCerts.Count) Intermediate certificate(s) with the following common name(s): $($IntermediateCerts.SubjectCN -join ', ')"

            # Add the $IntermediateCerts object to the final object
            Add-Member -InputObject $FinalObj -MemberType NoteProperty -Name 'IntermediateCertificates' -Value $IntermediateCerts
            #Endregion Intermediate-Certificates-Processing

            #Region Leaf-Certificate-Processing

            # ($_.SubjectCN -ne $_.IssuerCN) -> To omit Root certificate from the result
            # ($_.SubjectCN -eq $TestAgainst) -> To get the Leaf certificate
            $TempLeafCertObj = $Obj | Where-Object -FilterScript { ($_.SubjectCN -ne $_.IssuerCN) -and ($_.SubjectCN -eq $TestAgainst) } |

            # To make sure the output values are unique based on TBSValue property
            Group-Object -Property TBSValue | ForEach-Object -Process { $_.Group[0] }

            $LeafCert = [PSCustomObject]@{
                SubjectCN = $TempLeafCertObj.SubjectCN
                IssuerCN  = $TempLeafCertObj.IssuerCN
                NotAfter  = $TempLeafCertObj.NotAfter
                TBSValue  = $TempLeafCertObj.TbsValue
            }

            Write-Verbose -Message "The Primary Signer has $($TempLeafCertObj.Count) Leaf certificate with the following common name: $($TempLeafCertObj.SubjectCN -join ', ')"

            # Add the $LeafCert object to the final object
            Add-Member -InputObject $FinalObj -MemberType NoteProperty -Name 'LeafCertificate' -Value $LeafCert
            #Endregion Leaf-Certificate-Processing
        }

        # If nested certificate is being processed and X509Certificate2 object is passed
        elseif ($X509Certificate2) {

            #Region Intermediate-Certificates-Processing

            # ($_.SubjectCN -ne $_.IssuerCN) -> To omit Root certificate from the result
            # ($_.SubjectCN -ne $LeafCNOfTheNestedCertificate) -> To omit the Leaf certificate
            $Obj | Where-Object -FilterScript { ($_.SubjectCN -ne $_.IssuerCN) -and ($_.SubjectCN -ne $LeafCNOfTheNestedCertificate) } |
            # To make sure the output values are unique based on TBSValue property

            Group-Object -Property TBSValue | ForEach-Object -Process { $_.Group[0] } |
            # Add each intermediate certificate to the nested object of the final object

            ForEach-Object -Process {
                $IntermediateCerts += [PSCustomObject]@{
                    SubjectCN = $_.SubjectCN
                    IssuerCN  = $_.IssuerCN
                    NotAfter  = $_.NotAfter
                    TBSValue  = $_.TbsValue
                }
            }

            Write-Verbose -Message "The Nested Signer's Root Certificate common name is: $($($Obj | Where-Object -FilterScript { ($_.SubjectCN -eq $_.IssuerCN) }).SubjectCN | Select-Object -First 1)"
            Write-Verbose -Message "The Nested Signer has $($IntermediateCerts.Count) Intermediate certificate(s) with the following common name(s): $($IntermediateCerts.SubjectCN -join ', ')"

            # Add the $IntermediateCerts object to the final object
            Add-Member -InputObject $FinalObj -MemberType NoteProperty -Name 'IntermediateCertificates' -Value $IntermediateCerts

            #Endregion Intermediate-Certificates-Processing

            #Region Leaf-Certificate-Processing

            # ($_.SubjectCN -ne $_.IssuerCN) -> To omit Root certificate from the result
            # ($_.SubjectCN -eq $LeafCNOfTheNestedCertificate) -> To get the Leaf certificate
            $TempLeafCertObj = $Obj | Where-Object -FilterScript { ($_.SubjectCN -ne $_.IssuerCN) -and ($_.SubjectCN -eq $LeafCNOfTheNestedCertificate) } |

            # To make sure the output values are unique based on TBSValue property
            Group-Object -Property TBSValue | ForEach-Object -Process { $_.Group[0] }

            $LeafCert = [PSCustomObject]@{
                SubjectCN = $TempLeafCertObj.SubjectCN
                IssuerCN  = $TempLeafCertObj.IssuerCN
                NotAfter  = $TempLeafCertObj.NotAfter
                TBSValue  = $TempLeafCertObj.TbsValue
            }

            Write-Verbose -Message "The Nested Signer has $($TempLeafCertObj.Count) Leaf certificate with the following common name: $($TempLeafCertObj.SubjectCN -join ', ')"

            # Add the $LeafCert object to the final object
            Add-Member -InputObject $FinalObj -MemberType NoteProperty -Name 'LeafCertificate' -Value $LeafCert

            #Endregion Leaf-Certificate-Processing
        }
    }

    end {
        # Return the final object with the 2 nested objects
        return [System.Object[]]$FinalObj
    }
}
Export-ModuleMember -Function 'Get-CertificateDetails'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAzzkVVTDsHAs+K
# bGafDF9311OKEkdqfK8qIAx4A23ZG6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgApkCgiOQNV6twxG0bcP8pMift/Yu4/WAYzoIwfHBYl8wDQYJKoZIhvcNAQEB
# BQAEggIAjdx77xxnXXNrpOOW7PijgD4VACkdP4tYNVxvQh/lDpguEHZqM4jWZAD+
# ntASShKb4g6Fi1tNfsZFPi7KrDo8HGynwf08Pn905WejCGGTIM8PBLTiONaSxXHQ
# QeNshkR2uEoVc5tTikOS9Ol7Wu7baDYsRSBj+2gLuBoXYaUJ+cz08z9ZGo3YyEbc
# f9VzpCKlTuOdkSlRsUEWW6OziWIOaGP+Xj5gn43Jdx6ttPJMQneZXtAtDa33vVDn
# nTvMRaGo7YBZWFVTDz62cNqXsU17SxaW+Gu3iNibDomOJX/rVvbjGs+iMTI2hwZx
# XnsSbUM2gX4WrFMg+vL4772qerGpRebd4KhIKRETgY9tjwWmlecSyLa/dnM837Sm
# 8QA48yJh28G51Qvii0GEWO6+vRQk0Z9fvHiDcFoN8o+hVBN+JxUukOW0Qe+tqwzg
# 8+5Dh9qOQf+iwdrvMLZmJ1RBGxVoLxb4BAE4qj29Uwq/4SgGHsnjlhu/94mnWoF6
# 1UUEmnSNFjtU6vHB8XbKMsDnZqxSigrTEH0Ojj9481pfuffRlv5z2GOzXyo+Gvl1
# AyDcAJpZ5HKICWSZzUAYpKp84J7K76HdQkC0BvJNL5yKNpahV/S5Iff4KROqqz5m
# k2x1XqNoZ5162NffYPiSOFznB7SpLfXdyQQVV/wxQ/NtvJ5PQp4=
# SIG # End signature block
