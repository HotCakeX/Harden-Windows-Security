Function Get-CertificateDetails {
    <#
    .SYNOPSIS
        A function to detect Root, Intermediate and Leaf certificates
        It returns a compound object that contains 2 nested objects for Intermediate and Leaf certificates
    .INPUTS
        WDACConfig.AllCertificatesGrabber.AllFileSigners[]
    .OUTPUTS
        WDACConfig.ChainPackage[]
    .PARAMETER CompleteSignatureResult
    .NOTES
        Old method of recognizing the certificate type:
        If the file's subject common name is equal to the certificate's subject common name, then it's the leaf certificate - If a certificate's subject common name is equal to its issuer common name, then it's a root certificate - otherwise it's an intermediate certificate
        CertType    = ($SubjectCN -eq $IssuerCN) ? 'Root' : (($SubjectCN -eq $FileSubjectCN) ? 'Leaf' : 'Intermediate')
    #>
    [CmdletBinding()]
    [OutputType([WDACConfig.ChainPackage[]])]
    param (
        [Parameter(Mandatory = $true)][WDACConfig.AllCertificatesGrabber.AllFileSigners[]]$CompleteSignatureResult
    )
    Begin {
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        $FinalObject = New-Object -TypeName System.Collections.Generic.List[WDACConfig.ChainPackage]
    }

    process {

        # Loop over each signer of the file, in case the file has multiple separate signers
        for ($i = 0; $i -lt $CompleteSignatureResult.Count; $i++) {

            # Get the current chain and SignedCms of the signer
            [System.Security.Cryptography.X509Certificates.X509Chain]$CurrentChain = $CompleteSignatureResult.Chain[$i]
            [System.Security.Cryptography.Pkcs.SignedCms]$CurrentSignedCms = $CompleteSignatureResult.Signer[$i]

            [System.UInt32]$CertificatesInChainCount = $CurrentChain.ChainElements.Certificate.Count

            :ChainProcessLoop Switch ($CertificatesInChainCount) {

                # If the chain includes a Root, Leaf and at least one Intermediate certificate
                { $_ -gt 2 } {

                    # The last certificate in the chain is the Root certificate
                    [System.Security.Cryptography.X509Certificates.X509Certificate]$CurrentRootCertificate = $CurrentChain.ChainElements.Certificate[-1]

                    $RootCertificate = [WDACConfig.ChainElement]::New(
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentRootCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $false), # SubjectCN
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentRootCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $true), # IssuerCN
                        $CurrentRootCertificate.NotAfter,
                        [WDACConfig.CertificateHelper]::GetTBSCertificate($CurrentRootCertificate),
                        $CurrentRootCertificate, # Append the certificate object itself to the output object as well
                        [WDACConfig.CertificateType]::Root
                    )

                    # An array to hold the Intermediate Certificate(s) of the current chain
                    $IntermediateCertificates = New-Object -TypeName System.Collections.Generic.List[WDACConfig.ChainElement]

                    # All the certificates in between are Intermediate certificates
                    foreach ($Cert in $CurrentChain.ChainElements.Certificate[1..($CertificatesInChainCount - 2)]) {

                        # Create a collection of intermediate certificates
                        $IntermediateCertificates.Add([WDACConfig.ChainElement]::New(
                                [WDACConfig.CryptoAPI]::GetNameString($Cert.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $false),
                                [WDACConfig.CryptoAPI]::GetNameString($Cert.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $true),
                                $Cert.NotAfter,
                                [WDACConfig.CertificateHelper]::GetTBSCertificate($Cert) ,
                                $Cert, # Append the certificate object itself to the output object as well
                                [WDACConfig.CertificateType]::Intermediate
                            ))
                    }

                    # The first certificate in the chain is the Leaf certificate
                    [System.Security.Cryptography.X509Certificates.X509Certificate]$CurrentLeafCertificate = $CurrentChain.ChainElements.Certificate[0]

                    $LeafCertificate = [WDACConfig.ChainElement]::New(
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentLeafCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $false),
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentLeafCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $true),
                        $CurrentLeafCertificate.NotAfter,
                        [WDACConfig.CertificateHelper]::GetTBSCertificate($CurrentLeafCertificate),
                        $CurrentLeafCertificate, # Append the certificate object itself to the output object as well
                        [WDACConfig.CertificateType]::Leaf
                    )

                    $FinalObject.Add([WDACConfig.ChainPackage]::New(
                            $CurrentChain, # The entire current chain of the certificate
                            $CurrentSignedCms, # The entire current SignedCms object
                            $RootCertificate,
                            $IntermediateCertificates,
                            $LeafCertificate
                        ))

                    Break ChainProcessLoop
                }

                # If the chain only includes a Root and Leaf certificate
                { $_ -eq 2 } {

                    # The last certificate in the chain is the Root certificate
                    [System.Security.Cryptography.X509Certificates.X509Certificate]$CurrentRootCertificate = $CurrentChain.ChainElements.Certificate[-1]

                    $RootCertificate = [WDACConfig.ChainElement]::New(
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentRootCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $false), # SubjectCN
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentRootCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $true), # IssuerCN
                        $CurrentRootCertificate.NotAfter,
                        [WDACConfig.CertificateHelper]::GetTBSCertificate($CurrentRootCertificate),
                        $CurrentRootCertificate, # Append the certificate object itself to the output object as well
                        [WDACConfig.CertificateType]::Root
                    )

                    # The first certificate in the chain is the Leaf certificate
                    [System.Security.Cryptography.X509Certificates.X509Certificate]$CurrentLeafCertificate = $CurrentChain.ChainElements.Certificate[0]

                    $LeafCertificate = [WDACConfig.ChainElement]::New(
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentLeafCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $false),
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentLeafCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $true),
                        $CurrentLeafCertificate.NotAfter,
                        [WDACConfig.CertificateHelper]::GetTBSCertificate($CurrentLeafCertificate),
                        $CurrentLeafCertificate, # Append the certificate object itself to the output object as well
                        [WDACConfig.CertificateType]::Leaf
                    )

                    $FinalObject.Add([WDACConfig.ChainPackage]::New(
                            $CurrentChain, # The entire current chain of the certificate
                            $CurrentSignedCms, # The entire current SignedCms object
                            $RootCertificate,
                            $null,
                            $LeafCertificate
                        ))

                    break ChainProcessLoop
                }

                # If the chain only includes a Root certificate
                { $_ -eq 1 } {

                    # The only certificate in the chain is the Root certificate
                    [System.Security.Cryptography.X509Certificates.X509Certificate]$CurrentRootCertificate = $CurrentChain.ChainElements.Certificate

                    $RootCertificate = [WDACConfig.ChainElement]::New(
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentRootCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $false), # SubjectCN
                        [WDACConfig.CryptoAPI]::GetNameString($CurrentRootCertificate.Handle, [WDACConfig.CryptoAPI]::CERT_NAME_SIMPLE_DISPLAY_TYPE, $null, $true), # IssuerCN
                        $CurrentRootCertificate.NotAfter,
                        [WDACConfig.CertificateHelper]::GetTBSCertificate($CurrentRootCertificate),
                        $CurrentRootCertificate, # Append the certificate object itself to the output object as well
                        [WDACConfig.CertificateType]::Root
                    )

                    $FinalObject.Add([WDACConfig.ChainPackage]::New(
                            $CurrentChain, # The entire current chain of the certificate
                            $CurrentSignedCms, # The entire current SignedCms object
                            $RootCertificate,
                            $null,
                            $null
                        ))

                    break ChainProcessLoop
                }
            }
        }
    }
    End {
        return $FinalObject
    }
}
Export-ModuleMember -Function 'Get-CertificateDetails'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD7MtNwsYMAIyzI
# 355PLU/hpCGEUZiHn+TW/xeo3cYnRqCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgaIFAXbfJlEFsPRuLcp08JFuuzrKYWowKnePE6pV1WE0wDQYJKoZIhvcNAQEB
# BQAEggIATLHCoYK9nAZE6jBZcdykb6OlZyFkeJzN4y0bXeu0zutduWCVDpZbqpwg
# ZrM299l9oKIZGQ+F0vaF5EZR+jnGudALVgWjNb4Ag6QjIutSrXob31rEfryauGL0
# iKnIkksSbKMNNF4vivkN0nkz1rDwUz4W55fmDAK1RQ9OSHz2yXMiFr5nMHi5d+rn
# TAA57cSqb8y5sbwo3kpiZZ0BCfEyiU3RojWHty5zexi6PxK20HyyAnRBDpqjTvSU
# ZwNPjTbjYUhK3FusmADWNfw+BKwwkCG1G4zVMHmGTsPO0bY7x2+h1dK/6EeQxyV2
# wTcivGXB+QA2Ldw6046PoiAYsA0sGbZFGrCf4am3GRxCfKMYemQxHm55tVqX9wrC
# /sc1fKcLqBpbWtBrj3CIW3x7OXS0flS9lSQGQtAVZKQU+3Gw5ME7RtDm98ZxZibQ
# AorLCBbaGxujxMuYm0X+1DVchNAwJ5VITYl7o7wn+uKPdZHLvMschzju4gWIFJu/
# 7J9MGBkrMp+VXyBhGpooaHD/DnfvBDmlfZhZ/08aBfCAa+FngYpxo0abs4kmg32j
# O5HCCMCWsc8tv1K2o7gs0IFbSE9A4W9I9aqMoNKEuKJozyvn2LLxZzC2OQ3TGtYP
# mm62AOna4OPYqlJGxINJYKwwGcASJl8hCXF/IpXNFkJPp+p+6/M=
# SIG # End signature block
