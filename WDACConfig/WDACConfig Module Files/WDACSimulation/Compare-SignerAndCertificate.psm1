# Importing the $PSDefaultParameterValues to the current session, prior to everything else
. "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

# Defining the Signer class from the WDACConfig Namespace if it doesn't already exist
if (-NOT ('WDACConfig.Signer' -as [System.Type]) ) {
    Add-Type -Path "$ModuleRootPath\C#\Signer.cs"
}

# Importing the required sub-modules
Import-Module -FullyQualifiedName "$ModuleRootPath\WDACSimulation\Get-SignerInfo.psm1" -Force
Import-Module -FullyQualifiedName "$ModuleRootPath\WDACSimulation\Get-AuthenticodeSignatureEx.psm1" -Force
Import-Module -FullyQualifiedName "$ModuleRootPath\WDACSimulation\Get-CertificateDetails.psm1" -Force

Function Compare-SignerAndCertificate {
    <#
    .SYNOPSIS
        a function that takes WDAC XML policy file path and a Signed file path as inputs and compares the output of the Get-SignerInfo and Get-CertificateDetails functions
    .INPUTS
        System.String
    .OUTPUTS
        System.Object[]
    .PARAMETER XmlFilePath
        Path to a WDAC XML file
    .PARAMETER SignedFilePath
        Path to a signed file
    #>
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)][System.String]$XmlFilePath,
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$SignedFilePath
    )

    # Get the signer information from the XML file path using the Get-SignerInfo function
    [WDACConfig.Signer[]]$SignerInfo = Get-SignerInfo -XmlFilePath $XmlFilePath

    # An array to store the final comparison results of this function
    [System.Object[]]$ComparisonResults = @()

    # Get details of the intermediate and leaf certificates of the primary certificate of the signed file
    [System.Object[]]$AllPrimaryCertificateDetails = Get-CertificateDetails -FilePath $SignedFilePath

    # Store the intermediate certificate(s) details of the Primary certificate of the signed file
    [System.Object[]]$PrimaryCertificateIntermediateDetails = $AllPrimaryCertificateDetails.IntermediateCertificates

    # Get the Nested (Secondary) certificate of the signed file, if any
    [System.Management.Automation.Signature]$ExtraCertificateDetails = Get-AuthenticodeSignatureEx -FilePath $SignedFilePath

    # Extract the Nested (Secondary) certificate from the nested property, if any
    $NestedCertificate = ($ExtraCertificateDetails).NestedSignature.SignerCertificate

    if ($null -ne [System.Security.Cryptography.X509Certificates.X509Certificate2]$NestedCertificate) {
        # First get the CN of the leaf certificate of the nested Certificate
        $NestedCertificate.Subject -match 'CN=(?<InitialRegexTest1>.*?),.*' | Out-Null
        $LeafCNOfTheNestedCertificate = $matches['InitialRegexTest1'] -like '*"*' ? ($NestedCertificate.Subject -split 'CN="(.+?)"')[1] : $matches['InitialRegexTest1']

        Write-Verbose -Message 'Found a nested Signer in the file'

        # Send the nested certificate along with its Leaf certificate's CN to the Get-CertificateDetails function in order to get the intermediate and leaf certificates details of the Nested certificate
        [System.Object[]]$AllNestedCertificateDetails = Get-CertificateDetails -X509Certificate2 $NestedCertificate -LeafCNOfTheNestedCertificate $LeafCNOfTheNestedCertificate

        # Store the intermediate certificate(s) details of the Nested certificate from the signed file
        [System.Object[]]$NestedCertificateDetails = $AllNestedCertificateDetails.IntermediateCertificates
    }

    # Get the leaf certificate details of the Main Certificate from the signed file path
    [System.Object]$LeafCertificateDetails = $AllPrimaryCertificateDetails.LeafCertificate

    # Get the leaf certificate details of the Nested Certificate from the signed file path, if it exists
    if ($null -ne $NestedCertificate) {
        # append an X509Certificate2 object to the array
        [System.Object]$NestedLeafCertificateDetails = $AllNestedCertificateDetails.LeafCertificate
    }

    # Loop through each signer in the signer information array
    foreach ($Signer in $SignerInfo) {
        # Create a custom object to store the comparison result for this signer
        $ComparisonResult = [pscustomobject]@{
            SignerID            = $Signer.ID
            SignerName          = $Signer.Name
            SignerCertRoot      = $Signer.CertRoot
            SignerCertPublisher = $Signer.CertPublisher
            CertSubjectCN       = $null
            CertIssuerCN        = $null
            CertNotAfter        = $null
            CertTBSValue        = $null
            CertRootMatch       = $false
            CertNameMatch       = $false
            CertPublisherMatch  = $false
            FilePath            = $SignedFilePath # Add the file path to the object
        }

        # Loop through each certificate in the certificate details array of the Main Cert
        foreach ($Certificate in $PrimaryCertificateIntermediateDetails) {

            # Check if the signer's CertRoot (referring to the TBS value in the xml file which belongs to an intermediate cert of the file)...
            # ...matches the TBSValue of the file's certificate (TBS values of one of the intermediate certificates of the file since -IntermediateOnly parameter is used earlier and that's what FilePublisher level uses)
            # So this checks to see if the Signer's TBS value in xml matches any of the TBS value(s) of the file's intermediate certificate(s), if it does, that means that file is allowed to run by the WDAC engine

            # Or if the Signer's CertRoot matches the TBS value of the file's primary certificate's Leaf Certificate
            # This can happen with other rules than FilePublisher etc.
            if (($Signer.CertRoot -eq $Certificate.TBSValue) -or ($Signer.CertRoot -eq $LeafCertificateDetails.TBSValue)) {

                # Assign the certificate properties to the comparison result object and set the CertRootMatch to true based on further conditions
                $ComparisonResult.CertSubjectCN = $Certificate.SubjectCN
                $ComparisonResult.CertIssuerCN = $Certificate.IssuerCN
                $ComparisonResult.CertNotAfter = $Certificate.NotAfter
                $ComparisonResult.CertTBSValue = $Certificate.TBSValue

                # if the signed file has nested certificate, only set a flag instead of setting the entire CertRootMatch property to true
                if ($null -ne $NestedCertificate) {
                    $CertRootMatchPart1 = $true
                }
                else {
                    # meaning one of the TBS values of the file's intermediate certs or File's Primary Leaf Certificate's TBS value is in the xml file signers' TBS values
                    $ComparisonResult.CertRootMatch = $true
                }

                # Check if the signer's name (Referring to the one in the XML file) matches the Intermediate certificate's SubjectCN or Leaf Certificate's SubjectCN
                if (($Signer.Name -eq $Certificate.SubjectCN) -or ($Signer.Name -eq $LeafCertificateDetails.SubjectCN)) {
                    # Set the CertNameMatch to true
                    $ComparisonResult.CertNameMatch = $true # this should naturally be always true like the CertRootMatch because this is the CN of the same cert that has its TBS value in the xml file in signers
                }

                # Check if the signer's CertPublisher (aka Leaf Certificate's CN used in the xml policy) matches the leaf certificate's SubjectCN (of the file)
                if ($Signer.CertPublisher -eq $LeafCertificateDetails.SubjectCN) {

                    # if the signed file has nested certificate, only set a flag instead of setting the entire CertPublisherMatch property to true
                    if ($null -ne $NestedCertificate) {
                        $CertPublisherMatchPart1 = $true
                    }
                    else {
                        $ComparisonResult.CertPublisherMatch = $true
                    }
                }

                # Break out of the inner loop whether we found a match for this signer or not
                break
            }
        }

        # Nested Certificate TBS processing, if it exists
        if ($null -ne $NestedCertificate) {

            # Loop through each certificate in the NESTED certificate details array
            foreach ($Certificate in $NestedCertificateDetails) {

                # Check if the signer's CertRoot (referring to the TBS value in the xml file which belongs to an intermediate cert of the file)...
                # ...matches the TBSValue of the file's certificate (TBS values of one of the intermediate certificates of the file since -IntermediateOnly parameter is used earlier and that's what FilePublisher level uses)
                # So this checks to see if the Signer's TBS value in xml matches any of the TBS value(s) of the file's intermediate certificate(s), if yes, that means that file is allowed to run by WDAC engine
                if ($Signer.CertRoot -eq $Certificate.TBSValue) {

                    # Assign the certificate properties to the comparison result object and set the CertRootMatch to true
                    $ComparisonResult.CertSubjectCN = $Certificate.SubjectCN
                    $ComparisonResult.CertIssuerCN = $Certificate.IssuerCN
                    $ComparisonResult.CertNotAfter = $Certificate.NotAfter
                    $ComparisonResult.CertTBSValue = $Certificate.TBSValue

                    # When file has nested signature, only set a flag instead of setting the entire property to true
                    $CertRootMatchPart2 = $true

                    # Check if the signer's Name matches the Intermediate certificate's SubjectCN
                    if ($Signer.Name -eq $Certificate.SubjectCN) {
                        # Set the CertNameMatch to true
                        $ComparisonResult.CertNameMatch = $true # this should naturally be always true like the CertRootMatch because this is the CN of the same cert that has its TBS value in the xml file in signers
                    }

                    # Check if the signer's CertPublisher (aka Leaf Certificate's CN used in the xml policy) matches the leaf certificate's SubjectCN (of the file)
                    if ($Signer.CertPublisher -eq $LeafCNOfTheNestedCertificate) {
                        # If yes, set the CertPublisherMatch to true for this comparison result object
                        $CertPublisherMatchPart2 = $true
                    }

                    # Break out of the inner loop whether we found a match for this signer or not
                    break
                }
            }
        }

        # if the signed file has nested certificate
        if ($null -ne $NestedCertificate) {

            # check if both of the file's certificates (Nested and Main) are available in the Signers in xml policy
            if (($CertRootMatchPart1 -eq $true) -and ($CertRootMatchPart2 -eq $true)) {
                $ComparisonResult.CertRootMatch = $true # meaning all of the TBS values of the double signed file's intermediate certificates exists in the xml file's signers' TBS values
            }
            else {
                $ComparisonResult.CertRootMatch = $false
            }

            # check if Lean certificate CN of both of the file's certificates (Nested and Main) are available in the Signers in xml policy
            if (($CertPublisherMatchPart1 -eq $true) -and ($CertPublisherMatchPart2 -eq $true)) {
                $ComparisonResult.CertPublisherMatch = $true
            }
            else {
                $ComparisonResult.CertPublisherMatch = $false
            }
        }

        # Add the comparison result object to the comparison results array
        [System.Object[]]$ComparisonResults += $ComparisonResult
    }

    # Return the comparison results array
    return $ComparisonResults

}
Export-ModuleMember -Function 'Compare-SignerAndCertificate'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCvuiEJytKN8qXu
# ytFUPrHuI3rzBTnYp2ALPtB+lh/YRaCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgSP278Izb8DVEjuAV6pzSBLKB8XSdyeT/LV+IqDlydGQwDQYJKoZIhvcNAQEB
# BQAEggIAHYddwFtQCOzZpHF4id8ROoNagpAdA9ycNX8XkNakhbbpkD9h8ZcWSOE8
# aecvuc1T33GkN8O9EG5rY+0pzYcJ/P8cSVGp5NS3OQzURcrxDli3hGZW/SXPJhK0
# p6iYeCkhFsaCqFtWWixQG1u0ivtkA9BEmXyrtkyHV6oalfP3xmLuzuPIo6WGb26/
# B5BsxIn5tiNM1IjBYwo5YTCtBnubXy6mwf+CzHrVHuCQV+MZeGFIxLLYY/yKYu09
# 6m0tgWBWxDhx9/Ej1FqoAhlauyAHerQPn06TouSw2xHvGTx//wy92I74Y32y481v
# +oFoNjKX477eWwzn5gPKM0D6PrWw/QT1ppR1+NCPia7Hi9fozAb28bBeLJKjExLU
# 8VuH/LDIypCt57IkQsF9tLT8WnBj0w4zXYWlK4Xj9IkFNADbkKcb6gDGOCpOziaP
# XMQ0t7kZLkkJw4A0QgYhmkHSsW4KLmx+9/OrCe0KrWZFxOfCY8DNnK+G6FEjuldV
# KaauM17WN1ZSgRf3DJ4Hrl4+Rd3+QwLvToFVe0LND7gnIQGAF3n3JquT3dbOK/qT
# PQsRnLbiKCu0tN8uO8zghi+CvCAO1UHqTIvosG92AT+DJlz1d7fOB/BMVpVSI9P7
# t7SnXNQhZzh7qFX0C+BueyMQZ00/6/d7W8kudxvyysNv5gwVbFU=
# SIG # End signature block
