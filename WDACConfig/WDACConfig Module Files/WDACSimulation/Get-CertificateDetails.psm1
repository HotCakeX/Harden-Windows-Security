# Importing the $PSDefaultParameterValues to the current session, prior to everything else
. "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

# Importing the required sub-modules
Import-Module -FullyQualifiedName "$ModuleRootPath\WDACSimulation\Get-TBSCertificate.psm1" -Force
Import-Module -FullyQualifiedName "$ModuleRootPath\WDACSimulation\Get-SignedFileCertificates.psm1" -Force

Function Get-CertificateDetails {
    <#
    .SYNOPSIS
        A function to detect Root, Intermediate and Leaf certificates
    .INPUTS
        System.String
        System.Management.Automation.SwitchParameter
    .OUTPUTS
        System.Object[]
    .PARAMETER FilePath
        Path to a signed file
    .PARAMETER X509Certificate2
        An X509Certificate2 object
    .PARAMETER IntermediateOnly
        Indicates that the function will only return the Intermediate certificate details
    .PARAMETER LeafCertificate
        Indicates that the function will only return the Leaf certificate details
    .PARAMETER LeafCNOfTheNestedCertificate
        This is used only for when -X509Certificate2 parameter is used, so that we can filter out the Leaf certificate and only get the Intermediate certificates at the end of this function
    #>
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = 'Based on File Path', Mandatory = $true)]
        [System.String]$FilePath,

        [Parameter(ParameterSetName = 'Based on Certificate', Mandatory = $true)]
        $X509Certificate2,

        [Parameter(ParameterSetName = 'Based on Certificate')]
        [System.String]$LeafCNOfTheNestedCertificate,

        [Parameter(ParameterSetName = 'Based on File Path')]
        [Parameter(ParameterSetName = 'Based on Certificate')]
        [System.Management.Automation.SwitchParameter]$IntermediateOnly,

        [Parameter(ParameterSetName = 'Based on File Path')]
        [Parameter(ParameterSetName = 'Based on Certificate')]
        [System.Management.Automation.SwitchParameter]$LeafCertificate
    )

    # An array to hold objects
    [System.Object[]]$Obj = @()

    if ($FilePath) {
        # Get all the certificates from the file path using the Get-SignedFileCertificates function
        $CertCollection = Get-SignedFileCertificates -FilePath $FilePath | Where-Object -FilterScript { $_.EnhancedKeyUsageList.FriendlyName -ne 'Time Stamping' }
    }
    else {
        # The "| Where-Object -FilterScript {$_ -ne 0}" part is used to filter the output coming from Get-AuthenticodeSignatureEx function that gets nested certificate
        $CertCollection = Get-SignedFileCertificates -X509Certificate2 $X509Certificate2 | Where-Object -FilterScript { $_.EnhancedKeyUsageList.FriendlyName -ne 'Time Stamping' } | Where-Object -FilterScript { $_ -ne 0 }
    }

    # Loop through each certificate in the collection and call this function recursively with the certificate object as an input
    foreach ($Cert in $CertCollection) {

        # Build the certificate chain
        [System.Security.Cryptography.X509Certificates.X509Chain]$Chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain

        # Set the chain policy properties
        $chain.ChainPolicy.RevocationMode = 'NoCheck'
        $chain.ChainPolicy.RevocationFlag = 'EndCertificateOnly'
        $chain.ChainPolicy.VerificationFlags = 'NoFlag'

        [void]$Chain.Build($Cert)

        # If AllCertificates is present, loop through all chain elements and display all certificates
        foreach ($Element in $Chain.ChainElements) {
            # Create a custom object with the certificate properties

            # Extract the data after CN= in the subject and issuer properties
            # When a common name contains a comma ',' then it will automatically be wrapped around double quotes. E.g., "Skylum Software USA, Inc."
            # The methods below are conditional regex. Different patterns are used based on the availability of at least one double quote in the CN field, indicating that it had comma in it so it had been enclosed with double quotes by system

            $Element.Certificate.Subject -match 'CN=(?<InitialRegexTest2>.*?),.*' | Out-Null
            [System.String]$SubjectCN = $matches['InitialRegexTest2'] -like '*"*' ? ($Element.Certificate.Subject -split 'CN="(.+?)"')[1] : $matches['InitialRegexTest2']

            $Element.Certificate.Issuer -match 'CN=(?<InitialRegexTest3>.*?),.*' | Out-Null
            [System.String]$IssuerCN = $matches['InitialRegexTest3'] -like '*"*' ? ($Element.Certificate.Issuer -split 'CN="(.+?)"')[1] : $matches['InitialRegexTest3']

            # Get the TBS value of the certificate using the Get-TBSCertificate function
            [System.String]$TbsValue = Get-TBSCertificate -cert $Element.Certificate
            # Create a custom object with the extracted properties and the TBS value
            $Obj += [pscustomobject]@{
                SubjectCN = $SubjectCN
                IssuerCN  = $IssuerCN
                NotAfter  = $element.Certificate.NotAfter
                TBSValue  = $TbsValue
            }
        }
    }

    if ($FilePath) {

        # The reason the commented code below is not used is because some files such as C:\Windows\System32\xcopy.exe or d3dcompiler_47.dll that are signed by Microsoft report a different Leaf certificate common name when queried using Get-AuthenticodeSignature
        # (Get-AuthenticodeSignature -FilePath $FilePath).SignerCertificate.Subject -match 'CN=(?<InitialRegexTest4>.*?),.*' | Out-Null

        [System.Security.Cryptography.X509Certificates.X509Certificate]$CertificateUsingAlternativeMethod = [System.Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($FilePath)
        $CertificateUsingAlternativeMethod.Subject -match 'CN=(?<InitialRegexTest4>.*?),.*' | Out-Null

        [System.String]$TestAgainst = $matches['InitialRegexTest4'] -like '*"*' ? ((Get-AuthenticodeSignature -FilePath $FilePath).SignerCertificate.Subject -split 'CN="(.+?)"')[1] : $matches['InitialRegexTest4']

        if ($IntermediateOnly) {
            # ($_.SubjectCN -ne $_.IssuerCN) -> To omit Root certificate from the result
            # ($_.SubjectCN -ne $TestAgainst) -> To omit the Leaf certificate

            $FinalObj = $Obj |
            Where-Object -FilterScript { ($_.SubjectCN -ne $_.IssuerCN) -and ($_.SubjectCN -ne $TestAgainst) } |
            Group-Object -Property TBSValue | ForEach-Object -Process { $_.Group[0] } # To make sure the output values are unique based on TBSValue property

            return [System.Object[]]$FinalObj
        }
        elseif ($LeafCertificate) {
            # ($_.SubjectCN -ne $_.IssuerCN) -> To omit Root certificate from the result
            # ($_.SubjectCN -eq $TestAgainst) -> To get the Leaf certificate

            $FinalObj = $Obj |
            Where-Object -FilterScript { ($_.SubjectCN -ne $_.IssuerCN) -and ($_.SubjectCN -eq $TestAgainst) } |
            Group-Object -Property TBSValue | ForEach-Object -Process { $_.Group[0] } # To make sure the output values are unique based on TBSValue property

            return [System.Object[]]$FinalObj
        }

    }
    # If nested certificate is being processed and X509Certificate2 object is passed
    elseif ($X509Certificate2) {

        if ($IntermediateOnly) {
            # ($_.SubjectCN -ne $_.IssuerCN) -> To omit Root certificate from the result
            # ($_.SubjectCN -ne $LeafCNOfTheNestedCertificate) -> To omit the Leaf certificate

            $FinalObj = $Obj |
            Where-Object -FilterScript { ($_.SubjectCN -ne $_.IssuerCN) -and ($_.SubjectCN -ne $LeafCNOfTheNestedCertificate) } |
            Group-Object -Property TBSValue | ForEach-Object -Process { $_.Group[0] } # To make sure the output values are unique based on TBSValue property

            return [System.Object[]]$FinalObj
        }
        elseif ($LeafCertificate) {
            # ($_.SubjectCN -ne $_.IssuerCN) -> To omit Root certificate from the result
            # ($_.SubjectCN -eq $LeafCNOfTheNestedCertificate) -> To get the Leaf certificate

            $FinalObj = $Obj |
            Where-Object -FilterScript { ($_.SubjectCN -ne $_.IssuerCN) -and ($_.SubjectCN -eq $LeafCNOfTheNestedCertificate) } |
            Group-Object -Property TBSValue | ForEach-Object -Process { $_.Group[0] } # To make sure the output values are unique based on TBSValue property

            return [System.Object[]]$FinalObj
        }
    }
}

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAg1f2xGMWxhjEM
# FBFjSIaKyibSiS29kVpPwnIAHTtjR6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQg6sfw9lMohiiKoqM5ve3z1BKDgeOI3pEawUl3YbLcIkwwDQYJKoZIhvcNAQEB
# BQAEggIAmtffARgOO3ZqkVO2aPMcuFoeRm+JQ4vthgYA6t1aRlHGrjoDMKsjTY59
# K6y7kPI8GRJjQDLnBMGQic6THFRsnD/XSNZxD4Am6mXNq0l88lf8Tn5LZdcgrVxp
# sqUUHV/Mf07phyjVB9ig8pApiyhKwZxppqx2CdlSDxKEQUyi9hD2USLwrm+WSiLQ
# 2H1zPmfGiVH20Env4amtNmbRanjglpRiFfs1cpkcMXdEMYeSYKTc0wurnZ1fypYN
# goNtE+m5Zk94MsZzSuJHney/0nLF/J8eJvrIMrv6u4T47C2gohmEgEMlFZgfDLup
# FJhIuIAjCoY99tYxPkzjMtjLOv9IzCaLxeOleHV5ZLGHPXFg0aG6gy6sY815gf0S
# VDODibPMfJ5ezu0WgDUObzRqy7i5AmOa7BfK2lO0ylp0oi+7O6ZS7VdiWA6nFFmP
# jVv2uI+4SAsi1cpdyVLjhyc1D0w0VGWzKTz7ZLA4GGrEZxALXmZnAuVanGUxRzwX
# 6DPDRzR+ITpm5DwrxXonQdbTBmZZHyuFPJ/aP/Q64JoynSuYt4SzldQSKFfDK2I6
# tcwk0j6KiMEB33F/A2xB/n/PVQiF7bFLIEojuZi9ul/nLTGfGYF6DeDQjhHYehi6
# 0Vy/J97lVMz75p2Iu9167f+dFWy9IfoGfUmU6lnGfbXgoj2KIKo=
# SIG # End signature block
