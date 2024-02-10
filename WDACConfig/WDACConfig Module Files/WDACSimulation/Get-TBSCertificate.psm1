Function Get-TBSCertificate {
    <#
    .SYNOPSIS
        Function to calculate the TBS value of a certificate
    .INPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2
    .OUTPUTS
        System.String
    .PARAMETER Cert
        The certificate that is going to be used to retrieve its TBS value
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )
    Begin {
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Get the raw data of the certificate
        [System.Byte[]]$RawData = $Cert.RawData
    }

    Process {
        # Create an ASN.1 reader to parse the certificate
        [System.Formats.Asn1.AsnReader]$AsnReader = New-Object -TypeName System.Formats.Asn1.AsnReader -ArgumentList $RawData, ([System.Formats.Asn1.AsnEncodingRules]::DER)

        # Read the certificate sequence
        [System.Formats.Asn1.AsnReader]$Certificate = $AsnReader.ReadSequence()

        # Read the TBS (To be signed) value of the certificate
        $TbsCertificate = $Certificate.ReadEncodedValue()

        # Read the signature algorithm sequence
        [System.Formats.Asn1.AsnReader]$SignatureAlgorithm = $Certificate.ReadSequence()

        # Read the algorithm OID of the signature
        [System.String]$AlgorithmOid = $SignatureAlgorithm.ReadObjectIdentifier()

        # Define a hash function based on the algorithm OID
        switch ($AlgorithmOid) {
            '1.2.840.113549.1.1.4' { $HashFunction = [System.Security.Cryptography.MD5]::Create() ; break }
            '1.2.840.10040.4.3' { $HashFunction = [System.Security.Cryptography.SHA1]::Create() ; break }
            '2.16.840.1.101.3.4.3.2' { $HashFunction = [System.Security.Cryptography.SHA256]::Create() ; break }
            '2.16.840.1.101.3.4.3.3' { $HashFunction = [System.Security.Cryptography.SHA384]::Create() ; break }
            '2.16.840.1.101.3.4.3.4' { $HashFunction = [System.Security.Cryptography.SHA512]::Create() ; break }
            '1.2.840.10045.4.1' { $HashFunction = [System.Security.Cryptography.SHA1]::Create() ; break }
            '1.2.840.10045.4.3.2' { $HashFunction = [System.Security.Cryptography.SHA256]::Create() ; break }
            '1.2.840.10045.4.3.3' { $HashFunction = [System.Security.Cryptography.SHA384]::Create() ; break }
            '1.2.840.10045.4.3.4' { $HashFunction = [System.Security.Cryptography.SHA512]::Create() ; break }
            '1.2.840.113549.1.1.5' { $HashFunction = [System.Security.Cryptography.SHA1]::Create() ; break }
            '1.2.840.113549.1.1.11' { $HashFunction = [System.Security.Cryptography.SHA256]::Create() ; break }
            '1.2.840.113549.1.1.12' { $HashFunction = [System.Security.Cryptography.SHA384]::Create() ; break }
            '1.2.840.113549.1.1.13' { $HashFunction = [System.Security.Cryptography.SHA512]::Create() ; break }
            # sha-1WithRSAEncryption
            '1.3.14.3.2.29' { $HashFunction = [System.Security.Cryptography.SHA1]::Create() ; break }
            default { throw "No handler for algorithm $AlgorithmOid" }
        }

        # Write-Verbose -Message "Selected hash algorithm is: $($HashFunction.GetType().BaseType.Name)"

        # Compute the hash of the TBS value using the hash function
        [System.Byte[]]$Hash = $HashFunction.ComputeHash($TbsCertificate.ToArray())

        # Convert the hash to a hex string
        [System.String]$HexStringOutput = [System.BitConverter]::ToString($Hash) -replace '-', ''
    }

    End {
        # Return the output
        return $HexStringOutput
    }
}
Export-ModuleMember -Function 'Get-TBSCertificate'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBGX5+j52PXEfx2
# AuIRPENP72h+onaIVr1PAW1wB9qsIaCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgQZJBz9imjnGCtS1pAXdrroRojGr9QJyCselQCG87Ek8wDQYJKoZIhvcNAQEB
# BQAEggIAALaJ2LRXxfp+SsHV/rBOb/41XBQIwBtMnXAkWzjCHboJL7kUZaEiUDAc
# 5JAnirlSHPyI8Nf2X94eVHcPgm9NtPCN5h+V5rsvkCILtAh0l6RlCIGpcgodFEMY
# K/uuA2ejoxU4BaTN0N6Cq6zYKJe/tXVYtSg0uufb6xZjQaFZJ+8yJJ04drdxc24i
# YU0ao5cXXmU3NysjjpyBmJ58Is+g8xumluc8BryT8Iuvcb4bFziuj4LC+hsXwRz6
# Jx33fEeGLHnuyucQuDd3eDIxHI+cb5ukNV10aUo5Hqjh71IymVeZuE4VUItRvZBQ
# cqtTM97sMw3tqEj2YA+vWCOWgfPIRPVZuGg+vhQteXEl5p+fDLaAuL1kV3ihwDYw
# SVywYWR4EGSqZucJlBeZk3+FXk9MSGUNYcXm8+Wt6eOmd1HauJvl5OOXb8dKoEgV
# lf4MqLbJujktWbqAoyseg1fdLWo1HdaY7CacWlN6Y6rVjaL03wdDWRZMxEscAarb
# RQFImxi+9iBuq+aNOKYbZ+ixyCMRhWRSbsMcuol4aDse2vToQOicFrMTokFXVccO
# KD5lwHRNA2evwwCGleM/LzbcwNOZ9ihdqpyvT/IHGa0kDjJx+VI21Ob2L9g5NQSM
# 78zyND4XFBzcOaF+3LVt7MHRWj1Gj2m9y1YHtPIuyV0ARO91fMQ=
# SIG # End signature block
