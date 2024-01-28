# Importing the $PSDefaultParameterValues to the current session, prior to everything else
. "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

Function Get-SignedFileCertificates {
    <#
    .SYNOPSIS
        A function to get all the certificates from a signed file or a certificate object and output a Collection
    .PARAMETER FilePath
        Optional parameter, the function will get all the certificates from this file if this parameter is used
    .PARAMETER X509Certificate2
        Optional parameter, the function will get all the certificates from this certificate object if this parameter is used
    .INPUTS
        System.String
        System.Security.Cryptography.X509Certificates.X509Certificate2
    .OUTPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2Collection])]
    param (
        [Parameter()]
        [System.String]$FilePath,
        [Parameter(ValueFromPipeline = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$X509Certificate2
    )

    begin {
        # Create an X509Certificate2Collection object
        [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]$CertCollection = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    }

    process {
        # Check which parameter set is used
        if ($FilePath) {
            # If the FilePath parameter is used, import all the certificates from the file
            $CertCollection.Import($FilePath, $null, 'DefaultKeySet')
        }
        elseif ($X509Certificate2) {
            # If the CertObject parameter is used, add the certificate object to the collection
            $CertCollection.Add($X509Certificate2)
        }
    }

    end {
        # Return the collection
        return $CertCollection
    }
}
Export-ModuleMember -Function 'Get-SignedFileCertificates'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCKrSsshlsAo2bJ
# 09DgXpcPHsR/8GZT/fgBdv1eN3HGf6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQg/mXJKEvoFplvFU898HtgL3aGJ6OfIucpvJopM0mAr/QwDQYJKoZIhvcNAQEB
# BQAEggIAKS4PzLu9fegEHQFyYRpb7iKtaEkTlYIQ7C8fdCkGiTQVZ4syFEaZOrc9
# YZ4SOd/9YXzwx3D++279mMytW9enie2ta2ers8iBkLeILs9EDgJw+DWECGCUBsMn
# IwYO5Wt5JqQFJFSkZ3pQzDH3NaZyb2qabwM7i7jCV3EH+EMabmzWRG+o45NbWIvd
# NpLzNv7XJFlsktvPYsICqaqzF7cowtAthvGLCjbRSex2IDxgBLcZ8i+ovkyHcYTW
# BY4uXiztY7FQbLr/zLmcvrQcZX2K5BZ2t9J7zID61zXxHpfWb2XDFAVrDAkO0SvY
# +gpVyb/66mFVfnKMHd95UKMsJ2NM3xrWsdH5VHJf2bKShC1zT4+Phy7+piIrMZTv
# UuWYrq1I4fu+ySoHZR/cLJ1et/KeXMnZVtwn1KKG7yIyxw8ALXucmYZfC6HSTwSg
# vZDOrPlW3Dk/bwdmE05QxUEFw5J877yMGn3H7fBbecUYJ84qeYrNVBwEHNrJq2mY
# kerTqmOo47XTnHRqmoTCXUAivB/81RCbvOD+yXx4SNJ4MEMrCb5PG/Bs+iYQdUpg
# FNZB9T1k8RJ/vTFCYG2Cj9TNeTjQ4bRsuOqD4RrjsjR1kGxl8J+R8dz3m32Bzi1z
# A4J5+Hj/09M8VuLCdK5iQL29cNco4DzzVXH0PdPCYE/WTRI/Uyo=
# SIG # End signature block