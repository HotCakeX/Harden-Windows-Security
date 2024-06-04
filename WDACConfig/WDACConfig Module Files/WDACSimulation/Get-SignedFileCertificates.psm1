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
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Create an X509Certificate2Collection object
        [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]$CertCollection = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    }

    process {
        # Check which parameter set is used
        if ($FilePath) {
            try {
                # If the FilePath parameter is used, import all the certificates from the file
                $CertCollection.Import($FilePath, $null, 'DefaultKeySet')
            }
            catch {
                throw [ExceptionFailedToGetCertificateCollection]::new('Could not get the certificate collection of the file due to lack of necessary permissions.', 'Get-SignedFileCertificates')
            }
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA8ZhX0nMQP6G0C
# v1tlKgNZ3vPxnh29+Zc6sOLxbZ3YK6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgFa6qkE0CZ8RsiTyMhRLnB67o+AyFuuJyd6nr8+A5QwYwDQYJKoZIhvcNAQEB
# BQAEggIACeAgPMHL3HZmEx4RlBQTcyI5EO3ZXKvCc/QETog4QEZf122sR3VhgnZq
# /anqCe3Ri5xTGxJc1dO8k3/+MjKk9tWWSgsdJc1wCFfCKn0F8Q5iNnG51d4W9Umm
# YjPtu5M32a+wlOYarPl/ji9bs5a1cUTTIWOuLUQ8IXAFO3GkgriWh2/LKfyIn897
# 2EAiBzIuVivN4auSUjL/m94ItiunNgU4ryFNL4SsArBB1psooSE4oGdoZiLbQgY0
# W7W4DPSL/7+ZQpCZFsvm/W19SQrBBgt3aZLzwiwrHFOji9SBUjc++V/3S/DZA29y
# Ce/M2XbGp1aAgdgg54OTv4gYNZLycgCEWZsf30iJRnAtLydOvQJc2DHbuh37pXg4
# Nj/eRmOEYL0WJ0wDrlDXgb6CKjkRq+P36VPGIvwTaPbnSkeyCyoiJVAhcRBSEHf5
# vu+ocJdJ3261iFY4I1GURUBvcIOkGpCtQaucD4CXRTrVSkDq6H0YzAbqRQ+RI6hr
# 277eiKdb3JGF94OfctRf//npCTlk+761JEZMCLV71rgZfU2YlAUm8bn1xS0/XiLH
# K6R4J27gEaveuwCUfRTSxuFCdzt+hJfBsIz/9+u5ef5goR0UovkaKhG9mqcHp4EJ
# QpnhhDTBUI8uOnB0Ev0yqVvaggu/pQr7gjm2JePEw2WK3AvTBcE=
# SIG # End signature block
