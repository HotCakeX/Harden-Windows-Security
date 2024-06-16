Function Select-LogProperties {
    <#
    .SYNOPSIS
        Selects, processes and sorts the properties for the Code Integrity and AppLocker logs.
    #>
    Param (
        [PSCustomObject[]]$Logs
    )
    Return $Logs | Select-Object -Property @{
        Label      = 'File Name'
        Expression = {
            # Can't use Get-Item or Get-ChildItem because the file might not exist on the disk
            # Can't use Split-Path -LiteralPath with -Leaf parameter because not supported
            [System.String]$TempPath = Split-Path -LiteralPath $_.'File Name'
            $_.'File Name'.Replace($TempPath, '').TrimStart('\')
        }
    },
    'TimeCreated',
    'PolicyName',
    'ProductName',
    'FileVersion',
    'OriginalFileName',
    'FileDescription',
    'InternalName',
    'PackageFamilyName',
    @{
        Label      = 'Full Path'
        Expression = { $_.'File Name' }
    },
    'Validated Signing Level',
    'Requested Signing Level',
    'SI Signing Scenario',
    'UserId',
    @{
        Label      = 'Publishers'
        Expression = { [System.String[]]$_.'Publishers' }
    },
    'SHA256 Hash',
    'SHA256 Flat Hash',
    'SHA1 Hash',
    'SHA1 Flat Hash',
    'PolicyGUID',
    'PolicyHash',
    'ActivityId',
    'Process Name',
    'UserWriteable',
    'PolicyID',
    'Status',
    'USN',
    'SignatureStatus',
    'ProviderName',
    'SignerInfo' | Sort-Object -Property TimeCreated -Descending

    <#
    Return [System.Linq.Enumerable]::OrderByDescending(
        [System.Collections.Generic.List[System.Object]]$Logs,
        [System.Func[System.Object, System.DateTime]] { param($Item) $Item.TimeCreated }
    )
        #>
}
Export-ModuleMember -Function 'Select-LogProperties'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCkZG5Qo23wTjYw
# z70lU4lGgo25O6L3Dwp05JxrAguDhqCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQg/+Nr8F8VZhO2tZOj7Y98ZsrP9qoNxQ/YVjkqNKSEw+8wDQYJKoZIhvcNAQEB
# BQAEggIAPSrBQoHAB+YrFjANVLTWv9yeCQvKkPeZwiE1RSMCsz9fTrJIFeLTRDfh
# WTkB97eFGH3OtYe0q3dilpf/it1wVSyuXkbTTiioFw0jGqOVCbrl8G+koldiYMSP
# 7bNCAo6lgtGFbo5Z1Koj8zyc0ulo0cOavBQkuPkjZBJhotATm5LEo2Ngl4r1hSBe
# BK+Ku7lmogfoXHyK9yh+xeDie6qZWSWESG9ohwZ5d6bscOXSYicpQdP8ScAACUat
# WWuuqWxf5cg8CAiK24EyiO47DtFmboPp0vrja5y3eVTSfayTE4iymttV3ZFS9Php
# oor4dlWgtZ2Oajh9cZ/gu6JYiF+cAZ7wW6630HaJj8tPZJ0evAVPquaDBDjgErGA
# NpFYEFBjtuaqwh2mz6dVNug/W9Es57xgC50cl1ZXWJHWqtULXd4ZbJNqcyDq9R+O
# RVNnMja83FOtFb7aNSpufDQaSlDjvGtmSTMfwJgUcjy5dMEAB5RAaQHS5QTbdZDK
# LnfmthscFa/k7ZgaiO7IMY7ZdDR/8NmhFZ57qXtK86TTDCCazC8cAtcX6uyAOgMG
# zVIYGk+10Rr3in3BWHf6OXZadaIRNNDmr6aAh1y/72+rT0jupsSXC4UZDYRWYORg
# d7frhNKWhjAgN+30X/Sckd4Zrsi2CjDI11tRMiNJj3cYqjKJWiY=
# SIG # End signature block
