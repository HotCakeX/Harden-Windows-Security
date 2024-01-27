function Compare-SecureString {
    <#
    .SYNOPSIS
        Safely compares two SecureString objects without decrypting them.
        Outputs $true if they are equal, or $false otherwise.
    .INPUTS
        System.Security.SecureString
    .OUTPUTS
        System.Boolean
    .PARAMETER SecureString1
        First secure string
    .PARAMETER SecureString2
        Second secure string to compare with the first secure string
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.Security.SecureString]$SecureString1,
        [System.Security.SecureString]$SecureString2
    )
    try {
        $Bstr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString1)
        $Bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString2)
        $Length1 = [Runtime.InteropServices.Marshal]::ReadInt32($Bstr1, -4)
        $Length2 = [Runtime.InteropServices.Marshal]::ReadInt32($Bstr2, -4)
        if ( $Length1 -ne $Length2 ) {
            return $false
        }
        for ( $I = 0; $I -lt $Length1; ++$I ) {
            $B1 = [Runtime.InteropServices.Marshal]::ReadByte($Bstr1, $I)
            $B2 = [Runtime.InteropServices.Marshal]::ReadByte($Bstr2, $I)
            if ( $B1 -ne $B2 ) {
                return $false
            }
        }
        return $true
    }
    finally {
        if ( $Bstr1 -ne [IntPtr]::Zero ) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr1)
        }
        if ( $Bstr2 -ne [IntPtr]::Zero ) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr2)
        }
    }
}

Export-ModuleMember -Function 'Compare-SecureString'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB3stcON3LA/Iq+
# fGolHg9SO+X4I0E9hD5woMnIwtr5pKCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgh/Jn1gSiY0cDOR0lYGyoXdQ16yIKJKG1pjRdZvhq8f0wDQYJKoZIhvcNAQEB
# BQAEggIAg9ide+Wlx6M3XW/0W4emIRhL8rWFV7xxEV9AYTFkka6tGIgd3Um8k5fa
# i8zvCeZ0wqUXa/gTXq6Zf4VruJvq6PScHI9DO/oJg+0dFoeBdJ2dup5A/gprJIEg
# FRzQEt+lLMcjtju3Cgnl2qa1VHWWfKQR7j4iyAaqi8ciMoZYO6+rW44EWFLEJoBJ
# B5Cbg0Kk+ayuNLtH6WxSIITsBHa7VNW3mjgu5Prw8wmTUFqU+DHa7nT/18mlyy5O
# h313t72SZ5ckls+tI8hS4EpfdVx/Nw6calv/IIfG4YESGyRHFc1NPNWSJLZA+FV1
# czy6Qmyyj/ZHS0fD69ZaHFdQ7mFSeSdA4Ky0toBZ9HaviisbcrY9RNOltIBfRvJz
# 17IhglOhqBE8gUgshgFwNXTwAQ4BB5lJn41fpRTzI+V+KnWFcuz2lKaTvlDqq0Rq
# n3uEO4yAuE5oSV04nJywAU8Prk0EO6fLwImgPXHnh8auEWjivI+r8inr5FyOKXUd
# UkUC+kaC3agbCnuHqHiXi+CMrl+7HeSkf2dx53/CB/BjCByV4E2gawd4pqpiktvC
# 7K5pT42O5SUzdLyZ0hwhuwUUtkInVPIFbfDq5k5sYP3kSp1aKmyF1CLx3lnqyaGv
# WrzYgISl213fOdfZtD09BId67xfAwPRh0BIQl91tTQ6Hccrfkzw=
# SIG # End signature block
