Function Test-KernelProtectedFiles {
    <#
    .SYNOPSIS
        Detects kernel-protected files files such as the main executable of the games installed through Xbox app inside of the event logs
    .DESCRIPTION
        For these files, only Kernel can get their details such as hashes, it passes them to event viewer and we take them from event viewer logs
        Any other attempts such as "Get-FileHash" or "Get-AuthenticodeSignature" fails and ConfigCI Module cmdlets totally ignore these files and do not create allow rules for them
    .INPUTS
        PSCustomObject[]
    .OUTPUTS
        PSCustomObject[]
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param(
        [Parameter(Mandatory = $true)][PSCustomObject[]]$Logs
    )
    Begin {
        Write-Verbose -Message 'Test-KernelProtectedFiles: Checking for Kernel-Protected files'
        # Final output to return
        $KernelProtectedFileLogs = New-Object -TypeName System.Collections.Generic.HashSet[PSCustomObject]
    }
    Process {
        # Looping through every existing file with .exe and .dll extensions to check if they are kernel protected
        foreach ($Log in ($Logs | Where-Object -FilterScript { ([System.IO.Path]::GetExtension($_.'Full Path') -in @('.exe', '.dll')) -and ([System.IO.Path]::Exists($_.'Full Path')) })) {
            try {
                $Null = Get-FileHash -Path $Log.'Full Path' -ErrorAction Stop
            }
            # If the executable is protected, it will throw an exception and the module will continue to the next one
            # Making sure only the right file is captured by narrowing down the error type.
            # E.g., when get-filehash can't get a file's hash because its open by another program, the exception is different: System.IO.IOException
            catch [System.UnauthorizedAccessException] {
                [System.Void]$KernelProtectedFileLogs.Add($Log)
            }
            catch {
                Write-Verbose -Message "Test-KernelProtectedFiles: An unexpected error occurred while checking the file: $($Log.'Full Path')"
            }
        }
    }
    End {
        Return ($KernelProtectedFileLogs.Count -eq 0 ? $null : [PSCustomObject[]]$KernelProtectedFileLogs)
    }
}
Export-ModuleMember -Function 'Test-KernelProtectedFiles'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBHKMkT28X36Dwj
# Cn61ype5SvzUIZdSs14yZOWwbD4OoaCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQg/rD5gGofWRssXCK/60fZJ3mTCPwaJ3qCZAMQ/2dakX0wDQYJKoZIhvcNAQEB
# BQAEggIAgH4NGd+8VM3J4hrz65XLXq+gjt5tTxo1gyjWuegtzo79GSJJBB8gQAo/
# qRf7uS9esUSgT5+DYSJ8VKBKvOb1fylw4OJINnBeTwWarrlfv7rvVOHfRvCnVnDP
# o8GnBkej8Ud8KEcG3W/fDAkiieC75z5SFDYAFMpHEiFnTuyY/MGebx2D11iLTHbO
# d0VFpJn7JBMIJOV1+j4k39B8ZCNve0BVdxWWyU+k82026OokC7J/8DAk2hnCRiSC
# ftc6zyaH+qB//v6suLxxvG2OAbtFenFVqhT8NcsnnsfUWY33N4dt9KwORvT4H/7r
# pPVQRL41PkJcxN+W3V3wpfu0AqeuJHYDAsq7EVi5BbfFHfAFrYD05ki0MpqcrEK8
# vhMzHumsp0gqulH8nA3l6n4avqWWGDj5AZ70R03YIp0G7e4lghv09yfCjyYClkYj
# KfOstxJZkzBXFee7epHSQbn8UR0Lxe4ptXclsjilvxQVAopfDpA1h5H1irOBemzw
# +sqoo/IoR1l4y79at/hVmylJ0JmsBqFrIOhRXTqF+t8pwdVpobLTcg3mLjUkkBwE
# OIiBSYJfifIt3fIh70pcwsSGl7PFdrXwErBDXsJpqj5uKA8IIMcGGhJVMz6pN2Be
# nyG8bR5honK/M2MIgxuU56+3acFLwtxiGSlJ6/jkdyGi9ojHyhs=
# SIG # End signature block
