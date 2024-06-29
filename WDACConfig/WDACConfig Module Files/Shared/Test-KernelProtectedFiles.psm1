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
    }
    Process {
        # Looping through every existing file with .exe and .dll extensions to check if they are kernel protected
        [PSCustomObject[]]$KernelProtectedFileLogs = foreach ($Log in $Logs) {

            if ( ([System.IO.Path]::GetExtension($Log.'Full Path') -in @('.exe', '.dll')) -and ([System.IO.Path]::Exists($Log.'Full Path'))) {

                try {
                    $Null = Get-FileHash -Path $Log.'Full Path' -ErrorAction Stop
                }
                # If the executable is protected, it will throw an exception and the module will continue to the next one
                # Making sure only the right file is captured by narrowing down the error type.
                # E.g., when get-filehash can't get a file's hash because its open by another program, the exception is different: System.IO.IOException
                catch [System.UnauthorizedAccessException] {
                    $Log
                }
                catch {
                    Write-Verbose -Message "Test-KernelProtectedFiles: An unexpected error occurred while checking the file: $($Log.'Full Path')"
                }
            }
        }
    }
    End {
        Return ($KernelProtectedFileLogs.Count -eq 0 ? $null : $KernelProtectedFileLogs)
    }
}
Export-ModuleMember -Function 'Test-KernelProtectedFiles'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA8rw6xHRRe46QR
# 6xWIu1xrMpiNI/iVOYkkNeAzzdY8z6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgv87O/5Nlal3ZVsjnB0sGb4KXdVkiaBmjpac6y+6fF5YwDQYJKoZIhvcNAQEB
# BQAEggIAcZr2+WL0s3BSFTVo4i9FiwNWGrUh/ffMRZQrwdUyGlbqYne58O23n1Zl
# 9hXWYKguq+2HyejJHeoXOOUMYk+KQRMcOMDrh2Y6//MYPE4ickDke75YwUtlPUQx
# AacYSdDcxHTz+b+5YL65Vvp7DGgqhP4ZgNsQj+EyHUrXxXTrv8zWPca34HiL02ro
# MDne37X8n+CPCUZrnlhg2OQ2F+fVtjCYYFabqQOOFIgRrCz8bd+8rZbr2pXOK0UI
# 3Ek/gSVENXbq+28z9RE3IjBjMnt2Y8jQIGFgsNuAJ6rMofYfo3t0qgReIVvCgoRV
# PBCo+WRjaOkcXySKGnZkdpb/5jazR2bCqBHDjVsAwblhSPna6XBPeoaaDBC/RkdN
# 3f24BznwIINVrnBjgogBOlhc9NnJCMuKeN1l+CGUTlpfNgCROSxC6WSigbEZo+mi
# FBkCiO4kvgsrHj3wRlu110pN0hl+3nAUgTbDvhgdPvgkoYXTMIW0fGMUkNLFha/6
# Orbud6QkjeQZDwRHFrssQI2oLpuA/LSwHPWACV7LkVf7hH8SD9npJGYOCltzDkZD
# kS4sfSV8jiO105Ia9WbV7cQbvn/WNXfx9Vdr/BX/O/OXMMB7k4j4PEU8DZ7ElGln
# HqjS6gMTRVQvx3lX6wCbw/sJDFY0RWq1JQJo5XRZ9hR3aawS6cg=
# SIG # End signature block
