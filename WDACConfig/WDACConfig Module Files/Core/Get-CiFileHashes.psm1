Function Get-CiFileHashes {
    [CmdletBinding()]
    [OutputType([WDACConfig.AuthenticodePageHashes])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo]$FilePath,
        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )
    [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false
    . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

    # if -SkipVersionCheck wasn't passed, run the updater
    if (-NOT $SkipVersionCheck) {
        # Importing the required sub-module for update checking
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Update-Self.psm1" -Force

        Update-Self -InvocationStatement $MyInvocation.Statement
    }

    return [WDACConfig.AuthPageHash]::GetCiFileHashes($FilePath)
    <#
.SYNOPSIS
    Calculates the Authenticode hash and first page hash of the PEs with SHA1 and SHA256 algorithms.
    The hashes are compliant wih the Windows Defender Application Control (WDAC) policy.
    For more information please visit: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create#more-information-about-hashes
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Get-CiFileHashes
.PARAMETER Path
    The path to the file for which the hashes are to be calculated.
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
.INPUTS
    System.IO.FileInfo
.OUTPUTS
    [WDACConfig.AuthenticodePageHashes]

    The output has the following properties
    - SHA1Page: The SHA1 hash of the first page of the PE file.
    - SHA256Page: The SHA256 hash of the first page of the PE file.
    - SHA1Authenticode: The SHA1 hash of the Authenticode signature of the PE file.
    - SHA256Authenticode: The SHA256 hash of the Authenticode signature of the PE file.
.NOTES
    If the is non-conformant, the function will calculate the flat hash of the file using the specified hash algorithm
    And return them as the Authenticode hashes. This is compliant with how the WDAC engine in Windows works.
#>
}

Register-ArgumentCompleter -CommandName 'Get-CiFileHashes' -ParameterName 'FilePath' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterAnyFilePathsPicker)

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCADRxilK8xhiSr8
# l5EOCO1be/H0Xsy4UgPs79qWmdLbJaCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgNbFxvf9pqlCMfA3NxLrY/xy95I7fRf7bB8moO4ojku8wDQYJKoZIhvcNAQEB
# BQAEggIAPnMezZghn8Yfb5pLQQwAj2SLLV8ThIBk1YZpBh+KRc7NRZLi4SS6w08Y
# 2jpjGOmQIKcFa3NWVy0VDBG5K6BtlAHwQzprrAo2L5OnBzlTSqfbjg2zzeCu9w70
# uRJ12q+ojM3Xj7/WSrxJ3I2Mr0VWlswmPCW5JjWpGk5RQpgfL541zSDUYAdZJNue
# GB553LCFCod9XQB8SGdBnIicZFk+8SRDsXQXyRPqvjv+50Y1gwtJk8jwv+heVs3/
# HTCDTwzGU80kFyq1eUdPRhvqyVBCwzAog9rh4gSD41IQmseJCAAcSRCXso6TzrPd
# hyV/cP7vDtLGCyxUkH0fqLhsJaktR455w+ADez298H5mp1cI1tv2BbVNDwAYnVpJ
# HdzFq/usGnZ/CHqM67Nle/AcTWAAc5oa2lye6WP1uN8mTj6zz9Lbd/FEemRudbH3
# 20BE58THSuolYe43VP8mX13OGM1F+X+qNFym1DCNBHpxH8qMW7IENLfK3+tqVDQe
# 5lrVYG/rUGQhyidFNlt0i0zPWBrgLp7AgWI+JiPqWmZk8D5lB+hCIWz2bPy14tUX
# xSv9XSkdWu/nrmghgSy9vqhjZd4kE1fxxCvYHLLP8kIcpGj6AHqR/OWhVasRvbvM
# wYqOO5kGkGK8Ctsxs1IyGJAwI378WaF+xfcxTn9mnqQVzjNGKVE=
# SIG # End signature block
