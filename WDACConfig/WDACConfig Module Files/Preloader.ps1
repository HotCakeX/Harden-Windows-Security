if (!$IsWindows) {
    Throw [System.PlatformNotSupportedException] 'The WDACConfig module only runs on Windows operation systems.'
}

# Specifies that the WDACConfig module requires Administrator privileges
#Requires -RunAsAdministrator

# Create tamper resistant global variables (if they don't already exist) - They are automatically imported in the caller's environment
try {
    if ((Test-Path -Path 'Variable:\MSFTRecommendedBlockRulesURL') -eq $false) { New-Variable -Name 'MSFTRecommendedBlockRulesURL' -Value 'https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac.md' -Option 'Constant' -Scope 'Global' -Description 'User Mode block rules' -Force }
    if ((Test-Path -Path 'Variable:\MSFTRecommendedDriverBlockRulesURL') -eq $false) { New-Variable -Name 'MSFTRecommendedDriverBlockRulesURL' -Value 'https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md' -Option 'Constant' -Scope 'Global' -Description 'Kernel Mode block rules' -Force }
    if ((Test-Path -Path 'Variable:\UserTempDirectoryPath') -eq $false) { New-Variable -Name 'UserTempDirectoryPath' -Value ([System.IO.Path]::GetTempPath()) -Option 'Constant' -Scope 'Global' -Description 'Properly and securely retrieved Temp Directory' -Force }
    if ((Test-Path -Path 'Variable:\UserAccountDirectoryPath') -eq $false) { New-Variable -Name 'UserAccountDirectoryPath' -Value ((Get-CimInstance Win32_UserProfile -Filter "SID = '$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)'").LocalPath) -Option 'Constant' -Scope 'Global' -Description 'Securely retrieved User profile directory' -Force }
    if ((Test-Path -Path 'Variable:\Requiredbuild') -eq $false) { New-Variable -Name 'Requiredbuild' -Value '22621.2428' -Option 'Constant' -Scope 'Script' -Description 'Minimum required OS build number' -Force }
    if ((Test-Path -Path 'Variable:\OSBuild') -eq $false) { New-Variable -Name 'OSBuild' -Value ([System.Environment]::OSVersion.Version.Build) -Option 'Constant' -Scope 'Script' -Description 'Current OS build version' -Force }
    if ((Test-Path -Path 'Variable:\UBR') -eq $false) { New-Variable -Name 'UBR' -Value (Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR') -Option 'Constant' -Scope 'Script' -Description 'Update Build Revision (UBR) number' -Force }
    if ((Test-Path -Path 'Variable:\FullOSBuild') -eq $false) { New-Variable -Name 'FullOSBuild' -Value "$OSBuild.$UBR" -Option 'Constant' -Scope 'Script' -Description 'Create full OS build number as seen in Windows Settings' -Force }
    if ((Test-Path -Path 'Variable:\ModuleRootPath') -eq $false) { New-Variable -Name 'ModuleRootPath' -Value ($PSScriptRoot) -Option 'Constant' -Scope 'Global' -Description 'Storing the value of $PSScriptRoot in a global constant variable to allow the internal functions to use it when navigating the module structure' -Force }
}
catch {
    Throw [System.InvalidOperationException] 'Could not set the required global variables.'
}

# Make sure the current OS build is equal or greater than the required build number
if (-NOT ([System.Decimal]$FullOSBuild -ge [System.Decimal]$Requiredbuild)) {
    Throw [System.PlatformNotSupportedException] "You are not using the latest build of the Windows OS. A minimum build of $Requiredbuild is required but your OS build is $FullOSBuild`nPlease go to Windows Update to install the updates and then try again."
}

# Loop through all the relevant files in the module
foreach ($File in (Get-ChildItem -Recurse -File -Path $ModuleRootPath -Include '*.ps1', '*.psm1')) {

    # Get the signature of the current file
    [System.Management.Automation.Signature]$Signature = Get-AuthenticodeSignature -FilePath $File

    # Ensure that they are code signed properly and have not been tampered with.
    if (($Signature.SignerCertificate.Thumbprint -eq '1c1c9082551b43eec17c0301bfb2f27031a4d8c8') -and ($Signature.Status -in 'Valid', 'UnknownError')) {
        # If the file is signed properly, then continue to the next file
    }
    else {
        Throw [System.Security.SecurityException] "The module has been tampered with, signature status of the file $($File.FullName) is $($Signature.Status)"
    }
}

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC+kKF0TrvUydR3
# RoeBV1rvokHfEf+EaUs3+W4GaAT1Q6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgmDpTjxwOYh1M6Y065UoecdVoRJvpEgntMRJmT/plNtYwDQYJKoZIhvcNAQEB
# BQAEggIAU7291Emtgs+t3GrSJWprk+JNz1i4usoWfhjVoPRivTCoU9B6U0m0/Rmh
# qHy+oQASDCG7/X/4ih14mWOGMTn2E7Y8YwX32Va23QQctgnMwiFl69LYqmihIhAx
# 1lcYYkvMujOMOwNF0ixbwpiZ5SbwpcHHl1xpHJYGHDavB690XF46P+pBsAfVxoOP
# cpTM7DTtvyiKFnwH5cbjkalQtARbAY5iwLSdEApsubPA8PPXbnxFHV1MVqrIuSSR
# QoXBDCIL/79eu+BT10v0aElyG9JlLPKmuqq8RObd984Z5EWvoDq6Xmu1peBeYF+M
# /TnL4eDYI1VMSgzIU6oHhCc+7qaK4ivScdxOPYOkVo/9aM1Q17G/FmffIuWEd3Io
# AlcJu1AJA5sn2bx7jkWcEB2YJYbwIjBQ+YFmrJEeaBiW8rvgO/48zWotWrAFWG4p
# iP77twapyCSgt5HpeoSyt3QtWkzbazvy6vESSpFpHOONieBMRitl+7R0pOZQC9M6
# U/bBs1uzURb+T8ER1RQKrbK6ATc+amPPzomBwt0TKm3XPsd4lIUHhyrOKlWtLeDH
# FEwZlWJpFRFGRwX6NeQpDx6Nl8FtH1EhVuhoMqSraOAhqQ4hbn3l440Dk9iRj1SK
# Ui3JTnsQSqd6doTgxwxtteWeIYql6wRGh+chCyDfEishLVbOxN4=
# SIG # End signature block
