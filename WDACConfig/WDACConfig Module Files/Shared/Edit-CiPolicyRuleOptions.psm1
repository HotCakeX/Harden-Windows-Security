Function Edit-CiPolicyRuleOptions {
    <#
    .SYNOPSIS
        Configures the Policy rule options in a given XML file and sets the HVCI to Strict
    .PARAMETER Action
        The type of policy to configure the rule options for
    .PARAMETER XMLFile
        The XML file to configure the rule options for
    .INPUTS
        System.String
        System.IO.FileInfo
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    param (
        [ValidateSet('Base', 'Supplemental', 'TestMode', 'Base-KernelMode', 'Base-ISG', 'RemoveAll')]
        [Parameter(Mandatory = $true)]
        [System.String]$Action,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$XMLFile
    )
    Begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'Configuring the policy rule options'
    }
    Process {
        Switch ($Action) {
            'Base' {
                @(0, 2, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath $XMLFile -Option $_ }
                @(3, 4, 8, 9, 10, 13, 14, 15, 18) | ForEach-Object -Process { Set-RuleOption -FilePath $XMLFile -Option $_ -Delete }
                break
            }
            'Base-ISG' {
                @(0, 2, 6, 11, 12, 14, 15, 16, 17, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath $XMLFile -Option $_ }
                @(3, 4, 8, 9, 10, 13, 18) | ForEach-Object -Process { Set-RuleOption -FilePath $XMLFile -Option $_ -Delete }
                break
            }
            'Base-KernelMode' {
                @(2, 6, 16, 17, 20) | ForEach-Object -Process { Set-RuleOption -FilePath $XMLFile -Option $_ }
                @(0, 3, 4, 8, 9, 10, 11, 12, 13, 14, 15, 18, 19) | ForEach-Object -Process { Set-RuleOption -FilePath $XMLFile -Option $_ -Delete }
                break
            }
            'Supplemental' {
                Set-RuleOption -FilePath $XMLFile -Option 18
                @(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath $XMLFile -Option $_ -Delete }
                break
            }
            'TestMode' {
                9..10 | ForEach-Object -Process { Set-RuleOption -FilePath $XMLFile -Option $_ }
                break
            }
            'RemoveAll' {
                0..20 | ForEach-Object -Process { Set-RuleOption -FilePath $XMLFile -Option $_ -Delete }
                break
            }
        }
    }
    End {
        Set-HVCIOptions -Strict -FilePath $XMLFile
    }
}
Export-ModuleMember -Function 'Edit-CiPolicyRuleOptions'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC59mNnEyLmgaqQ
# f50brPXwMg4BYkmblAywqvGbLXwu86CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgO3xJBacf6acjkugTJV3EygttaOkXgg1N7pslRsVPmYEwDQYJKoZIhvcNAQEB
# BQAEggIADRD76npuYOvlfaZXjn+Hun23/hodv3F0XrzLEL5PEPZg69ocl7wZFCSK
# nsIxwhYEW8JcnOichBik90BkFpUq/z1Z0GWJCp/LmDDA3zlE1+wgzl4oW0EEYDMR
# 8wUAaWJM4V73e0LE/4tVOaFR95pCDlTjaVq6VKY/qD286IHlusXglfXHHjEGPsAk
# v58QgnsWTYr1Scy3hFQVjpBCcIYaD29SGVQwTf1+py8DSnGr2EpDg1YC0XJl7BC+
# 9bAYXlyvpHkkQJ8Fchyh5wu/WmasZ+T3c/p8JEVoeeQm/aBJT9khaIU9wEC9UhNE
# Wwyh/GuyROMfKaFPhrzZjhQdVt6YghhBav57f9rYz9H9vq7O8d1wU7vpuIgciMLy
# R6yD77YNFt/vxq12MVTDW68sr3Lsd/caJ0ZdMdQlWtlJYdikMhtuXhE9UXOPKNPC
# AoQUSBioaq/iBLuxZxMSVm0bmiMHz+hw78D1J1/HDPJbQMHCOm/HIFiXqX6Fqlgm
# U5MR9Kl8iRTTZ1eWG0UJ9H2s6w+QfQXUmHdoedwqXHdFbiKF40ChNu4OV7AavIJC
# qzRxnmJazJYjao6gyejhen7zbsDDzJbBkydAC/SkBvUP0lALzQPSLcMCcfSSX5Ff
# J7zB98EV6cjd58usQH22iFbpyZp9fKxdH2nAr49UqBzuacAPLc8=
# SIG # End signature block
