Function Set-LogPropertiesVisibility {
    <#
    .SYNOPSIS
    Sets the properties to be visible in the output of the Out-GridView cmdlet.
    .PARAMETER LogType
        The type of log file to be displayed.
    .PARAMETER EventsToDisplay
        The event objects whose properties visibility are to be configured.
    .INPUTS
        PSCustomObject[]
        System.String
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    Param (
        [ValidateSet('Evtx/Local', 'MDEAH')]
        [Parameter(Mandatory = $true)][System.String]$LogType,
        [Parameter(Mandatory = $true)][PSCustomObject[]]$EventsToDisplay
    )
    Begin {
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Switch ($LogType) {
            'Evtx/Local' {
                [System.String[]]$PropertiesToDisplay = @('TimeCreated', 'File Name', 'Full Path', 'Process Name', 'ProductName', 'OriginalFileName', 'InternalName', 'PackageFamilyName', 'FileVersion', 'Publishers', 'PolicyName', 'SI Signing Scenario')
            }
            'MDEAH' {
                [System.String[]]$PropertiesToDisplay = @('TimeStamp', 'DeviceName', 'FileName', 'FolderPath', 'InitiatingProcessFileName', 'SignatureStatus', 'PolicyName', 'OriginalFileName', 'InternalName', 'PackageFamilyName', 'FileVersion', 'Type', 'SISigningScenario')
            }
        }
    }
    Process {
        # Create a PSPropertySet object that contains the names of the properties to be visible
        # Used for Out-GridView display
        # https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.pspropertyset
        # https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-pscustomobject#using-defaultpropertyset-the-long-way
        $Visible = [System.Management.Automation.PSPropertySet]::new(
            'DefaultDisplayPropertySet', # the name of the property set
            $PropertiesToDisplay # the names of the properties to be visible
        )

        # Add the PSPropertySet object to the PSStandardMembers member set of each element of the $EventsToDisplay array
        foreach ($Element in $EventsToDisplay) {
            $Element | Add-Member -MemberType 'MemberSet' -Name 'PSStandardMembers' -Value $Visible
        }
    }
}
Export-ModuleMember -Function 'Set-LogPropertiesVisibility'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDClIyYO3VMsG7v
# odNZ3AWBCcXzMUKhvpPzEPrT1MsiFqCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgbM7mZsIvL18S1GXMNdkNhcOtR+OqmdE97Fs30kTtTcYwDQYJKoZIhvcNAQEB
# BQAEggIAJ7SbIVv+78UYeXJpZalf7+69ln1OINXWUxBNUO8rBmUCD4xJDW9mihlk
# 7yDx4YQpJtUcHNrW3DWlvfLeagDy1xCbJFYYKPbO1Y5mEhxROPTlJjlQik7oQvL6
# tkcJKfZtw7JaOaOQUPzRParVJtHQ8I9TH9AvJ3n88mOxOTZApbBko6L82FvXObz0
# VePietX8Il8OssL/fHzj2DnRd0Tydv0McmmaOrNuW5ikTd9qsHH108eMPty4HrGn
# 4oL1Ky/Czj+Gwv4Is5btKB9d4447131HU7GDeSFIz9YO3NWhb6+nAWLKO/uXqi7v
# B4x6CmUwwwXuAWkf1fLDyQx5deZvCMTioJd33vTzzT2B0kjy1E3ZJpwsWecT/iUj
# hRiYdBeZe2/lEtp69JtEj5wjTFEJSbp60+Svd6f8h8M36jdTHtDNV49QdTvMx9nF
# e5mHAalDwru+Agq6FRkcpifzMHTd2KedyOmhqfctFQ4hymDnnmYzsoa4Hk4cekxQ
# eNOO6hkUTQaifiueY3F9+uQbOtpBT2KWmqxoZR0KIoD7+mEwc5zK7kiUh9Su1rH/
# JHOFViro63yYLd34Y1Q8iBakBBA944Z7gzapM8IvBkuFVKzsiq9LUpJdCiahSIza
# W2FsSVMO7yGuPU85MiAIgrGO+gOJ6/KM7u23dAxzLk3FyAXL/EA=
# SIG # End signature block
