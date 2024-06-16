
Function Get-FileRuleOutput {
    <#
    .SYNOPSIS
        a function to load an xml file and create an output array of custom objects that contain the file rules that are based on file hashes
    .PARAMETER XmlPath
        Path to the XML file that user selected for WDAC simulation
    .NOTES
        The function is intentionally not made to handle Allow all rules since checking for their existence happens in the main cmdlet
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Object[]
    #>
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [parameter(Mandatory = $true)]
        [System.IO.FileInfo]$XmlPath
    )
    Begin {
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Load the xml file into a variable
        $Xml = [System.Xml.XmlDocument](Get-Content -LiteralPath $XmlPath)

        # Create an empty array to store the output
        [System.Object[]]$OutputHashInfoProcessing = @()
    }

    Process {

        # Loop through each file rule in the xml file
        foreach ($FileRule in $Xml.SiPolicy.FileRules.Allow) {

            # Extract the hash value from the Hash attribute
            [System.String]$Hashvalue = $FileRule.Hash

            # Extract the hash type from the FriendlyName attribute using regex
            [System.String]$HashType = $FileRule.FriendlyName -replace '.* (Hash (Sha1|Sha256|Page Sha1|Page Sha256|Authenticode SIP Sha256))$', '$1'

            # Extract the file path from the FriendlyName attribute using regex
            [System.IO.FileInfo]$FilePathForHash = $FileRule.FriendlyName -replace ' (Hash (Sha1|Sha256|Page Sha1|Page Sha256|Authenticode SIP Sha256))$', ''

            # Create a custom object with the three properties
            $Object = [PSCustomObject]@{
                HashValue       = $Hashvalue
                HashType        = $HashType
                FilePathForHash = $FilePathForHash
            }

            # Add the object to the output array if it is not a duplicate hash value
            if ($OutputHashInfoProcessing.HashValue -notcontains $Hashvalue) {
                $OutputHashInfoProcessing += $Object
            }
        }

        # Only show the Authenticode Hash SHA256
        [System.Object[]]$OutputHashInfoProcessing = $OutputHashInfoProcessing | Where-Object -FilterScript { $_.hashtype -eq 'Hash Sha256' }
    }

    End {
        # Return the output array
        Write-Verbose -Message "Get-FileRuleOutput: Returning $($OutputHashInfoProcessing.Count) file rules that are based on file hashes"
        return $OutputHashInfoProcessing
    }
}
Export-ModuleMember -Function 'Get-FileRuleOutput'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA665oHZqqhg0Vb
# cELbeYkLyg/nNXh/+ZhpXeP/ehOobaCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQg2z7eMTxX9Z0u9SoMKVsg155qNNgDM225T2msIWOiDy4wDQYJKoZIhvcNAQEB
# BQAEggIAL0stfm7ViojKtrHiRdDnGEQ0HA14cEccefA+s3YaXuAdb21vu7CpsDh6
# cmn7Vxyf8oDvE73bLw/ek3NBbCyEXs1t/dWfXoFd9D+Rci6veSgUCfU9hYjBci73
# tNASt0a82E9408nVSIevG+oAc1iEpO6o99JON2FJPDtSodLyLZE6RwWkOocJuye3
# wxO39l19DQQmrR9x+/5hWG/5EIfpjJzyTJST2SG1nNT5/y26MzK9oSkIku4mOgPQ
# BCk2QD5jMcb9kKvocsVLude5LJktg3HjOTYAriF7my6+pVJy9VxAtM8j5YvAC46h
# CtoMi85dzJu54jZmiMZla2afYvTz1EhtIA4WVtfJGj35ho66DbPgI9E52VtpJHvi
# iibg5Kzjin3fOiilKJgVKO8rJwhtb8P/f03yTIvxZmqFyuQGQZNS3b930FWuJo5c
# ielWzBDEGQXL2UG0v389XuZJ4CMicWrGfq6kXlKAlnq4KfKnu8iboXhJDqCqelsC
# CSi9MjEDEyXxNlFs/nQ0VwLipZT+vAO1CeRxsE97g17Sjy00YH6BvapbkozSB5ST
# 5iNJDz0DIMghPrit2gruY6QvV0Rvusbs3bcWA0oqoiGcGSuhkBB26kRe4mo+uDgW
# /eg6+VkZif0HbGsCBfWtNwm9gZ0tlfgw5kI7a8ZQ4KFKKN2jTp8=
# SIG # End signature block
