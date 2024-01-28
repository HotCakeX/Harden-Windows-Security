# Importing the $PSDefaultParameterValues to the current session, prior to everything else
. "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

Function Get-FileRuleOutput {
    <#
    .SYNOPSIS
        a function to load an xml file and create an output array of custom objects that contain the file rules that are based on file hashes
    .PARAMETER XmlPath
        Path to the XML file that user selected for WDAC simulation
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Object[]
    #>
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [System.IO.FileInfo]$XmlPath
    )

    # Load the xml file into a variable
    $Xml = [System.Xml.XmlDocument](Get-Content -Path $XmlPath)

    # Create an empty array to store the output
    [System.Object[]]$OutputHashInfoProcessing = @()

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

    # Return the output array
    return $OutputHashInfoProcessing
}

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCAWUpn31GEmAz7
# //Ad8gEeEhXvVuvkzG330WndPNQhfqCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQg4hHbLNudi+jy4c6Dg/JgN1vh0iXhOTYmufhx8HEjuc0wDQYJKoZIhvcNAQEB
# BQAEggIAWac6SDbFreismhGBNC+vcIgmlcpUfhmxf/KzFn5Ozra5Qo2KfggytNok
# E7JdYj3MHaLw2liDMUcHP5aurujxJsb4f1Ib58HhKLuwF7LnLJ5i4OySJHq7C1aT
# Z+WkYbwtSJISc8mJu/xe1UVRh5FMIqwZ4EAy6HvBG19Kx34brcxOHuHq+k0PeKql
# eHjMfupPh4YXmcjwRxMVukYH3PPaFGs1u0P1EwpONOTRUVB+MP8nG+YmkI+W6F5S
# mbQI5IZpWU5b7JwlDKBMLbKDPGaNmpalQskaoTDan9mKu+ZpV9aqniS2Oqg3z/eP
# 79CUumaaQbpxLu1PeIaBSC5osJvkBOja7XZFm3xFNjyxJ/YamrW02Uk58WIgaW3x
# uiMbw7B9cPMNx1vRetxAINWwp0QT97TpcPBRt0v96gslJwiZqB6lfbPMauJggNjG
# os1wSB6coAbRr41sqzc37hKpd9tMKLLbssfhSOxYZtqS/Si/buZhg3bhrYOTZVyN
# ucozd6iU2HLoePeGQHLCBufPowSOpDoc8J0COiYU2WZ2RDjw6qxLSmDflhswoM8g
# x2aTPH7ym5SEz3BxFdhTj7ppn6rBb6p1W6L8FObaWIjiKmbLDBy+7G1ARXYkCbXQ
# kjmNVyQJjAsBUCeAN20esmZnmSv1+4hb/BEhMkZl8Uqt21zyaJc=
# SIG # End signature block
