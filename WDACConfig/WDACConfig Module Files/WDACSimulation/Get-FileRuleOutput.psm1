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
    [OutputType([System.Object[]])]
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
    Write-Verbose -Message "Get-FileRuleOutput: Returning $($OutputHashInfoProcessing.Count) file rules that are based on file hashes"
    return $OutputHashInfoProcessing
}
Export-ModuleMember -Function 'Get-FileRuleOutput'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBq843SF48k223G
# yUbra8SgUZLQbOoqbN9z+2KE2vkkYKCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgNrZPQbfPDkPwoPlv5w37qbgg7FiUtFod92lHED6qevowDQYJKoZIhvcNAQEB
# BQAEggIAm6XWWktZph4L4bIVQmOpkMdVRIBBCiEbvXo2nDwjEC/bhIxCmnLC8g4B
# 6XKh3RYHtqb8VBzUAeyqWC7InpDiGJ94UDCw5TtMmMbYcU4gttKN/2zDO5S3f8u0
# HiYPFfE4shMqRSpwybJyJ/UO6rz+edxRg9pYDPEsYI+vP+WUyRn2hMIsE+m5t5gp
# XlLowmu0pHHitTOqGWyvFiEQwBkyYbUrWRs15fYWtAZbZ8ubkvpcWjqnpok/O0zf
# rHpxbb4IVydPA1vJj6bxilVBTk+jh4adHjCLrkHCZJqixJBaCOFWYVirZ3XIPekk
# 8WeCsT3v6Wd689+2VCbjrhJRIo8BetWbM81ogrfsakvYjVk2R2cJdGi0ljg+++ks
# MdaDgeo3ZSu1oEL4p3Y6HSK886vCsPgQeTnl6cUcAzWz7VcRRdRnAxB2PMDHIJRI
# Lsc/EDVcrmfUF00hsZKYfpDLo/fd/kfEXoTpCv1yEIyfPUe1pGAt2Hk8Di4Y8D6r
# iNwxUm+E0r2SlNEtt/34fHnzfMFZkJqjC7wCKCH0R0Q35mAqt+TgSLuPxIQQ1OM3
# a4OxtoHVG7KxZkbV5ytcpOfR39vyeE/cFZ15zgeca+/CmF2RmpbCT1rLbV9fnVx+
# eyc+BgxmKxfjmujWjONZ9pjHKmjlq6OicwKPsBEDAZxENMw0R0s=
# SIG # End signature block
