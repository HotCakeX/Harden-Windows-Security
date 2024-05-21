Function Remove-OrphanAllowedSignersAndCiSigners_IDBased {
    <#
    .SYNOPSIS
        Removes elements with invalid SignerIds from the CiSigners and AllowedSigners nodes in a CI policy XML file
        These are elements with SignerIds that are not found in any <Signer> in the <Signers> node
    .PARAMETER Path
        The path to the CI policy XML file
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$Path
    )
    Begin {
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Load the XML file
        [System.Xml.XmlDocument]$Xml = Get-Content -Path $Path

        # Create an XmlNamespaceManager for namespace resolution
        [System.Xml.XmlNamespaceManager]$NsManager = New-Object System.Xml.XmlNamespaceManager -ArgumentList $Xml.NameTable
        $NsManager.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

        # Get the list of valid signer IDs from the Signers node
        [System.String[]]$ValidSignerIds = $Xml.SelectNodes('//ns:Signers/ns:Signer', $NsManager) | ForEach-Object -Process { $_.ID }

        Function Remove-InvalidSignerIds {
            <#
        .SYNOPSIS
            Removes nodes with invalid SignerIds from the given XmlNodeList
        .INPUTS
            System.Xml.XmlNodeList
        .OUTPUTS
            System.Void
        .PARAMETER NodeList
            The XmlNodeList to remove invalid SignerIds from
        #>
            Param (
                [Parameter(Mandatory = $true)][System.Xml.XmlNodeList]$NodeList
            )

            foreach ($Node in $NodeList) {
                if ($ValidSignerIds -notcontains $Node.SignerId) {
                    [System.Void]$Node.ParentNode.RemoveChild($Node)
                }
            }
        }
    }

    Process {

        # Get CiSigners and AllowedSigners nodes
        [System.Xml.XmlNodeList]$CiSigners = $Xml.SelectNodes('//ns:CiSigners/ns:CiSigner', $NsManager)
        [System.Xml.XmlNodeList]$AllowedSigners12 = $Xml.SelectNodes('//ns:SigningScenarios/ns:SigningScenario[@Value="12"]/ns:ProductSigners/ns:AllowedSigners/ns:AllowedSigner', $NsManager)
        [System.Xml.XmlNodeList]$AllowedSigners131 = $Xml.SelectNodes('//ns:SigningScenarios/ns:SigningScenario[@Value="131"]/ns:ProductSigners/ns:AllowedSigners/ns:AllowedSigner', $NsManager)

        # Remove invalid signer IDs from CiSigners and AllowedSigners
        Remove-InvalidSignerIds $CiSigners
        Remove-InvalidSignerIds $AllowedSigners12
        Remove-InvalidSignerIds $AllowedSigners131

    }
    End {
        # Save the changes to the XML file
        $Xml.Save($Path)
    }
}
Export-ModuleMember -Function 'Remove-OrphanAllowedSignersAndCiSigners_IDBased'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDxCtyqvRx02Cij
# 0iw25QrPxYTS8h82ZJlkaV81jjeC06CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgXNqcihUO+cJkmSBignGIEGOKN92AK2Cc2iVAC82b38UwDQYJKoZIhvcNAQEB
# BQAEggIAFl+2r1q4vUEaPND38pvNL3mtp4lXqwLRVfia1XzVGcXWuAenKHWFvDIi
# oJABEa7sXzAZn7HeZp2Np33pLI6upWDSjbsNi4s5RY4Dgq0d6OXKKcONrrq5g0+m
# pErsvVPoQk+P98VLVLjZdZcVc415EwUdYF1ZwpoBzMVB+S4YLUggvLHsc65mkc3e
# nLIdejBbk9shyv2dbdB0NRIKB/ccIcU3X+/Fttjz53Z++EYQA7iWVnUKqEsoYF8/
# 0k+o8oDcXWOnp+q5Y49QfuPtp0nVxagInPMuf//LZFCFiwU1Bru2rHTOf3bY6Q4u
# bSm6L8SdB1cmX7H3wiAs/BB0pEQwVSIVSHmktq2s0VrN06D4ArZ/hipylYCTCTEc
# IhEp8i+sAKi97OHYcwhv+pB30O4sHscvpujnIMaBfyKNvEU9/0PcdBcg5RhHAi5J
# NLhAigOMAFfwQZamUxM5ffkGYFlfU9HXxlsIwS5KhAzRqtvPBDbrE+RbLgZEtUho
# Gd3v8vsHPzzrSYn+UMNQ2A0Dnt/nqN8ZGbsJm69rxh0WgXepfLXQpttMy8YVcsBm
# QEMhb0Dh/fzZJLQ0xYeB2q21zAftMaqKVSmdPSF+43tpbAzPRiFWElY8xnEpotvQ
# jhZ1cJkvYZcf3k1WrEXba3GRjul9C5M4PZyQZaz6qDy0iwuJZKk=
# SIG # End signature block
