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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBM8KBRRZkRqYL/
# 9oJTjyLh2/8PlYtNjODpWgqgxKghQaCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQg/SCjiTXDan6C6lWUiYKZ8ar02f79O6UgOAj2Lcv/89EwDQYJKoZIhvcNAQEB
# BQAEggIALCPxszXjXgnhtdehzmsLLV19Ij6kUL1DZASO2ktOXPfIDL/B7S9eEnnm
# Rrsmkpa67aZzcNNuW/5rZyELwzSlqfoj7TtiSksVnirGoa7WfIaHr+Vpqi0CuYlQ
# WpbldQ+V1cOsXILZ/cp6STO9b8VsSuezwyLWVtJnODrbzciksIbIvzH9jK9xigyx
# JrNyXlsY3RCpT3D7RPWeeZeFcQT4XjdLsQtaLBiobgAPUo23OtgOqQp1jAEfaOM4
# CbN+XKXCGdFWSnn+yOBf1qzMYiKBGXMbhWKdiBKcC1szr3c/S1tX8b/tJjS+9Mtf
# u1j8uZK8P6KpDEyz0XqNZLVeigEKnsQqAtyvfA+Xd/mRfe2y5UMQ72jaRVvSnUIj
# 9R3LaVWVsXzs73+QeRKFrK0CW2pVwr3/MBanbadwBMC333zxq2MOUoG+0pzuNLWZ
# F5k2UPd7MZj2d6f5TIdf4WmkTw8UVNKEWOpoI3sIP/rXcifYpPl6FjrprmbDQtLf
# fmbc/COzGcarlTZ5cCndw2Kb8Ao6Jg9ALAO8OGxri73v4aqfpgIBsotUVSTuhcsA
# hLxqh71UHd4IFgkPrts8AR1rQlWysQyomsv9m+OKaDT+RDcs7uJNKBC1XVFySRPr
# z23/c9/EBbfi6U19c3GOuJ+6JURsZaYnjnOICd+c2WhUjReklKc=
# SIG # End signature block
