Function New-CertificateSignerRules {
    <#
    .SYNOPSIS
        Creates new Signer rules for Certificates, in the XML file
        The level is Pca/Root/Leaf certificate, meaning there is no certificate publisher mentioned
        Only Certificate TBS and its name is used.
    .PARAMETER SignerData
        The SignerData to be used for creating the rules
    .PARAMETER XmlFilePath
        The path to the XML file to be modified
    .INPUTS
        PSCustomObject[]
        System.IO.FileInfo
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    Param (
        [Parameter(Mandatory = $true)][PSCustomObject[]]$SignerData,
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath
    )
    Begin {
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Load the XML file
        [System.Xml.XmlDocument]$Xml = Get-Content -Path $XmlFilePath

        # Define the namespace manager
        [System.Xml.XmlNamespaceManager]$Ns = New-Object -TypeName System.Xml.XmlNamespaceManager -ArgumentList $Xml.NameTable
        $Ns.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

        # Find the Signers Node
        [System.Xml.XmlElement]$SignersNode = $Xml.SelectSingleNode('//ns:Signers', $Ns)

        # Find the ProductSigners Nodes
        [System.Xml.XmlElement]$UMCI_ProductSigners_Node = $Xml.SelectSingleNode('//ns:SigningScenarios/ns:SigningScenario[@Value="12"]/ns:ProductSigners', $Ns)
        [System.Xml.XmlElement]$KMCI_ProductSigners_Node = $Xml.SelectSingleNode('//ns:SigningScenarios/ns:SigningScenario[@Value="131"]/ns:ProductSigners', $Ns)

        # Find the CiSigners Node
        [System.Xml.XmlElement]$CiSignersNode = $Xml.SelectSingleNode('//ns:CiSigners', $Ns)
    }

    Process {

        foreach ($Data in $SignerData) {

            # Create a unique ID for the Signer element
            [System.String]$Guid = [System.Guid]::NewGuid().ToString().replace('-', '').ToUpper()

            [System.String]$SignerID = "ID_SIGNER_R_$Guid"

            # Create the new Signer element
            [System.Xml.XmlElement]$NewSignerNode = $Xml.CreateElement('Signer', $SignersNode.NamespaceURI)
            $NewSignerNode.SetAttribute('ID', $SignerID)
            $NewSignerNode.SetAttribute('Name', $Data.SignerName)

            # Create the CertRoot element and add it to the Signer element
            [System.Xml.XmlElement]$CertRootNode = $Xml.CreateElement('CertRoot', $SignersNode.NamespaceURI)
            $CertRootNode.SetAttribute('Type', 'TBS')
            $CertRootNode.SetAttribute('Value', $Data.TBS)
            [System.Void]$NewSignerNode.AppendChild($CertRootNode)

            # Add the new Signer element to the Signers node
            [System.Void]$SignersNode.AppendChild($NewSignerNode)

            # For User-Mode files
            if ($Data.SiSigningScenario -eq '1') {

                # Check if AllowedSigners node exists, if not, create it
                $UMCI_Temp_AllowedSignersNode = $UMCI_ProductSigners_Node.SelectSingleNode('ns:AllowedSigners', $Ns)

                if ($Null -eq $UMCI_Temp_AllowedSignersNode) {

                    [System.Xml.XmlElement]$UMCI_Temp_AllowedSignersNode = $Xml.CreateElement('AllowedSigners', $Ns.LookupNamespace('ns'))
                    [System.Void]$UMCI_ProductSigners_Node.AppendChild($UMCI_Temp_AllowedSignersNode)

                }

                # Create Allowed Signers inside the <AllowedSigners> -> <ProductSigners> -> <SigningScenario Value="12">
                [System.Xml.XmlElement]$NewUMCIAllowedSignerNode = $Xml.CreateElement('AllowedSigner', $UMCI_Temp_AllowedSignersNode.NamespaceURI)
                $NewUMCIAllowedSignerNode.SetAttribute('SignerId', $SignerID)
                [System.Void]$UMCI_Temp_AllowedSignersNode.AppendChild($NewUMCIAllowedSignerNode)

                # Create a CI Signer for the User Mode Signer
                [System.Xml.XmlElement]$NewCiSignerNode = $Xml.CreateElement('CiSigner', $CiSignersNode.NamespaceURI)
                $NewCiSignerNode.SetAttribute('SignerId', $SignerID)
                [System.Void]$CiSignersNode.AppendChild($NewCiSignerNode)
            }

            # For Kernel-Mode files
            elseif ($Data.SiSigningScenario -eq '0') {

                # Check if AllowedSigners node exists, if not, create it
                $KMCI_Temp_AllowedSignersNode = $KMCI_ProductSigners_Node.SelectSingleNode('ns:AllowedSigners', $Ns)

                if ($Null -eq $KMCI_Temp_AllowedSignersNode) {

                    [System.Xml.XmlElement]$KMCI_Temp_AllowedSignersNode = $Xml.CreateElement('AllowedSigners', $Ns.LookupNamespace('ns'))
                    [System.Void]$KMCI_ProductSigners_Node.AppendChild($KMCI_Temp_AllowedSignersNode)

                }

                # Create Allowed Signers inside the <AllowedSigners> -> <ProductSigners> -> <SigningScenario Value="131">
                [System.Xml.XmlElement]$NewKMCIAllowedSignerNode = $Xml.CreateElement('AllowedSigner', $KMCI_Temp_AllowedSignersNode.NamespaceURI)
                $NewKMCIAllowedSignerNode.SetAttribute('SignerId', $SignerID)
                [System.Void]$KMCI_Temp_AllowedSignersNode.AppendChild($NewKMCIAllowedSignerNode)

                # Kernel-Mode signers don't need CI Signers
            }
        }
    }

    End {
        # Save the modified XML back to the file
        $Xml.Save($XmlFilePath)
    }
}
Export-ModuleMember -Function 'New-CertificateSignerRules'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA8CxZ10usueJkW
# goOszNaT5g+OD2SkBNb70qZYQmTwxaCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgXq0FCx+jz3T9E3RC9yDet4LDYM2OMwF2R9CFEmWjI/YwDQYJKoZIhvcNAQEB
# BQAEggIATRS+wXdiADHexq5nQy7qkcmBj7ocRnF8Hj7zVBnqh/2dxuGrXXA67DSo
# CNSGV6K8fJv/zXNwXGiMctPy8obBDy6ynnXb8ZKlZfoCzWXPkK6+6cmuiUce/h3a
# Sqp75rtcG4ueAhpDiWKULMlcMFfXw0DT43jd6eZh0GIduKKPiJtPwH7mu+DHSn8c
# GthWp9ZwYwHPuuy7aa/QmozIuWNJTdzxX2RpUSxZIsHCWI7FAR8S5DZKubCQNrfm
# PCFlcBkPCvccJiw+kvpClNTO9QitnBCJo4NaniyDWLzyLOvhPJ/QS+spsAXN+Y1R
# GvE5ZZhjfISAteIGBx9h7+Lm35a39mSkq+qYT7aIpL9R1MuCjy1EzxyB+WDIgsTv
# 9J6WS5VZbZB7W9jaB/JiAygFaHGBub2pdg8hqssUwETt9GGpDZp1Hihj1B//iYlV
# p71l4g+ZFuXDdzkpFsHIfUcx/gcQ6pcPT0Jqh9CcXdR2SMQn0KGNIbfxO2khcmox
# L079Y08I3q5KHk2xVO221M7D4WXb1l2GKKXTLWOwA0OnfojGOG0DlZumNR4GyELJ
# K9cFbYQd1XD9ajMHdVqOn3QxEN83jNHxDVqABDurhQ98vKViWA7t1bnf1D2r8xlc
# +1q51cdj890p2H/GuiKrJ89NIfM2wFQnfVv7FNrYhFum57RifTw=
# SIG # End signature block
