Function New-HashLevelRules {
    <#
    .SYNOPSIS
        Creates new Hash level rules in an XML file
        For each hash data, it creates 2 Hash rules, one for Authenticode SHA2-256 and one for SHA1 hash
        It also adds the FileRulesRef for each hash to the ProductSigners node of the correct signing scenario (Kernel/User mode)
    .PARAMETER Hashes
        The Hashes to be used for creating the rules, they are the output of the Build-SignerAndHashObjects function
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
    Param(
        [Parameter(Mandatory = $true)][PSCustomObject[]]$Hashes,
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath
    )
    Begin {
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message "New-HashLevelRules: There are $($Hashes.Count) Hash rules to be added to the XML file"

        # Load the XML file
        [System.Xml.XmlDocument]$Xml = Get-Content -Path $XmlFilePath

        # Define the namespace manager
        [System.Xml.XmlNamespaceManager]$Ns = New-Object -TypeName System.Xml.XmlNamespaceManager -ArgumentList $Xml.NameTable
        $Ns.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

        # Find the ProductSigners Nodes
        [System.Xml.XmlElement]$UMCI_ProductSigners_Node = $Xml.SelectSingleNode('//ns:SigningScenarios/ns:SigningScenario[@Value="12"]/ns:ProductSigners', $Ns)
        [System.Xml.XmlElement]$KMCI_ProductSigners_Node = $Xml.SelectSingleNode('//ns:SigningScenarios/ns:SigningScenario[@Value="131"]/ns:ProductSigners', $Ns)
    }

    Process {

        # Find the FileRules node
        [System.Xml.XmlElement]$FileRulesNode = $Xml.SelectSingleNode('//ns:FileRules', $Ns)

        # Loop through each hash and create a new rule for it
        Foreach ($Hash in $Hashes) {

            [System.String]$Guid = [System.Guid]::NewGuid().ToString().replace('-', '').ToUpper()

            # Create a unique ID for the rule
            [System.String]$HashSHA256RuleID = "ID_ALLOW_A_$Guid"
            [System.String]$HashSHA1RuleID = "ID_ALLOW_B_$Guid"

            # Create new Allow Hash rule for Authenticode SHA256D
            [System.Xml.XmlElement]$NewAuth256HashNode = $Xml.CreateElement('Allow', $FileRulesNode.NamespaceURI)
            $NewAuth256HashNode.SetAttribute('ID', $HashSHA256RuleID)
            $NewAuth256HashNode.SetAttribute('FriendlyName', "$($Hash.FileName) Hash Sha256")
            $NewAuth256HashNode.SetAttribute('Hash', $Hash.AuthenticodeSHA256)
            # Add the new node to the FileRules node
            [System.Void]$FileRulesNode.AppendChild($NewAuth256HashNode)

            # Create new Allow Hash rule for Authenticode SHA1
            [System.Xml.XmlElement]$NewAuth1HashNode = $Xml.CreateElement('Allow', $FileRulesNode.NamespaceURI)
            $NewAuth1HashNode.SetAttribute('ID', $HashSHA1RuleID)
            $NewAuth1HashNode.SetAttribute('FriendlyName', "$($Hash.FileName) Hash Sha1")
            $NewAuth1HashNode.SetAttribute('Hash', $Hash.AuthenticodeSHA1)
            # Add the new node to the FileRules node
            [System.Void]$FileRulesNode.AppendChild($NewAuth1HashNode)

            # For User-Mode files
            if ($Hash.SiSigningScenario -eq '1') {

                # Check if FileRulesRef node exists, if not, create it
                $UMCI_Temp_FileRulesRefNode = $UMCI_ProductSigners_Node.SelectSingleNode('ns:FileRulesRef', $Ns)

                if ($Null -eq $UMCI_Temp_FileRulesRefNode) {

                    [System.Xml.XmlElement]$UMCI_Temp_FileRulesRefNode = $Xml.CreateElement('FileRulesRef', $Ns.LookupNamespace('ns'))
                    [System.Void]$UMCI_ProductSigners_Node.AppendChild($UMCI_Temp_FileRulesRefNode)

                }

                # Create FileRuleRef for Authenticode SHA256 Hash inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="12">
                [System.Xml.XmlElement]$NewUMCIFileRuleRefNode = $Xml.CreateElement('FileRuleRef', $UMCI_Temp_FileRulesRefNode.NamespaceURI)
                $NewUMCIFileRuleRefNode.SetAttribute('RuleID', $HashSHA256RuleID)
                [System.Void]$UMCI_Temp_FileRulesRefNode.AppendChild($NewUMCIFileRuleRefNode)

                # Create FileRuleRef for Authenticode SHA1 Hash inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="12">
                [System.Xml.XmlElement]$NewUMCIFileRuleRefNode = $Xml.CreateElement('FileRuleRef', $UMCI_Temp_FileRulesRefNode.NamespaceURI)
                $NewUMCIFileRuleRefNode.SetAttribute('RuleID', $HashSHA1RuleID)
                [System.Void]$UMCI_Temp_FileRulesRefNode.AppendChild($NewUMCIFileRuleRefNode)

            }

            # For Kernel-Mode files
            elseif ($Hash.SiSigningScenario -eq '0') {

                # Display a warning if a hash rule for a kernel-mode file is being created and the file is not an MSI
                # Since MDE does not record the Signing information events (Id 8038) for MSI files so we must create Hash based rules for them
                if (-NOT $Hash.FileName.EndsWith('.msi')) {
                    Write-Warning -Message "Creating Hash rule for Kernel-Mode file: $($Hash.FileName). Kernel-Mode file should be signed!"
                }

                # Check if FileRulesRef node exists, if not, create it
                $KMCI_Temp_FileRulesRefNode = $KMCI_ProductSigners_Node.SelectSingleNode('ns:FileRulesRef', $Ns)

                if ($Null -eq $KMCI_Temp_FileRulesRefNode) {

                    [System.Xml.XmlElement]$KMCI_Temp_FileRulesRefNode = $Xml.CreateElement('FileRulesRef', $Ns.LookupNamespace('ns'))
                    [System.Void]$KMCI_ProductSigners_Node.AppendChild($KMCI_Temp_FileRulesRefNode)
                }

                # Create FileRuleRef for Authenticode SHA256 Hash inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="131">
                [System.Xml.XmlElement]$NewKMCIFileRuleRefNode = $Xml.CreateElement('FileRuleRef', $KMCI_Temp_FileRulesRefNode.NamespaceURI)
                $NewKMCIFileRuleRefNode.SetAttribute('RuleID', $HashSHA256RuleID)
                [System.Void]$KMCI_Temp_FileRulesRefNode.AppendChild($NewKMCIFileRuleRefNode)

                # Create FileRuleRef for Authenticode SHA1 Hash inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="131">
                [System.Xml.XmlElement]$NewKMCIFileRuleRefNode = $Xml.CreateElement('FileRuleRef', $KMCI_Temp_FileRulesRefNode.NamespaceURI)
                $NewKMCIFileRuleRefNode.SetAttribute('RuleID', $HashSHA1RuleID)
                [System.Void]$KMCI_Temp_FileRulesRefNode.AppendChild($NewKMCIFileRuleRefNode)
            }
        }

    }

    End {
        $Xml.Save($XmlFilePath)
    }
}
Export-ModuleMember -Function 'New-HashLevelRules'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDt+zZFVPdtiJ5n
# RXmlqwWBdVxLnAa2KTp2wE0xIojfN6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgySMwm3DN7/QLo7E4tIHgbEefvPLHltFCS5fLe92arKEwDQYJKoZIhvcNAQEB
# BQAEggIABSwQyhvuJk4d8BfQXQJQXIJbTxYYjw0usU7wxqSgHgkNCCKhP0KiCz6c
# 6XaWqtZk6CfIUZbuAlbaRSlI72rIe+DtzPDE7f5QgvRaN0TKTiOVbiXndYuoLwAy
# yjdfWisLdAI4+9UNO0J3PjbSco80o6aVs4+7gp6U7GbhU3ZsXX1j4wZN00aZXegU
# UfUfNXMBYvzY996yr0oUT6X5a6iz32NhjRsT2XH7qSsMS/8uN4QsWGv2hCZtNN/g
# eQavEvra7iQ4mmSzuoVLMNbuhg0V4RHAt/heEizHTs7KAFN+/ag5Rw9p1xHbBEFs
# L8XjHMUlwyQQjYPB+g+l5d1WmjCgm+QQGVKojOSN5/boy/54IUfaCWbfwqdNOvZl
# Yqh2cS29aZTBAevwQLQMzUQ9tdCkT9s9YO8GsJWG2cWPBzMO43h9kqjIT6pD6+DQ
# mknttEeSFDuljL642SMxBovKX282KrGGw24dRjfIsqaYxhjBDaLJt/3JpuTG4K42
# s/rRIJhWJUAtcufvxUu3Hjwo3NarB6931Zlh2VFNF4R0gZXttlbQMqpxNoeb8geG
# NuY935i5SG0xW8HBQH2+7dIrmSGxMkqcyMNJn6i8cF5G7uftJ3m3gfqyuFiz6pOM
# vnr4e0lUB8oGkrbX0aKfYkCGEyIHea/poYLL7JEdz0Qmq1ozI5Q=
# SIG # End signature block
