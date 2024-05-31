Function New-PFNLevelRules {
    [CmdletBinding()]
    [OutputType([System.Void])]
    Param (
        [Alias('PFN')]
        [Parameter(Mandatory = $true)][System.String[]]$PackageFamilyNames,
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath
    )
    Begin {
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Load the XML file
        [System.Xml.XmlDocument]$Xml = Get-Content -Path $XmlFilePath

        # Define the namespace manager
        [System.Xml.XmlNamespaceManager]$Ns = New-Object -TypeName System.Xml.XmlNamespaceManager -ArgumentList $Xml.NameTable
        $Ns.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

        # Find the FileRules node
        [System.Xml.XmlElement]$FileRulesNode = $Xml.SelectSingleNode('//ns:FileRules', $Ns)

        # Find the User-Mode ProductSigners Nodes
        [System.Xml.XmlElement]$UMCI_ProductSigners_Node = $Xml.SelectSingleNode('//ns:SigningScenarios/ns:SigningScenario[@Value="12"]/ns:ProductSigners', $Ns)

        $PackageFamilyNames = $PackageFamilyNames | Select-Object -Unique
    }

    Process {

        foreach ($PFN in $PackageFamilyNames) {

            [System.String]$Guid = [System.Guid]::NewGuid().ToString().replace('-', '').ToUpper()
            [System.String]$ID = "ID_ALLOW_A_$Guid"

            # Create new PackageFamilyName rule
            [System.Xml.XmlElement]$PFNRuleNode = $Xml.CreateElement('Allow', $FileRulesNode.NamespaceURI)
            $PFNRuleNode.SetAttribute('ID', $ID)
            $PFNRuleNode.SetAttribute('FriendlyName', "Allowing packaged app by its Family Name: $PFN")
            $PFNRuleNode.SetAttribute('MinimumFileVersion', '0.0.0.0')
            $PFNRuleNode.SetAttribute('PackageFamilyName', $PFN)
            # Add the new node to the FileRules node
            [System.Void]$FileRulesNode.AppendChild($PFNRuleNode)

            # Check if FileRulesRef node exists, if not, create it
            $UMCI_Temp_FileRulesRefNode = $UMCI_ProductSigners_Node.SelectSingleNode('ns:FileRulesRef', $Ns)

            if ($Null -eq $UMCI_Temp_FileRulesRefNode) {

                [System.Xml.XmlElement]$UMCI_Temp_FileRulesRefNode = $Xml.CreateElement('FileRulesRef', $Ns.LookupNamespace('ns'))
                [System.Void]$UMCI_ProductSigners_Node.AppendChild($UMCI_Temp_FileRulesRefNode)

            }

            # Create FileRuleRef for the PFN inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="12">
            [System.Xml.XmlElement]$NewUMCIFileRuleRefNode = $Xml.CreateElement('FileRuleRef', $UMCI_Temp_FileRulesRefNode.NamespaceURI)
            $NewUMCIFileRuleRefNode.SetAttribute('RuleID', $ID)
            [System.Void]$UMCI_Temp_FileRulesRefNode.AppendChild($NewUMCIFileRuleRefNode)
        }
    }

    End {
        # Save the modified XML back to the file
        $Xml.Save($XmlFilePath)
    }
}
Export-ModuleMember -Function 'New-PFNLevelRules'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCAxQ2T4ZtEqnvg
# E/xFNq4xBjdjBWCK1ye8Ig7MGFJIL6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgfoR+EkOylkBA/eo6P/OEhpnZKAjCBWTQrT0QjgM046EwDQYJKoZIhvcNAQEB
# BQAEggIAh7uTveRl5vtbuFmtghbEEFGvEwFU8wtgmetd7idwwdUKFtnRAwTTT9Hw
# C6b08CQUOamWtZOlPJ7odf67mlKW5QpcSE/NRH9qtQaCGN1UDR0MPP+bKCgDK6fd
# E+2y9Zkh5hjF6hb0+Utz/2fXxzs2RNPpDbfpOGN72Haflen3FyFwrwlYjxSIyRiX
# HcGR7XRPgV4puV+oJ+IPzonKdJ8vGu7pdAWAecjjGISOxfXOe4j+pB6Vg7UbdQoY
# 4TkBkyR9/pXoScXY73e6RkEveU6b6lTTFW/Q3ncjNBzC2AtvPqpPoN4Kz/3/pzJS
# N81Un/6iSxc2eWBVnHoyMo4b48bDryYjxcLLi5UXyNxlnJv8ETtAmoUYaKYo0/3E
# v3g9PwBHnPA1TVLkPt3DEfLneJ+PFdwiAAyUI0terWAmIRjHib5QgFavZxUkNwZL
# StMDxzXsL3ALzNE4NzrjC8AZ6ST5X2j4iLf1LRUJpAmchWcoty32DLpg0Zm/H6/M
# v2hKHYzRED7rqNApHIUjgrZPz9dUnmIL92EmvhgoLE/GYhDA/7KL6R6vy1dyRDqO
# LQxQpovutppkj3EhsOLt9m9N+9Mhydn9pzruR7XuJhav+Dt6oQx7rxIpd/DqafdT
# yyUiMYVjLebM8SFF0TY869Max+T+spxHtpvrGTZ2YpdcqQaMSc0=
# SIG # End signature block
