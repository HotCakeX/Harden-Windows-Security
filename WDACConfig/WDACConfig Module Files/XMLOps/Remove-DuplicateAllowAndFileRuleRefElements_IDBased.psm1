Function Remove-DuplicateAllowAndFileRuleRefElements_IDBased {
    <#
    .SYNOPSIS
        Removes duplicates <Allow> elements from the <FileRules> nodes
        and <FileRuleRef> elements from the <FileRulesRef> nodes in every <ProductSigners> node of each <SigningScenario> node

        The criteria for removing duplicates is the ID attribute of the <Allow> elements and the RuleID attribute of the <FileRuleRef> elements
    .PARAMETER XmlFilePath
        The file path of the XML document to be modified
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath
    )
    Begin {
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Load the XML document from the specified file path
        [System.Xml.XmlDocument]$XmlDocument = Get-Content -Path $XmlFilePath

        # Create a namespace manager for handling XML namespaces
        [System.Xml.XmlNamespaceManager]$NsMgr = New-Object -TypeName System.Xml.XmlNamespaceManager -ArgumentList $XmlDocument.NameTable
        $NsMgr.AddNamespace('sip', 'urn:schemas-microsoft-com:sipolicy')
    }

    Process {
        # Remove duplicate <Allow> elements within the <FileRules> section
        [System.Xml.XmlNodeList]$AllowElements = $XmlDocument.SelectNodes('//sip:FileRules/sip:Allow', $NsMgr)

        [System.Collections.Hashtable]$UniqueAllowIDs = @{}

        foreach ($AllowElement in $AllowElements) {

            [System.String]$AllowID = $AllowElement.ID

            if ($UniqueAllowIDs.ContainsKey($AllowID)) {

                Write-Verbose "Removing duplicate Allow element with ID: $AllowID"
                [System.Void]$AllowElement.ParentNode.RemoveChild($AllowElement)
            }
            else {
                $UniqueAllowIDs[$AllowID] = $true
            }
        }

        # Remove duplicate <FileRuleRef> elements within <FileRulesRef> under <ProductSigners> nodes
        [System.Xml.XmlNodeList]$SigningScenarios = $XmlDocument.SelectNodes('//sip:SigningScenarios/sip:SigningScenario', $NsMgr)

        foreach ($Scenario in $SigningScenarios) {

            $ProductSigners = $Scenario.ProductSigners

            $FileRulesRefs = $ProductSigners.FileRulesRef

            foreach ($FileRulesRef in $FileRulesRefs) {

                [System.Collections.Hashtable]$UniqueFileRuleRefIDs = @{}

                [System.Xml.XmlElement[]]$FileRuleRefs = $FileRulesRef.FileRuleRef

                foreach ($FileRuleRef in $FileRuleRefs) {

                    [System.String]$RuleID = $FileRuleRef.RuleID

                    if ($UniqueFileRuleRefIDs.ContainsKey($RuleID)) {

                        Write-Verbose "Removing duplicate FileRuleRef element with ID: $RuleID"
                        [System.Void]$FileRulesRef.RemoveChild($FileRuleRef)
                    }
                    else {
                        $UniqueFileRuleRefIDs[$RuleID] = $true
                    }
                }
            }
        }
    }

    End {
        # Save the modified XML document back to the original file path
        $XmlDocument.Save($XmlFilePath)
    }
}
Export-ModuleMember -Function 'Remove-DuplicateAllowAndFileRuleRefElements_IDBased'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAUYPSwmBG2kef3
# xjy5uVppffuxp60cpAJy7zSNj3rfFKCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgin9CocmAhQ1RDZoyhF8+yV8bamI2/H7b00WBB0oiu0owDQYJKoZIhvcNAQEB
# BQAEggIAbzSwTiIRWFRX4Oe9y6w6CKVzXJ6vepkKo+vN0R25fL+LplSDU7dg8sf9
# BV5HBFwcNsdUPx40KmdVC0wZiHErkBQ3Za174BhUarlYHUinSz+3t7r4SW/+pzSc
# a5ldHDrhVgxUJOZYCMWZouoZzVC9ZUBVxIzRCWFmDY7hMCaK+RqYW/WhQ1hO/thT
# bXU7zanT9hv7T6xN3aJA7o3QLdoxg7YgIXmA1Im2l0iRqkiQ4+Thhz2Jwrsv3e41
# n6xDdqiEsLGRawCDxSa7WFLOLicDkz7EoFyuYc0iSuYuA28iS458/j4M6X2PQn1R
# SRDkFUREpGsp9DCI1viDjy8x4Yxs8S6OEoF9X27tF1uFVvzzDbVIHu7RAH2R/vTt
# FdkNpVWYGRuR0xnTzHA/rfYvkZiJwnJr04ltPY440kZXwObuXWxQhA9zdVozxIAw
# EQdBU2AgVUpvGPy+MmLphMU2yZ8OKOS7TQKK8vBRqRiHCPZfwgUHNZrTdS9qObVg
# UDZ8ncFqNw5rp1vQOeQZLcLBGwji9bg7dnmWIFERuqVHV/noTfkakT8+a0hL15qC
# mEgWk4qr11/jksX0etRFWwriy5KT82IN+i3CXTUpnA/ftDgCtF17DCwhIkypnt+H
# QeXI/10HDiAjQpAfH8S2t9HYx4ck05cX/xsaN/PVFf35RfjPBNA=
# SIG # End signature block
