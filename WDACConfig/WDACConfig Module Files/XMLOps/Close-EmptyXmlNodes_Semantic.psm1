Function Close-EmptyXmlNodes_Semantic {
    <#
    .SYNOPSIS
        Closes all empty XML nodes and removes empty nodes that are neither base nodes nor 'ProductSigners' nodes
        According to the CI Schema

        For example, it converts this

    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="Auto generated policy on 03-13-2024">
      <ProductSigners>
        <AllowedSigners>
        </AllowedSigners>
      </ProductSigners>
    </SigningScenario>

    Or this

    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="Auto generated policy on 03-13-2024">
      <ProductSigners>
        <AllowedSigners />
      </ProductSigners>
    </SigningScenario>

    to this

    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="Auto generated policy on 03-13-2024">
      <ProductSigners />
    </SigningScenario>

    .PARAMETER XmlFilePath
        The path to the XML file to be processed
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

        # Define the base node names that should not be removed even if empty
        [System.String[]]$BaseNodeNames = @('SiPolicy', 'Rules', 'EKUs', 'FileRules', 'Signers', 'SigningScenarios', 'UpdatePolicySigners', 'CiSigners', 'HvciOptions', 'BasePolicyID', 'PolicyID')

        Function Close-EmptyNodesRecursively {
            <#
            .SYNOPSIS
                Helper function to recursively close empty XML nodes
            #>
            param (
                [Parameter(Mandatory = $true)][System.Xml.XmlElement]$XmlNode
            )

            foreach ($ChildNode in $XmlNode.ChildNodes) {
                if ($ChildNode -is [System.Xml.XmlElement]) {
                    # Recursively close empty child nodes
                    Close-EmptyNodesRecursively -XmlNode $ChildNode

                    # Check if the node is empty
                    if (-not $ChildNode.HasChildNodes -and -not $ChildNode.HasAttributes) {

                        # Check if it's a base node
                        if ($BaseNodeNames -contains $ChildNode.LocalName) {
                            # self-close it
                            $ChildNode.IsEmpty = $true
                        }
                        # Special case for ProductSigners because it's a required node inside each SigningScenario but can't be empty
                        elseif ($ChildNode.LocalName -eq 'ProductSigners') {
                            # self-close it
                            $ChildNode.IsEmpty = $true
                        }
                        else {
                            # If it's not a base node, remove it
                            [System.Void]$ChildNode.ParentNode.RemoveChild($ChildNode)
                        }
                    }
                }
            }
        }
    }
    Process {
        # Load the XML file
        [System.Xml.XmlDocument]$Xml = Get-Content -Path $XmlFilePath

        # Start the recursive function from the root element
        Close-EmptyNodesRecursively -XmlNode $Xml.DocumentElement
    }
    End {
        # Save the changes back to the XML file
        $Xml.Save($XmlFilePath)
    }
}
Export-ModuleMember -Function 'Close-EmptyXmlNodes_Semantic'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBy59sB6JDopRNf
# x6PG3Bl5JlcUljcJNitgh2wcwWBRPKCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgAcIdGbYE8NwqDhIac4U8p8lebZLXiYg4SO+iM61B6TwwDQYJKoZIhvcNAQEB
# BQAEggIAdF+OCfKfTJC6/XgHeDUPDJbNagfdpUA/ZATFhJkA2sn8feBHxoah9S5x
# NWFhPr7L7eTd147tAyBK/4wHsIxZWKlGP0bNRRZsWyGOoWcmv9ONhzfv2N5MYB0H
# AE0HjW7U7rvetQw/ITLQFqIoZg8vBfGOupBn+K/V41B6AAdkjYMHK1hYf3LKPIZD
# M8FWINToQHs/gSkUlZIFhWZGQP7hcyTdNOmDNHvr5+Vjzm1RyUXgNXvuZ/626byn
# 3jUqxGOQVk3Bvz5SdI3aqEvBO6oqsxASdJZcMqUYeVUWSxxhqg/+8g6a9OfkFZmN
# rhZ6pk6W0y8fPYjjGN5YRwsbRDk6O9QUG6KzmiCbY7pWYqCcvT44flkqksVVgjZx
# b/XtXEydoWGNIM2x1jzA/keaTwoC4cK+O8rlLBNk92s7kAX4Tw+PMB1rCgu+rHjT
# F0g3oDmLo8IHlq/TmBFnRhkE9kwbSW0eYzyEfFnwSX1TcbsgYSzEWfdeoVqyO6UF
# n33n8kWMicD+ulKuW9tcYfXIUQ9tJOBSubZ7VhAaj9d2klNF0nMxM2l8w3WmVNr2
# U7oovVWkuqOzQjaeyRsuUgVS9CedlijNxTHNyb97/WhmEIEib+cNpRWb0GPa90PQ
# R97pyd9IeDyd2Y1JIBhXDRr1FaYjMwR9M4L/sXUctTUV2fmMeNA=
# SIG # End signature block
