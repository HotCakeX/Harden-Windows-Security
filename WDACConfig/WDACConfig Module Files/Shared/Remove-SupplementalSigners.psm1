Function Remove-SupplementalSigners {
    <#
.SYNOPSIS
    Removes the entire SupplementalPolicySigners block
    and any Signer in Signers node that have the same ID as the SignerIds of the SupplementalPolicySigner(s) in <SupplementalPolicySigners>...</SupplementalPolicySigners> node
    from a CI policy XML file
.NOTES
    It doesn't do anything if the input policy file has no SupplementalPolicySigners block.
    It will also always check if the Signers node is not empty, like
   <Signers>
   </Signers>

   if it is then it will close it: <Signers />

   The function can run infinite number of times on the same file.
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
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [System.IO.FileInfo]$Path
    )
    Begin {

        # Make sure the input file is compliant with the CI policy schema
        $null = Test-CiPolicy -XmlFile $Path

        # Get the XML content from the file
        [System.Xml.XmlDocument]$XMLContent = Get-Content -Path $Path

    }

    Process {

        # Get the SiPolicy node
        [System.Xml.XmlElement]$SiPolicyNode = $XMLContent.SiPolicy

        # Declare the namespace manager and add the default namespace with a prefix
        [System.Xml.XmlNamespaceManager]$NameSpace = New-Object -TypeName System.Xml.XmlNamespaceManager -ArgumentList $XMLContent.NameTable
        $NameSpace.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

        # Check if the SupplementalPolicySigners node exists and has child nodes
        if ($SiPolicyNode.SupplementalPolicySigners -and $SiPolicyNode.SupplementalPolicySigners.HasChildNodes) {

            Write-Verbose -Message 'Removing the SupplementalPolicySigners block and their corresponding Signers'

            # Select the SupplementalPolicySigners node using XPath and the namespace manager
            [System.Xml.XmlElement[]]$NodesToRemove_SupplementalPolicySigners = $SiPolicyNode.SelectNodes('//ns:SupplementalPolicySigners', $NameSpace)

            # Get the SignerIds of the nodes inside of the SupplementalPolicySigners nodes - <SupplementalPolicySigners>...</SupplementalPolicySigners>
            [System.Xml.XmlElement[]]$SupplementalPolicySignerIDs = $SiPolicyNode.SupplementalPolicySigners.SelectNodes("//ns:SupplementalPolicySigner[starts-with(@SignerId, 'ID_SIGNER_')]", $NameSpace)

            # Get the unique SignerIds
            [System.String[]]$SupplementalPolicySignerIDs = $SupplementalPolicySignerIDs.SignerId | Select-Object -Unique

            # An array to store the nodes to remove
            $NodesToRemove_Signers = New-Object -TypeName 'System.Collections.Generic.List[System.Xml.XmlElement]'

            # Select all the Signer nodes in <Signers>...</Signers> that have the same ID as the SignerIds of the SupplementalPolicySigners nodes
            foreach ($SignerID in $SupplementalPolicySignerIDs) {
                $NodesToRemove_Signers.Add($SiPolicyNode.Signers.SelectNodes("//ns:Signer[@ID='$SignerID']", $NameSpace))
            }

            # Loop through the Signer nodes to remove
            foreach ($SignerNode in $NodesToRemove_Signers) {
                # Remove the Signer from the Signers node
                [System.Void]$SiPolicyNode.Signers.RemoveChild($SignerNode)
            }

            # Loop through the <SupplementalPolicySigners>..</SupplementalPolicySigners> nodes to remove, in case there are multiple!
            foreach ($Node in $NodesToRemove_SupplementalPolicySigners) {

                # Remove the <SupplementalPolicySigners> node from the parent node which is $SiPolicyNode
                [System.Void]$SiPolicyNode.RemoveChild($Node)
            }
        }

        # Check if the Signers node is empty, if it is then close it
        if (-NOT $SiPolicyNode.Signers.HasChildNodes) {

            # Create a new self-closing element with the same name and attributes as the old one
            [System.Xml.XmlElement]$NewSignersNode = $XMLContent.CreateElement('Signers', 'urn:schemas-microsoft-com:sipolicy')

            foreach ($Attribute in $SiPolicyNode.Signers.Attributes) {
                $NewSignersNode.SetAttribute($Attribute.Name, $Attribute.Value)
            }

            # Select the Signers node using XPath and the namespace manager
            [System.Xml.XmlElement]$OldSignersNode = $XMLContent.SelectSingleNode('//ns:Signers', $NameSpace)

            # Replace the old element with the new one
            [System.Void]$SiPolicyNode.ReplaceChild($NewSignersNode, $OldSignersNode)
        }

    }

    End {
        # Save the modified XML content to a file
        $XMLContent.Save($Path)
    }

}

Export-ModuleMember -Function 'Remove-SupplementalSigners'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAuy2NwPolNbvnY
# AaOrAbNeorU3qEQNZDIFSizLFj+7J6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgsNW60rYjImvlGdP4sJ7C/1gzAPR4hGLpklqVyJ2WGXMwDQYJKoZIhvcNAQEB
# BQAEggIAHdthV9U51E2QJX1SzTd3zC2KUm5AAFLD00ceSyHVgsry47ux8YxClQ6W
# ZTbWnQ3afOTx5NybpdiTn+cQHFtmmQoXemz3hGvzg80NYdVqqpFqDzN4kcPia63U
# yfBPLxFmyqXJnqivXuHN3gsIRBxFpKpWuaoypP5YCUDZbtB7GxviWIoDUbqqPXJC
# oq55Io9TQ3g4a1zQ99yrkhFe8Gihr6dljFq1Tj92SSdFwdF/ZcCgfzbsQg38Mg39
# YkGsMk0Id3uki5Uh3GhYmSn3ADfCqxA3V+mASApCj6p3XNhr38wuaJ6DbYDq8Je0
# 4u/fHSE21S0CWFravkz8UmZGZllA4ACLn41C/w3M7XVtbVAz/Hk7W5mc5JQoKsp8
# avMhtOgiztHdvawMEreIbNG+RZ2ShWO1wQErf7bs3aseYgIVSuBck804fGcNJeX6
# 7EXe9eVr8S4BKQeZz8BdyuRG5/YR30cE496yvCj1s4ypxaLYisEGI1SB5Vjo+HPa
# DZr3+jqd9w8fI2J0mPYUEHuxoRbPf2M88W+Oht+jM793nTzgI0x0jcAc2xhvDUYf
# BXBMeJu4HHX9gKuLpIzvUAtKvK2gC5EYgSuKfjHbQydSTziHCiKQN5h5yLvhWghH
# X7U+kX3lsYvREAaRCbsZLqsbLamvgMBpfXzFYhVCBq+rxuuQCPI=
# SIG # End signature block
