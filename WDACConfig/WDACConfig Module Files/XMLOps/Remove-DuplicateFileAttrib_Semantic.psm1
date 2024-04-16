function Remove-DuplicateFileAttrib_Semantic {
    <#
    .SYNOPSIS
        A function that deduplicates the <FileAttrib> elements inside the <FileRules> node.
        It successfully detects duplicate <FileAttrib> elements based on their properties. For example,
        if two <FileAttrib> elements have the same MinimumFileVersion and one of these properties of them are the same (FileName, InternalName, FileDescription, FilePath, and ProductName), they are considered half-duplicates.
        In order to be considered fully duplicate, they must also be associated with Signers whose IDs are in the same SigningScenario.

        So for example, if two <FileAttrib> elements have the same FileName and MinimumFileVersion, but they are associated with 2 different Signers, one in kernel mode and the other in user mode signing scenario, they are not considered duplicates.

        After deduplication, the function updates the FileAttribRef RuleID for associated Signers by setting the RuleID of the removed duplicate FileAttrib elements to the RuleID of the unique remaining FileAttrib element.

        This is according to the CI Schema
    .PARAMETER XmlFilePath
        The path to the XML file to be processed
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath
    )

    Begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Load the XML file
        [System.Xml.XmlDocument]$XmlDoc = New-Object -TypeName System.Xml.XmlDocument
        $XmlDoc.Load($XmlFilePath)

        # Create a namespace manager
        [System.Xml.XmlNamespaceManager]$NsMgr = New-Object -TypeName System.Xml.XmlNamespaceManager -ArgumentList $XmlDoc.NameTable
        $NsMgr.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

        # Define a hashtable to store FileAttrib elements based on their properties
        [System.Collections.Hashtable]$FileAttribHash = @{}

        # Define a hashtable to store FileAttrib elements along with their associated Signer IDs
        [System.Collections.Hashtable]$FileAttribSignerHash = @{}

        # Define a hashtable to store Signer IDs and their associated SigningScenario IDs
        [System.Collections.Hashtable]$SignerScenarioHash = @{}

    }

    Process {

        # Iterate through each FileAttrib element
        foreach ($FileAttrib in $XmlDoc.SelectNodes('//ns:FileAttrib', $NsMgr)) {

            # Get the relevant properties
            [System.String]$MinimumFileVersion = $FileAttrib.GetAttribute('MinimumFileVersion')
            [System.String]$FileName = $FileAttrib.GetAttribute('FileName')
            [System.String]$InternalName = $FileAttrib.GetAttribute('InternalName')
            [System.String]$FileDescription = $FileAttrib.GetAttribute('FileDescription')
            [System.String]$FilePath = $FileAttrib.GetAttribute('FilePath')
            [System.String]$ProductName = $FileAttrib.GetAttribute('ProductName')

            # Generate a unique key based on relevant properties
            [System.String]$Key = "$MinimumFileVersion-$FileName-$InternalName-$FileDescription-$FilePath-$ProductName"

            # Check if the key already exists in the hashtable
            if (-not $FileAttribHash.ContainsKey($Key)) {

                # If not, add the key and create a new array to store the FileAttrib element
                $FileAttribHash[$Key] = @($FileAttrib)
            }
            else {
                # If the key already exists, append the FileAttrib element to the existing array
                $FileAttribHash[$Key] += $FileAttrib
            }

            # Get the Signer ID associated with this FileAttrib
            $SignerID = $XmlDoc.SelectSingleNode("//ns:Signer[ns:FileAttribRef/@RuleID='$($FileAttrib.GetAttribute('ID'))']/@ID", $NsMgr).Value

            # Add the FileAttrib and its associated Signer ID to the hashtable
            if (-not $FileAttribSignerHash.ContainsKey($Key)) {

                # If not, add the key and create a new array to store the Signer ID
                $FileAttribSignerHash[$Key] = @($SignerID)
            }
            else {
                # If the key already exists, append the Signer ID to the existing array
                $FileAttribSignerHash[$Key] += $SignerID
            }

            # Get the SigningScenario ID associated with this Signer ID
            $SigningScenarioID = $XmlDoc.SelectSingleNode("//ns:SigningScenario[ns:ProductSigners/ns:AllowedSigners/ns:AllowedSigner[@SignerId='$SignerID']]/@ID", $NsMgr).Value

            # Add the Signer ID and its associated SigningScenario ID to the hashtable
            if (-not $SignerScenarioHash.ContainsKey($SignerID)) {

                # add the Signer ID and create a new array to store the SigningScenario ID
                $SignerScenarioHash[$SignerID] = @($SigningScenarioID)
            }
            else {
                # If the Signer ID already exists, append the SigningScenario ID to the existing array
                $SignerScenarioHash[$SignerID] += $SigningScenarioID
            }
        }

        # Iterate through the hashtable to find and remove duplicates
        foreach ($Key in $FileAttribHash.Keys) {

            # If there's more than one FileAttrib element for this key
            if ($FileAttribHash[$Key].Count -gt 1) {

                # Get the unique Signer IDs associated with the FileAttrib elements
                $SignerIDs = $FileAttribSignerHash[$Key] | Select-Object -Unique

                # Get the unique SigningScenario IDs associated with the Signer IDs
                $ScenarioIDs = $SignerIDs | ForEach-Object -Process { $SignerScenarioHash[$_] } | Select-Object -Unique

                # If there are multiple unique SigningScenario IDs associated with this set of Signer IDs
                if ($ScenarioIDs.Count -gt 1) {
                    # Skip deduplication as the Signer IDs are in different Signing scenarios, meaning both User and Kernel modes are involved so it shouldn't be touched
                    continue
                }
                else {
                    # Remove duplicates by keeping only the first FileAttrib element
                    $FirstFileAttrib = $FileAttribHash[$Key] | Select-Object -First 1

                    # Iterate through the remaining FileAttrib elements
                    for ($i = 1; $i -lt $FileAttribHash[$Key].Count; $i++) {

                        # Get the duplicate FileAttrib element to remove based on the index
                        $FileAttribToRemove = $FileAttribHash[$Key][$i]

                        # Update FileAttribRef RuleID for associated Signers
                        $SignerIDs | ForEach-Object -Process {

                            # Get the Signer element associated with this Signer ID
                            $Signer = $XmlDoc.SelectSingleNode("//ns:Signer[@ID='$_']", $NsMgr)

                            # Get the FileAttribRef element associated with the duplicate FileAttrib element
                            $FileAttribRef = $Signer.SelectSingleNode("ns:FileAttribRef[@RuleID='$($FileAttribToRemove.GetAttribute('ID'))']", $NsMgr)

                            # Updating the RuleID of the duplicate <FileAttribRef> of the Signer before removing it and setting it to the RuleID of the unique remaining FileAttrib element
                            if ($Null -ne $FileAttribRef) {

                                if ($FirstFileAttrib.GetAttribute('ID') -notin $Signer.FileAttribRef.RuleID) {


                                    $FileAttribRef.SetAttribute('RuleID', $FirstFileAttrib.GetAttribute('ID'))
                                }
                            }
                        }
                        # Remove the duplicate FileAttrib element
                        Write-Verbose -Message "Remove-DuplicateFileAttrib: Removed duplicate FileAttrib with ID: $($FileAttribToRemove.GetAttribute('ID'))"
                        [System.Void]$FileAttribToRemove.ParentNode.RemoveChild($FileAttribToRemove)
                    }
                }
            }
        }

    }

    End {
        # Save the modified XML back to file
        $XmlDoc.Save($XmlFilePath)
    }
}
Export-ModuleMember -Function 'Remove-DuplicateFileAttrib_Semantic'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC+k7vhp8c86WbL
# Kwg60udQjt71Llf3NlXi9z9ZX+33K6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgCkEmQA6Bz4ztKSOupfOnuQhd/Bt9MEKu7Xyy114q6qswDQYJKoZIhvcNAQEB
# BQAEggIAPIf9nIuem5E+h461vsYOgvtTCZL6pJgJnL/84ZR1QF8KO+m68u50IvSC
# Oy4+EeN6OttimzwoP+wqYjZMFv/wskyFCZzKPnRpTcm36ixGSoEO7iTgrbcAN2n6
# MPlOKp5/GGumWzoNu4YxHsKCQNA9X1jyOUjkXhUFbXMcPjryQ60tHW7HsoDCuP9o
# qTHKDWvBd+97HohQzKUDtD3HAf64WSLbDxVKsRlmc1LE5zZGfMgiTYO0phw0gFSK
# G8c4rxfsG7tBo73Dl8JBYLnWYtiOB/Z3lk/N2atMPNgAsowHTjqOTGmSoO0Ckfy9
# Z03gnTp9Clf0Mcu/0MG/7aVKhUIoafNMNUWqRBBsEHIxc3+TkdUL8hIp2b5KhLTx
# x/2D9a+eBqWT1B2RPiyhktqrmgL/WUWM5hQmNvg38gaDoV/wF9CNFOdcJ/tEObqd
# pUdhWf6rFmaj6+b3vqjqoToqHeB1thdaXaqgGYU/xp1sCyk8Xe2McLdcEm2rgiG4
# am3kRspavl2BGW8gfMwu4I8/7AbH/wDFIVbkku2EegRR8Hw5RrCZbdQI1Qxs2wNG
# DlTfuAnBFIiAbCBxPsify3SLN06StlYQzzHBJNcs1WwOoZX42PFasNYZr8UR/12+
# z3xXf/Tm2OGW+u0aBzOW7b8milwL9+CWqN7InbMXFgUOmZMNWZU=
# SIG # End signature block
