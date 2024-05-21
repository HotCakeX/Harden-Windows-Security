Function Merge-Signers_Semantic {
    <#
    .SYNOPSIS
        Merges the FilePublisher and Publisher Signers in an XML file based on their TBS, Name, and CertPublisher values
        For each FilePublisher signer, if two signers are found with the same TBS, Name, and CertPublisher, only one of them will be kept, and their FileAttribRefs are merged
        For each Publisher signer, if two signers are found with the same TBS, Name, and CertPublisher, only one of them will be kept

        If two signers have the same TBS, Name, and CertPublisher but only one of them has FileAttribRefs, then they are not the same. This function makes the distinction between FilePublisher and Publisher signers.
        This function makes the distinction between the Signers that are part of Signing Scenario 131 and the ones that are part of Signing Scenario 12.
        So there are 4 different Signer types to consider.

        At the end, the XML file will have unique FilePublisher and Publisher signers for Signing Scenario 131 and 12, unique elements in the <AllowedSigners> and <CiSigners>

        Also, each Signer will have unique and valid FileAttribRef elements with IDs that point to an existing FileAttrib element in the <FileRules> node
    .PARAMETER XmlFilePath
        The path to the XML file to be modified
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    Param(
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath
    )
    Begin {
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Load the XML file
        [System.Xml.XmlDocument]$Xml = Get-Content -Path $XmlFilePath
    }

    Process {

        # Define the namespace manager
        [System.Xml.XmlNamespaceManager]$Ns = New-Object -TypeName System.Xml.XmlNamespaceManager -ArgumentList $Xml.NameTable
        $Ns.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

        # Get the User Mode Signing Scenario node
        [System.Xml.XmlNodeList]$AllowedSigners12 = $Xml.SelectNodes('//ns:SigningScenarios/ns:SigningScenario[@Value="12"]/ns:ProductSigners/ns:AllowedSigners', $Ns)

        # Get the Kernel Mode Signing Scenario node
        [System.Xml.XmlNodeList]$AllowedSigners131 = $Xml.SelectNodes('//ns:SigningScenarios/ns:SigningScenario[@Value="131"]/ns:ProductSigners/ns:AllowedSigners', $Ns)

        # Get the CiSigners node
        [System.Xml.XmlNodeList]$CiSigners = $Xml.SelectNodes('//ns:CiSigners', $Ns)

        # Find all Signer nodes
        [System.Xml.XmlNodeList]$SignerNodes = $Xml.SelectNodes('//ns:Signers/ns:Signer', $Ns)

        # Create a hashtable to track unique FilePublisher signers for Signing Scenario 131 - Signers that have at least one FileAttribRef
        [System.Collections.Hashtable]$UniqueFilePublisherSigners131 = @{}

        # Create a hashtable to track unique Publisher signers for Signing Scenario 131 - Signers that have no FileAttribRef
        [System.Collections.Hashtable]$UniquePublisherSigners131 = @{}

        # Create a hashtable to track unique FilePublisher signers for Signing Scenario 12 - Signers that have at least one FileAttribRef
        [System.Collections.Hashtable]$UniqueFilePublisherSigners12 = @{}

        # Create a hashtable to track unique Publisher signers for Signing Scenario 12 - Signers that have no FileAttribRef
        [System.Collections.Hashtable]$UniquePublisherSigners12 = @{}

        # XPath expression to select the Signing Scenario with value 131
        [System.String]$SigningScenario131XPath = '//ns:SigningScenarios/ns:SigningScenario[@Value="131"]'

        # Select the Signing Scenario with value 131
        [System.Xml.XmlNode]$SigningScenario131Node = $Xml.SelectSingleNode($SigningScenario131XPath, $Ns)

        # Find all of the <FileAttrib> elements in the <FileRules> node
        [System.Xml.XmlNodeList]$FileRulesElements = $Xml.SelectNodes('//ns:FileRules/ns:FileAttrib', $Ns)

        $FileRulesValidID_HashSet = [System.Collections.Generic.HashSet[System.String]]$FileRulesElements.ID

        if ($SignerNodes.Count -eq 0) {
            Write-Verbose -Message 'Merge-Signers: No Signer nodes found in the XML file. Exiting the function.'
            Return
        }

        # Iterate over each Signer node
        foreach ($Signer in $SignerNodes) {

            # If the signer has FileAttribRefs, it is a FilePublisher signer
            if ($Signer.SelectNodes('ns:FileAttribRef', $Ns).Count -gt 0) {

                # Making sure that each FilePublisher Signer has valid and unique FileAttribRef elements with IDs that point to an existing FileAttrib element in the <FileRules> node
                $ContentToReplaceWith = $Signer.FileAttribRef | Where-Object -FilterScript { $FileRulesValidID_HashSet -contains $_.RuleID } | Group-Object -Property RuleID | ForEach-Object -Process { $_.Group[0] }

                [System.Int64]$Before = $Signer.FileAttribRef.count

                # Remove all FileAttribRef elements from the Signer, whether they are valid or not
                $Signer.FileAttribRef | ForEach-Object -Process {
                    [System.Void]$_.ParentNode.RemoveChild($_)
                }

                # Add the valid FileAttribRef elements back to the Signer
                $ContentToReplaceWith | ForEach-Object -Process {
                    [System.Void]$Signer.AppendChild($Xml.ImportNode($_, $true))
                }

                [System.Int64]$After = $Signer.FileAttribRef.count

                if ($Before -ne $After) {
                    Write-Verbose -Message "Merge-Signers: Removed $($Before - $After) FileAttribRef elements from Signer with ID $($Signer.ID)."
                }

                # Determine the Signing Scenario based on the AllowedSigners
                $SigningScenario = $SigningScenario131Node.SelectSingleNode("./ns:ProductSigners/ns:AllowedSigners/ns:AllowedSigner[@SignerId='$($Signer.GetAttribute('ID'))']", $Ns)

                # If the signer is part of Signing Scenario 131
                if ($SigningScenario) {

                    # Create a unique key for each FilePublisher signer based on TBS, Name, and CertPublisher
                    [System.String]$FilePublisherKey = $Signer.SelectSingleNode('ns:CertRoot', $Ns).GetAttribute('Value') + '|' +
                    $Signer.GetAttribute('Name') + '|' +
                    ($Signer.SelectSingleNode('ns:CertPublisher', $Ns) ? $Signer.SelectSingleNode('ns:CertPublisher', $Ns).GetAttribute('Value') : $Null)

                    # If the signer is not in the hashtable, add it with its necessary details
                    if (-not $UniqueFilePublisherSigners131.ContainsKey($FilePublisherKey)) {

                        # Create a temp hashtable to store the signer and its details
                        [System.Collections.Hashtable]$FilePublisherKeyTemp = @{}
                        $FilePublisherKeyTemp['Signer'] = @($Signer.Clone())
                        $FilePublisherKeyTemp['AllowedSigner'] = $AllowedSigners131.SelectNodes("//ns:AllowedSigner[@SignerId='$($Signer.GetAttribute('ID'))']", $Ns)

                        # Add the temp signer hashtable to the main hashtable
                        $UniqueFilePublisherSigners131[$FilePublisherKey] = $FilePublisherKeyTemp
                    }

                    # If the signer is already in the hashtable
                    else {

                        # Get the FileAttribRefs of the existing signer
                        [System.Xml.XmlNodeList]$FileAttribRefs = $Signer.SelectNodes('ns:FileAttribRef', $Ns)

                        # add each of its FileAttribRefs to the existing signer
                        foreach ($FileAttribRef in $FileAttribRefs) {
                            [System.Void]$UniqueFilePublisherSigners131[$FilePublisherKey]['Signer'].AppendChild($Xml.ImportNode($FileAttribRef, $true))
                        }

                        Write-Verbose -Message "Merge-Signers: Merged FilePublisher signer for Signing Scenario 131 with IDs: $($UniqueFilePublisherSigners131[$FilePublisherKey].ID) and $($Signer.ID). Their FileAttribRefs are merged."
                    }
                }
                # If the signer is part of Signing Scenario 12
                else {

                    # Create a unique key for each FilePublisher signer based on TBS, Name, and CertPublisher
                    [System.String]$FilePublisherKey = $Signer.SelectSingleNode('ns:CertRoot', $Ns).GetAttribute('Value') + '|' +
                    $Signer.GetAttribute('Name') + '|' +
                    ($Signer.SelectSingleNode('ns:CertPublisher', $Ns) ? $Signer.SelectSingleNode('ns:CertPublisher', $Ns).GetAttribute('Value') : $Null)

                    # If the signer is not in the hashtable, add it with its FileAttribRefs
                    if (-not $UniqueFilePublisherSigners12.ContainsKey($FilePublisherKey)) {

                        # Create a temp hashtable to store the signer and its details
                        [System.Collections.Hashtable]$FilePublisherKeyTemp = @{}
                        $FilePublisherKeyTemp['Signer'] = @($Signer.Clone())
                        $FilePublisherKeyTemp['AllowedSigner'] = $AllowedSigners12.SelectNodes("//ns:AllowedSigner[@SignerId='$($Signer.GetAttribute('ID'))']", $Ns)
                        $FilePublisherKeyTemp['CiSigners'] = $CiSigners.SelectNodes("//ns:CiSigner[@SignerId='$($Signer.GetAttribute('ID'))']", $Ns)

                        # Add the temp signer hashtable to the main hashtable
                        $UniqueFilePublisherSigners12[$FilePublisherKey] = $FilePublisherKeyTemp
                    }

                    # If the signer is already in the hashtable
                    else {

                        # Get the FileAttribRefs of the existing signer
                        [System.Xml.XmlNodeList]$FileAttribRefs = $Signer.SelectNodes('ns:FileAttribRef', $Ns)

                        # add each of its FileAttribRefs to the existing signer
                        foreach ($FileAttribRef in $FileAttribRefs) {
                            [System.Void]$UniqueFilePublisherSigners12[$FilePublisherKey]['Signer'].AppendChild($Xml.ImportNode($FileAttribRef, $true))
                        }

                        Write-Verbose -Message "Merge-Signers: Merged FilePublisher signer for Signing Scenario 12 with IDs: $($UniqueFilePublisherSigners12[$FilePublisherKey].ID) and $($Signer.ID). Their FileAttribRefs are merged."
                    }
                }
            }

            # If the signer has no FileAttribRefs, it is a Publisher or PCA signer
            elseif ($Signer.SelectNodes('ns:FileAttribRef', $Ns).Count -eq 0) {

                # Determine the Signing Scenario based on the AllowedSigners
                $SigningScenario = $SigningScenario131Node.SelectSingleNode("./ns:ProductSigners/ns:AllowedSigners/ns:AllowedSigner[@SignerId='$($Signer.GetAttribute('ID'))']", $Ns)

                # If the signer is part of Signing Scenario 131
                if ($SigningScenario) {

                    # Create a unique key for each Publisher signer based on TBS, Name, and CertPublisher
                    [System.String]$PublisherKey = $Signer.SelectSingleNode('ns:CertRoot', $Ns).GetAttribute('Value') + '|' +
                    $Signer.GetAttribute('Name') + '|' +
                    ($Signer.SelectSingleNode('ns:CertPublisher', $Ns) ? $Signer.SelectSingleNode('ns:CertPublisher', $Ns).GetAttribute('Value') : $Null)

                    # If the signer is not in the hashtable, add it with its FileAttribRefs
                    if (-not $UniquePublisherSigners131.ContainsKey($PublisherKey)) {

                        # Create a temp hashtable to store the signer and its details
                        [System.Collections.Hashtable]$PublisherKeyTemp = @{}
                        $PublisherKeyTemp['Signer'] = @($Signer.Clone())
                        $PublisherKeyTemp['AllowedSigner'] = $AllowedSigners131.SelectNodes("//ns:AllowedSigner[@SignerId='$($Signer.GetAttribute('ID'))']", $Ns)

                        # Add the temp signer hashtable to the main hashtable
                        $UniquePublisherSigners131[$PublisherKey] = $PublisherKeyTemp
                    }
                    else {
                        Write-Verbose -Message "Merge-Signers: Excluded Publisher signer for Signing Scenario 131 with ID: $($Signer.ID). Only one Publisher signer is allowed per TBS, Name, and CertPublisher."
                    }
                }
                # If the signer is part of Signing Scenario 12
                else {

                    # Create a unique key for each Publisher signer based on TBS, Name, and CertPublisher
                    [System.String]$PublisherKey = $Signer.SelectSingleNode('ns:CertRoot', $Ns).GetAttribute('Value') + '|' +
                    $Signer.GetAttribute('Name') + '|' +
                    ($Signer.SelectSingleNode('ns:CertPublisher', $Ns) ? $Signer.SelectSingleNode('ns:CertPublisher', $Ns).GetAttribute('Value') : $Null)

                    # If the signer is not in the hashtable, add it with its FileAttribRefs
                    if (-not $UniquePublisherSigners12.ContainsKey($PublisherKey)) {

                        # Create a temp hashtable to store the signer and its details
                        [System.Collections.Hashtable]$PublisherKeyTemp = @{}
                        $PublisherKeyTemp['Signer'] = @($Signer.Clone())
                        $PublisherKeyTemp['AllowedSigner'] = $AllowedSigners12.SelectNodes("//ns:AllowedSigner[@SignerId='$($Signer.GetAttribute('ID'))']", $Ns)
                        $PublisherKeyTemp['CiSigners'] = $CiSigners.SelectNodes("//ns:CiSigner[@SignerId='$($Signer.GetAttribute('ID'))']", $Ns)

                        # Add the temp signer hashtable to the main hashtable
                        $UniquePublisherSigners12[$PublisherKey] = $PublisherKeyTemp
                    }
                    else {
                        Write-Verbose -Message "Merge-Signers: Excluded Publisher signer for Signing Scenario 12 with ID: $($Signer.ID). Only one Publisher signer is allowed per TBS, Name, and CertPublisher."
                    }
                }
            }
        }

        $UniqueFilePublisherSigners12.Values | ForEach-Object -Process {

            # Create a unique ID for each signer
            [System.String]$Guid = [System.Guid]::NewGuid().ToString().replace('-', '').ToUpper()
            $Guid = "ID_SIGNER_A_$Guid"

            # Set the ID attribute of the Signer node to the unique ID
            foreach ($Signer in $_['Signer']) {
                $Signer.SetAttribute('ID', $Guid)
            }
            # Set the SignerId attribute of the AllowedSigner node to the unique ID
            foreach ($AllowedSigner in $_['AllowedSigner']) {
                $AllowedSigner.SetAttribute('SignerId', $Guid)
            }
            # Set the SignerId attribute of the CiSigner node to the unique ID
            foreach ($CiSigner in $_['CiSigners']) {
                $CiSigner.SetAttribute('SignerId', $Guid)
            }
        }

        $UniquePublisherSigners12.Values | ForEach-Object -Process {

            # Create a unique ID for each signer
            [System.String]$Guid = [System.Guid]::NewGuid().ToString().replace('-', '').ToUpper()
            $Guid = "ID_SIGNER_B_$Guid"

            # Set the ID attribute of the Signer node to the unique ID
            foreach ($Signer in $_['Signer']) {
                $Signer.SetAttribute('ID', $Guid)
            }
            # Set the SignerId attribute of the AllowedSigner node to the unique ID
            foreach ($AllowedSigner in $_['AllowedSigner']) {
                $AllowedSigner.SetAttribute('SignerId', $Guid)
            }
            # Set the SignerId attribute of the CiSigner node to the unique ID
            foreach ($CiSigner in $_['CiSigners']) {
                $CiSigner.SetAttribute('SignerId', $Guid)
            }
        }

        $UniquePublisherSigners131.Values | ForEach-Object -Process {

            # Create a unique ID for each signer
            [System.String]$Guid = [System.Guid]::NewGuid().ToString().replace('-', '').ToUpper()
            $Guid = "ID_SIGNER_B_$Guid"

            # Set the ID attribute of the Signer node to the unique ID
            foreach ($Signer in $_['Signer']) {
                $Signer.SetAttribute('ID', $Guid)
            }
            # Set the SignerId attribute of the AllowedSigner node to the unique ID
            foreach ($AllowedSigner in $_['AllowedSigner']) {
                $AllowedSigner.SetAttribute('SignerId', $Guid)
            }
        }

        $UniqueFilePublisherSigners131.Values | ForEach-Object -Process {

            # Create a unique ID for each signer
            [System.String]$Guid = [System.Guid]::NewGuid().ToString().replace('-', '').ToUpper()
            $Guid = "ID_SIGNER_A_$Guid"

            # Set the ID attribute of the Signer node to the unique ID
            foreach ($Signer in $_['Signer']) {
                $Signer.SetAttribute('ID', $Guid)
            }

            # Set the SignerId attribute of the AllowedSigner node to the unique ID
            foreach ($AllowedSigner in $_['AllowedSigner']) {
                $AllowedSigner.SetAttribute('SignerId', $Guid)
            }
        }

        # Clear the existing Signers node from any type of Signer
        [System.Xml.XmlElement]$SignersNode = $Xml.SelectSingleNode('//ns:Signers', $Ns)

        if ($null -ne $SignersNode) {
            $SignersNode.RemoveAll()
        }

        # Clear the existing AllowedSigners and CiSigners nodes from any type of Signer
        [System.Xml.XmlElement]$AllowedSigners12ToClear = $Xml.SelectSingleNode('//ns:SigningScenarios/ns:SigningScenario[@Value="12"]/ns:ProductSigners/ns:AllowedSigners', $Ns)
        [System.Xml.XmlElement]$AllowedSigners131ToClear = $Xml.SelectSingleNode('//ns:SigningScenarios/ns:SigningScenario[@Value="131"]/ns:ProductSigners/ns:AllowedSigners', $Ns)
        [System.Xml.XmlElement]$CiSignersToClear = $Xml.SelectSingleNode('//ns:CiSigners', $Ns)

        # Making sure the nodes are not null meaning they are not empty, before attempting to remove all of their elements
        if ($null -ne $AllowedSigners12ToClear) {
            $AllowedSigners12ToClear.RemoveAll()
        }

        if ($null -ne $AllowedSigners131ToClear) {
            $AllowedSigners131ToClear.RemoveAll()
        }

        if ($null -ne $CiSignersToClear) {
            $CiSignersToClear.RemoveAll()
        }

        # Repopulate the Signers, AllowedSigners and CiSigners nodes with the unique values

        # Add the unique FilePublisher signers for Signing Scenario 131 back to the Signers node
        foreach ($Signer in $UniqueFilePublisherSigners131.Values) {

            # index 0 is used because otherwise it would throw an error about array not being able to be appended to the XML
            # first index makes sure it is XmlElement type
            [System.Void]$SignersNode.AppendChild($Signer['Signer'][0])

            # A warning message to catch any edge cases that shouldn't happen
            if (($Signer['AllowedSigner'].SignerId | Select-Object -Unique).count -gt 1) {
                Write-Warning -Message "Multiple AllowedSigners found for FilePublisher signer for Signing Scenario 131 with ID $($Signer['Signer'][0].ID)."
            }

            [System.Void]$AllowedSigners131.AppendChild($Signer['AllowedSigner'].Count -gt 1 ? $Signer['AllowedSigner'][0] : $Signer['AllowedSigner'])
        }

        # Add the unique Publisher signers for Signing Scenario 131 back to the Signers node
        foreach ($Signer in $UniquePublisherSigners131.Values) {

            # A warning message to catch any edge cases that shouldn't happen
            if (($Signer['AllowedSigner'].SignerId | Select-Object -Unique).count -gt 1) {
                Write-Warning -Message "Multiple AllowedSigners found for Publisher signer for Signing Scenario 131 with ID $($Signer['Signer'][0].ID)."
            }

            # Add the <Signer> element to the <Signers> node
            [System.Void]$SignersNode.AppendChild($Signer['Signer'][0])

            # Add the <AllowedSigner> element to the <AllowedSigners> node
            [System.Void]$AllowedSigners131.AppendChild($Signer['AllowedSigner'].Count -gt 1 ? $Signer['AllowedSigner'][0] : $Signer['AllowedSigner'])
        }

        # Add the unique FilePublisher signers for Signing Scenario 12 back to the Signers node
        foreach ($Signer in $UniqueFilePublisherSigners12.Values) {

            # A warning message to catch any edge cases that shouldn't happen
            if (($Signer['AllowedSigner'].SignerId | Select-Object -Unique).count -gt 1) {
                Write-Warning -Message "Multiple AllowedSigners found for FilePublisher signer for Signing Scenario 12 with ID $($Signer['Signer'][0].ID)."
            }

            # A warning message to catch any edge cases that shouldn't happen
            if (($Signer['CiSigners'].SignerId | Select-Object -Unique).count -gt 1) {
                Write-Warning -Message "Multiple CiSigners found for FilePublisher signer for Signing Scenario 12 with ID $($Signer['Signer'][0].ID)."
            }

            # Add the <Signer> element to the <Signers> node
            [System.Void]$SignersNode.AppendChild($Signer['Signer'][0])

            # Add the <AllowedSigner> element to the <AllowedSigners> node
            [System.Void]$AllowedSigners12.AppendChild($Signer['AllowedSigner'].Count -gt 1 ? $Signer['AllowedSigner'][0] : $Signer['AllowedSigner'])

            if ($Null -ne $Signer['CiSigners']) {
                # Add the <CiSigner> element to the <CiSigners> node
                [System.Void]$CiSigners.AppendChild($Signer['CiSigners'].Count -gt 1 ? $Signer['CiSigners'][0] : $Signer['CiSigners'])
            }
        }

        # Add the unique Publisher signers for Signing Scenario 12 back to the Signers node
        foreach ($Signer in $UniquePublisherSigners12.Values) {

            # A warning message to catch any edge cases that shouldn't happen
            if (($Signer['AllowedSigner'].SignerId | Select-Object -Unique).count -gt 1) {
                Write-Warning -Message "Multiple AllowedSigners found for Publisher signer for Signing Scenario 12 with ID $($Signer['Signer'][0].ID)."
            }

            # A warning message to catch any edge cases that shouldn't happen
            if (($Signer['CiSigners'].SignerId | Select-Object -Unique).count -gt 1) {
                Write-Warning -Message "Multiple CiSigners found for Publisher signer for Signing Scenario 12 with ID $($Signer['Signer'][0].ID)."
            }

            # Add the <Signer> element to the <Signers> node
            [System.Void]$SignersNode.AppendChild($Signer['Signer'][0])

            # Add the <AllowedSigner> element to the <AllowedSigners> node
            [System.Void]$AllowedSigners12.AppendChild($Signer['AllowedSigner'].Count -gt 1 ? $Signer['AllowedSigner'][0] : $Signer['AllowedSigner'])

            if ($Null -ne $Signer['CiSigners']) {
                # Add the <CiSigner> element to the <CiSigners> node
                [System.Void]$CiSigners.AppendChild($Signer['CiSigners'].Count -gt 1 ? $Signer['CiSigners'][0] : $Signer['CiSigners'])
            }
        }

    }

    End {
        # Save the changes back to the XML file
        $Xml.Save($XmlFilePath)
    }
}
Export-ModuleMember -Function 'Merge-Signers_Semantic'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCA0g2E/bWZSWqR
# nDu6aV9KLFaH0IpspGoGAw0UQEQs0aCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQg2lYv809+vqxv2OvkzBPf4jdx7scSVUsXDnSy5NVJWGcwDQYJKoZIhvcNAQEB
# BQAEggIAiA6OpujCZ7kLCC8F3eHZQC1qbjoX4Ay64hPyBThEpP16on3UwU/JjTzz
# Q1vc0onCqWt9AAYrUprJywnJwQramXI8MKgsoxlBq5Lq33ohkTv3f4PzuwOobqa6
# RJFeQWW1Mc09yU56B02+gUvnN88h7WnCGfcyFNo4B8EByIjG/AMXeSNRP3xZG2lH
# yT1E/+voqtm1OQGESHxiNi5P+TxJbzXmL5PTUlWOy1Wwh9J6sWn/n8hM/LEZdbC0
# hJROVCay3hSQQNgxZqOp3Z6MCZ11pztaekNkSPKb9mqr/Y8lNG7lOmq9BLj1SjsH
# fbBhgNZVP3dYW+tbNfNov8iWbNNG0IZpJsBqTWdVMhK9HjezYGRGudL3csgvWdjX
# aY5JIGiSTJEMpyf3E/XULmZWx4n5b/b/b9lSyi025EPNwpX50ouh5y1LEqoExaY0
# TFOXn3PBdJDS5JskedFAR4rPF+63jUh991h8G+bUYva0WfsX9rlXwCU55igBd8xx
# mo1jT+Yr5JIlYdiIto0q0RD7f4ond2SjkrIoUTUTIFch1n6Pw/dkGHW2wL1ItTFj
# j0Ffdns/8/MBVV+LpJKsXsg6BcdzqXfkKnGkL+MJ8v5JzcmNPPbuVgWzADdyl/9N
# UMdivq9YPODBc1v/LvSQ0DpUBqR1kf/qM5rY5AEXecLghsusxDo=
# SIG # End signature block
