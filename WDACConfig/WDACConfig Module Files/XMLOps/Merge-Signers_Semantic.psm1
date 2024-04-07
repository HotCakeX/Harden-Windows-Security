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
        $SignersNode.RemoveAll()

        # Clear the existing AllowedSigners and CiSigners nodes from any type of Signer
        [System.Xml.XmlElement]$AllowedSigners12ToClear = $Xml.SelectSingleNode('//ns:SigningScenarios/ns:SigningScenario[@Value="12"]/ns:ProductSigners/ns:AllowedSigners', $Ns)
        [System.Xml.XmlElement]$AllowedSigners131ToClear = $Xml.SelectSingleNode('//ns:SigningScenarios/ns:SigningScenario[@Value="131"]/ns:ProductSigners/ns:AllowedSigners', $Ns)
        [System.Xml.XmlElement]$CiSignersToClear = $Xml.SelectSingleNode('//ns:CiSigners', $Ns)

        $AllowedSigners12ToClear.RemoveAll()
        $AllowedSigners131ToClear.RemoveAll()
        $CiSignersToClear.RemoveAll()

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