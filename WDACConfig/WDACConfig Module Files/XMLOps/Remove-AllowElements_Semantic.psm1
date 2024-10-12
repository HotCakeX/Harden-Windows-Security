function Remove-AllowElements_Semantic {
    <#
    .SYNOPSIS
        A high performance function that removes duplicate <Allow> elements from the <FileRules> node and their corresponding <FileRuleRef> elements from the <FileRulesRef> node of the <ProductSigners> node under each <SigningScenario> node
        The criteria for removing duplicates is the Hash attribute of the <Allow> elements.
        If there are multiple <Allow> elements with the same Hash, the function keeps the first element and removes the rest.
        The function only considers <Allow> elements that are part of the same <SigningScenario> node and have the same Hash attribute as duplicates.
        After the function completes its operation, the XML file will not have any duplicate <Allow> elements, duplicate <FileRuleRef> elements or any orphan <FileRuleRef> elements.
        This is according to the CI Schema.
    .PARAMETER Path
        The path to the XML file to be modified
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
        # Load the XML file
        [System.Xml.XmlDocument]$Xml = Get-Content -Path $Path

        # Define the namespace manager
        [System.Xml.XmlNamespaceManager]$Ns = New-Object -TypeName System.Xml.XmlNamespaceManager -ArgumentList $Xml.NameTable
        $Ns.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

        # Get all of the <Allow> elements inside the <FileRules> node
        [System.Xml.XmlNodeList]$AllowElements = $Xml.SelectNodes('//ns:FileRules//ns:Allow', $Ns)

        # Get the <FileRules> node
        [System.Xml.XmlElement[]]$FileRulesNode = $Xml.SelectSingleNode('//ns:FileRules', $Ns)

        # Find the FileRulesRef Nodes inside the ProductSigners Nodes of each Signing Scenario
        [System.Xml.XmlNodeList]$UMCI_SigningScenario_ProductSigners_FileRulesRef_Node = $Xml.SelectNodes('//ns:SigningScenarios/ns:SigningScenario[@Value="12"]/ns:ProductSigners/ns:FileRulesRef/ns:FileRuleRef', $Ns)
        [System.Xml.XmlNodeList]$KMCI_SigningScenario_ProductSigners_FileRulesRef_Node = $Xml.SelectNodes('//ns:SigningScenarios/ns:SigningScenario[@Value="131"]/ns:ProductSigners/ns:FileRulesRef/ns:FileRuleRef', $Ns)

        [System.Xml.XmlNodeList]$UserModeFileRefs = $Xml.SelectNodes('//ns:SigningScenarios/ns:SigningScenario[@Value="12"]/ns:ProductSigners/ns:FileRulesRef', $Ns)
        [System.Xml.XmlNodeList]$KernelModeFileRefs = $Xml.SelectNodes('//ns:SigningScenarios/ns:SigningScenario[@Value="131"]/ns:ProductSigners/ns:FileRulesRef', $Ns)

        # Save the IDs of the FileRuleRef elements that are part of the User-Mode and Kernel-Mode signing scenarios as HashSets
        # These are unique because HashSets don't support duplicate values
        $UserMode_FileRulesRefIDs_HashSet = [System.Collections.Generic.HashSet[System.String]]$UMCI_SigningScenario_ProductSigners_FileRulesRef_Node.RuleID
        $KernelMode_FileRulesRefIDs_HashSet = [System.Collections.Generic.HashSet[System.String]]$KMCI_SigningScenario_ProductSigners_FileRulesRef_Node.RuleID

        # 2 Hashtables for User and Kernel mode <Allow> elements and their corresponding FileRuleRef elements together
        [System.Collections.Hashtable]$KernelModeHashTable = @{}
        [System.Collections.Hashtable]$UserModeHashTable = @{}

        # 2 Arrays to save the <Allow> elements of User and Kernel modes
        $ArrayOfUserModes = New-Object -TypeName System.Collections.Generic.List[System.Xml.XmlElement]
        $ArrayOfKernelModes = New-Object -TypeName System.Collections.Generic.List[System.Xml.XmlElement]
    }

    Process {

        # Separating User-Mode and Kernel-Mode <Allow> elements
        foreach ($AllowElement in $AllowElements) {

            # Check if the User-Mode <FileRulesRef> node has any elements
            # And then check if the current <Allow> element ID is part of the User-Mode <FileRulesRef> node
            if (($Null -ne $UserMode_FileRulesRefIDs_HashSet) -and ($UserMode_FileRulesRefIDs_HashSet.Contains($AllowElement.ID))) {
                $ArrayOfUserModes.Add($AllowElement)
            }

            # Check if the Kernel-Mode <FileRulesRef> node has any elements
            # And then check if the current <Allow> element ID is part of the Kernel-Mode <FileRulesRef> node
            elseif (($Null -ne $KernelMode_FileRulesRefIDs_HashSet) -and ($KernelMode_FileRulesRefIDs_HashSet.Contains($AllowElement.ID))) {
                $ArrayOfKernelModes.Add($AllowElement)
            }
            else {
                Write-Warning -Message "Remove-AllowElements_Semantic: The Allow element with ID $($AllowElement.ID) is not part of any Signing Scenario. It will be ignored."
            }
        }

        # Grouping the <Allow> elements by their Hash value, uniquely, So SHA1 and SHA256 hashes
        [System.Xml.XmlElement[]]$GroupsUserModes = foreach ($Item in ($ArrayOfUserModes | Group-Object -Property Hash)) {
            $Item.Group[0]
        }

        [System.Xml.XmlElement[]]$GroupsKernelModes = foreach ($Item in ($ArrayOfKernelModes | Group-Object -Property Hash)) {
            $Item.Group[0]
        }

        # Adding the User-Mode <Allow> elements and their corresponding <FileRuleRef> elements to the Hashtables
        foreach ($UserModeAllowElement in $GroupsUserModes) {

            # If the current <Allow> element ID is not already in the KernelModeHashTable, add it
            if (-NOT $UserModeHashTable.ContainsKey($UserModeAllowElement)) {

                # The key is the <Allow> element, the value is all of the <FileRuleRef> elements with the same RuleID as the Allow element's ID, without deduplication at this point
                # Cloning is necessary because after clearing the nodes, we would lose the reference to the original elements in those nodes
                $UserModeHashTable[@($UserModeAllowElement.Clone())] = @($Xml.SelectNodes("//ns:SigningScenarios/ns:SigningScenario[@Value='12']/ns:ProductSigners/ns:FileRulesRef/ns:FileRuleRef[@RuleID=`"$($UserModeAllowElement.ID)`"]", $Ns).Clone())
            }
        }

        # Adding the Kernel-Mode <Allow> elements and their corresponding <FileRuleRef> elements to the Hashtables
        foreach ($KernelModeAllowElement in $GroupsKernelModes) {

            # If the current <Allow> element ID is not already in the KernelModeHashTable, add it
            if (-NOT $KernelModeHashTable.ContainsKey($KernelModeAllowElement)) {

                # The key is the <Allow> element, the value is all of the <FileRuleRef> elements with the same RuleID as the Allow element's ID, without deduplication at this point
                $KernelModeHashTable[@($KernelModeAllowElement.Clone())] = @($Xml.SelectNodes("//ns:SigningScenarios/ns:SigningScenario[@Value='131']/ns:ProductSigners/ns:FileRulesRef/ns:FileRuleRef[@RuleID=`"$($KernelModeAllowElement.ID)`"]", $Ns).Clone())
            }
        }

        # Select and remove all <Allow> elements from <FileRules>
        [System.Xml.XmlNodeList]$AllowNodes = $Xml.SelectNodes('//ns:FileRules/ns:Allow', $NS)
        foreach ($Node in $AllowNodes) {
            [System.Void]$Node.ParentNode.RemoveChild($Node)
        }

        # Select and remove all <FileRuleRef> elements from <FileRulesRef> in each signing scenario
        [System.Xml.XmlNodeList]$SigningScenarios = $Xml.SelectNodes('//ns:SigningScenario/ns:ProductSigners/ns:FileRulesRef', $NS)
        foreach ($Scenario in $SigningScenarios) {
            [System.Xml.XmlNodeList]$FileRuleRefs = $Scenario.SelectNodes('ns:FileRuleRef', $NS)
            foreach ($FileRuleRef in $FileRuleRefs) {
                [System.Void]$FileRuleRef.ParentNode.RemoveChild($FileRuleRef)
            }
        }

        # Add Unique <Allow> elements and their corresponding <FileRuleRef> elements back to the XML file for the Kernel-Mode files
        foreach ($Group in $UserModeHashTable.GetEnumerator()) {
            # Add the unique <Allow> element
            [System.Void]$FileRulesNode.AppendChild($Group.Key[0])
            # Add the unique <FileRuleRef> element, using [0] index because the key is an array even though it only has 1 element
            $ToAppend1 = foreach ($Item in ($Group.Value.GetEnumerator() | Group-Object -Property RuleID)) {
                $Item.Group[0]
            }
            [System.Void]$UserModeFileRefs.AppendChild($ToAppend1)
        }

        # Add Unique <Allow> elements and their corresponding <FileRuleRef> elements back to the XML file for the Kernel-Mode files
        foreach ($Group in $KernelModeHashTable.GetEnumerator()) {
            # Add the unique <Allow> element, using [0] index because the key is an array even though it only has 1 element
            [System.Void]$FileRulesNode.AppendChild($Group.Key[0])
            # Add the unique <FileRuleRef> element
            $ToAppend2 = foreach ($Item in ($Group.Value.GetEnumerator() | Group-Object -Property RuleID)) {
                $Item.Group[0]
            }
            [System.Void]$KernelModeFileRefs.AppendChild($ToAppend2)
        }
    }

    End {
        $Xml.Save($Path)
    }
}
Export-ModuleMember -Function 'Remove-AllowElements_Semantic'
