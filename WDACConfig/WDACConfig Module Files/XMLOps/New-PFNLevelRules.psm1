Function New-PFNLevelRules {
    [CmdletBinding()]
    [OutputType([System.Void])]
    Param (
        [Alias('PFN')]
        [Parameter(Mandatory = $true)][System.String[]]$PackageFamilyNames,
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath
    )
    Begin {
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
