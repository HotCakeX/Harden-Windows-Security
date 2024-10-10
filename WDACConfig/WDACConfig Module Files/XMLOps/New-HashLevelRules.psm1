Function New-HashLevelRules {
    <#
    .SYNOPSIS
        Creates new Hash level rules in an XML file
        For each hash data, it creates 2 Hash rules, one for Authenticode SHA2-256 and one for SHA1 hash
        It also adds the FileRulesRef for each hash to the ProductSigners node of the correct signing scenario (Kernel/User mode)
    .PARAMETER Hashes
        The Hashes to be used for creating the rules, they are the output of the BuildSignerAndHashObjects Method
    .PARAMETER XmlFilePath
        The path to the XML file to be modified
    .INPUTS
        System.Collections.Generic.List[WDACConfig.HashCreator]
        System.IO.FileInfo
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    Param(
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[WDACConfig.HashCreator]]$Hashes,
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath
    )
    Begin {
        [WDACConfig.Logger]::Write("New-HashLevelRules: There are $($Hashes.Count) Hash rules to be added to the XML file")

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
