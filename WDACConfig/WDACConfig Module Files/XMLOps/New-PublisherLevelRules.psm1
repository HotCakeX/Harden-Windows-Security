Function New-PublisherLevelRules {
    <#
    .SYNOPSIS
        Creates new Publisher level rules in an XML file
        Each rules includes the Signers, AllowedSigners, and CiSigners (depending on kernel/user mode)
    .PARAMETER PublisherSigners
        The PublisherSigners to be used for creating the rules, they are the output of the BuildSignerAndHashObjects Method
    .PARAMETER XmlFilePath
        The path to the XML file to be modified
    .INPUTS
        System.Collections.Generic.List[WDACConfig.PublisherSignerCreator]
        System.IO.FileInfo
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    Param (
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[WDACConfig.PublisherSignerCreator]]$PublisherSigners,
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath
    )
    Begin {
        [WDACConfig.Logger]::Write("New-PublisherLevelRules: There are $($PublisherSigners.Count) Publisher Signers to be added to the XML file")

        # Load the XML file
        [System.Xml.XmlDocument]$Xml = Get-Content -Path $XmlFilePath

        # Define the namespace manager
        [System.Xml.XmlNamespaceManager]$Ns = New-Object -TypeName System.Xml.XmlNamespaceManager -ArgumentList $Xml.NameTable
        $Ns.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

        # Find the Signers Node
        [System.Xml.XmlElement]$SignersNode = $Xml.SelectSingleNode('//ns:Signers', $Ns)

        # Find the ProductSigners Nodes
        [System.Xml.XmlElement]$UMCI_ProductSigners_Node = $Xml.SelectSingleNode('//ns:SigningScenarios/ns:SigningScenario[@Value="12"]/ns:ProductSigners', $Ns)
        [System.Xml.XmlElement]$KMCI_ProductSigners_Node = $Xml.SelectSingleNode('//ns:SigningScenarios/ns:SigningScenario[@Value="131"]/ns:ProductSigners', $Ns)

        # Find the CiSigners Node
        [System.Xml.XmlElement]$CiSignersNode = $Xml.SelectSingleNode('//ns:CiSigners', $Ns)
    }

    Process {

        foreach ($PublisherData in $PublisherSigners) {

            #Region Creating Signers

            # Create signer for each certificate details in the PublisherSigners
            # Some files are signed by multiple signers
            foreach ($SignerData in $PublisherData.CertificateDetails) {

                [System.String]$Guid = [System.Guid]::NewGuid().ToString().replace('-', '').ToUpper()

                [System.String]$SignerID = "ID_SIGNER_B_$Guid"

                # Create the new Signer element
                [System.Xml.XmlElement]$NewSignerNode = $Xml.CreateElement('Signer', $SignersNode.NamespaceURI)
                $NewSignerNode.SetAttribute('ID', $SignerID)
                $NewSignerNode.SetAttribute('Name', $SignerData.IntermediateCertName)

                # Create the CertRoot element and add it to the Signer element
                [System.Xml.XmlElement]$CertRootNode = $Xml.CreateElement('CertRoot', $SignersNode.NamespaceURI)
                $CertRootNode.SetAttribute('Type', 'TBS')
                $CertRootNode.SetAttribute('Value', $SignerData.IntermediateCertTBS)
                [System.Void]$NewSignerNode.AppendChild($CertRootNode)

                # Create the CertPublisher element and add it to the Signer element
                [System.Xml.XmlElement]$CertPublisherNode = $Xml.CreateElement('CertPublisher', $SignersNode.NamespaceURI)
                $CertPublisherNode.SetAttribute('Value', $SignerData.LeafCertName)
                [System.Void]$NewSignerNode.AppendChild($CertPublisherNode)

                # Add the new Signer element to the Signers node
                [System.Void]$SignersNode.AppendChild($NewSignerNode)

                #Region Adding signer to the Signer Scenario and CiSigners

                # For User-Mode files
                if ($PublisherData.SiSigningScenario -eq '1') {

                    # Check if AllowedSigners node exists, if not, create it
                    $UMCI_Temp_AllowedSignersNode = $UMCI_ProductSigners_Node.SelectSingleNode('ns:AllowedSigners', $Ns)

                    if ($Null -eq $UMCI_Temp_AllowedSignersNode) {

                        [System.Xml.XmlElement]$UMCI_Temp_AllowedSignersNode = $Xml.CreateElement('AllowedSigners', $Ns.LookupNamespace('ns'))
                        [System.Void]$UMCI_ProductSigners_Node.AppendChild($UMCI_Temp_AllowedSignersNode)

                    }

                    # Create Allowed Signers inside the <AllowedSigners> -> <ProductSigners> -> <SigningScenario Value="12">
                    [System.Xml.XmlElement]$NewUMCIAllowedSignerNode = $Xml.CreateElement('AllowedSigner', $UMCI_Temp_AllowedSignersNode.NamespaceURI)
                    $NewUMCIAllowedSignerNode.SetAttribute('SignerId', $SignerID)
                    [System.Void]$UMCI_Temp_AllowedSignersNode.AppendChild($NewUMCIAllowedSignerNode)

                    # Create a CI Signer for the User Mode Signer
                    [System.Xml.XmlElement]$NewCiSignerNode = $Xml.CreateElement('CiSigner', $CiSignersNode.NamespaceURI)
                    $NewCiSignerNode.SetAttribute('SignerId', $SignerID)
                    [System.Void]$CiSignersNode.AppendChild($NewCiSignerNode)
                }

                # For Kernel-Mode files
                elseif ($PublisherData.SiSigningScenario -eq '0') {

                    # Check if AllowedSigners node exists, if not, create it
                    $KMCI_Temp_AllowedSignersNode = $KMCI_ProductSigners_Node.SelectSingleNode('ns:AllowedSigners', $Ns)

                    if ($Null -eq $KMCI_Temp_AllowedSignersNode) {

                        [System.Xml.XmlElement]$KMCI_Temp_AllowedSignersNode = $Xml.CreateElement('AllowedSigners', $Ns.LookupNamespace('ns'))
                        [System.Void]$KMCI_ProductSigners_Node.AppendChild($KMCI_Temp_AllowedSignersNode)

                    }

                    # Create Allowed Signers inside the <AllowedSigners> -> <ProductSigners> -> <SigningScenario Value="131">
                    [System.Xml.XmlElement]$NewKMCIAllowedSignerNode = $Xml.CreateElement('AllowedSigner', $KMCI_Temp_AllowedSignersNode.NamespaceURI)
                    $NewKMCIAllowedSignerNode.SetAttribute('SignerId', $SignerID)
                    [System.Void]$KMCI_Temp_AllowedSignersNode.AppendChild($NewKMCIAllowedSignerNode)

                    # Kernel-Mode signers don't need CI Signers
                }

                #Endregion Adding signer to the Signer Scenario and CiSigners

            }
            #Endregion Creating Signers
        }
    }

    End {
        # Save the modified XML back to the file
        $Xml.Save($XmlFilePath)
    }
}
Export-ModuleMember -Function 'New-PublisherLevelRules'
