Function New-CertificateSignerRules {
    <#
    .SYNOPSIS
        Creates new Signer rules for Certificates, in the XML file
        The level is Pca/Root/Leaf certificate, meaning there is no certificate publisher mentioned
        Only Certificate TBS and its name is used.
    .PARAMETER SignerData
        The SignerData to be used for creating the rules
    .PARAMETER XmlFilePath
        The path to the XML file to be modified
    .INPUTS
        PSCustomObject[]
        System.IO.FileInfo
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    Param (
        [Parameter(Mandatory = $true)][PSCustomObject[]]$SignerData,
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath
    )
    Begin {
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

        foreach ($Data in $SignerData) {

            # Create a unique ID for the Signer element
            [System.String]$Guid = [System.Guid]::NewGuid().ToString().replace('-', '').ToUpper()

            [System.String]$SignerID = "ID_SIGNER_R_$Guid"

            # Create the new Signer element
            [System.Xml.XmlElement]$NewSignerNode = $Xml.CreateElement('Signer', $SignersNode.NamespaceURI)
            $NewSignerNode.SetAttribute('ID', $SignerID)
            $NewSignerNode.SetAttribute('Name', $Data.SignerName)

            # Create the CertRoot element and add it to the Signer element
            [System.Xml.XmlElement]$CertRootNode = $Xml.CreateElement('CertRoot', $SignersNode.NamespaceURI)
            $CertRootNode.SetAttribute('Type', 'TBS')
            $CertRootNode.SetAttribute('Value', $Data.TBS)
            [System.Void]$NewSignerNode.AppendChild($CertRootNode)

            # Add the new Signer element to the Signers node
            [System.Void]$SignersNode.AppendChild($NewSignerNode)

            # For User-Mode files
            if ($Data.SiSigningScenario -eq '1') {

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
            elseif ($Data.SiSigningScenario -eq '0') {

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
        }
    }

    End {
        # Save the modified XML back to the file
        $Xml.Save($XmlFilePath)
    }
}
Export-ModuleMember -Function 'New-CertificateSignerRules'
