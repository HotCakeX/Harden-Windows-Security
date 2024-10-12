Function Clear-CiPolicy_Semantic {
    <#
    .SYNOPSIS
        Clears the CI Policy XML file from all nodes except the base nodes
        According to the CI Schema
        It clears any XML file to make it usable as a template for MDE AH CI Policy
    .PARAMETER Path
        The path to the XML file to be processed
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

        [System.Xml.XmlNamespaceManager]$Ns = New-Object -TypeName System.Xml.XmlNamespaceManager -ArgumentList $Xml.NameTable
        $Ns.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
    }

    Process {

        # Defining the Nodes to keep and clear, according to the CI Schema
        $NodesToClear = [ordered]@{
            EKUs                                                  = [System.Xml.XmlElement]$Xml.SelectSingleNode('//ns:EKUs', $Ns)
            FileRules                                             = [System.Xml.XmlElement]$Xml.SelectSingleNode('//ns:FileRules', $Ns)
            Signers                                               = [System.Xml.XmlElement]$Xml.SelectSingleNode('//ns:Signers', $Ns)
            UMCI_ProductSigners_Node                              = [System.Xml.XmlElement]$Xml.SelectSingleNode('//ns:SigningScenarios/ns:SigningScenario[@Value="12"]/ns:ProductSigners', $Ns)
            KMCI_ProductSigners_Node                              = [System.Xml.XmlElement]$Xml.SelectSingleNode('//ns:SigningScenarios/ns:SigningScenario[@Value="131"]/ns:ProductSigners', $Ns)
            UMCI_SigningScenario_ProductSigners_FileRulesRef_Node = [System.Xml.XmlElement]$Xml.SelectSingleNode('//ns:SigningScenarios/ns:SigningScenario[@Value="12"]/ns:ProductSigners/ns:FileRulesRef', $Ns)
            KMCI_SigningScenario_ProductSigners_FileRulesRef_Node = [System.Xml.XmlElement]$Xml.SelectSingleNode('//ns:SigningScenarios/ns:SigningScenario[@Value="131"]/ns:ProductSigners/ns:FileRulesRef', $Ns)
            UpdatePolicySignersNode                               = [System.Xml.XmlElement]$Xml.SelectSingleNode('//ns:UpdatePolicySigners', $Ns)
            CiSignersNode                                         = [System.Xml.XmlElement]$Xml.SelectSingleNode('//ns:CiSigners', $Ns)
        }

        foreach ($MainNode in $NodesToClear.Keys) {

            # Get the current node
            [System.Xml.XmlElement]$CurrentNode = $NodesToClear[$MainNode]

            if ($Null -ne $CurrentNode) {
                # Remove all child nodes
                while ($CurrentNode.HasChildNodes) {
                    [System.Void]$CurrentNode.RemoveChild($CurrentNode.FirstChild)
                }
                # Set the node to self close
                $CurrentNode.IsEmpty = $true
            }
        }
    }

    End {
        # Save the modified XML back to the file
        $Xml.Save($Path)
    }
}
Export-ModuleMember -Function 'Clear-CiPolicy_Semantic'
