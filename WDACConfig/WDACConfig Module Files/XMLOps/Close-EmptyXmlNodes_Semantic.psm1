Function Close-EmptyXmlNodes_Semantic {
    <#
    .SYNOPSIS
        Closes all empty XML nodes and removes empty nodes that are neither base nodes nor 'ProductSigners' nodes
        According to the CI Schema

        For example, it converts this

    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="Auto generated policy on 03-13-2024">
      <ProductSigners>
        <AllowedSigners>
        </AllowedSigners>
      </ProductSigners>
    </SigningScenario>

    Or this

    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="Auto generated policy on 03-13-2024">
      <ProductSigners>
        <AllowedSigners />
      </ProductSigners>
    </SigningScenario>

    to this

    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="Auto generated policy on 03-13-2024">
      <ProductSigners />
    </SigningScenario>

    .PARAMETER XmlFilePath
        The path to the XML file to be processed
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath
    )
    Begin {
        . "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\PSDefaultParameterValues.ps1"

        # Define the base node names that should not be removed even if empty
        [System.String[]]$BaseNodeNames = @('SiPolicy', 'Rules', 'EKUs', 'FileRules', 'Signers', 'SigningScenarios', 'UpdatePolicySigners', 'CiSigners', 'HvciOptions', 'BasePolicyID', 'PolicyID')

        Function Close-EmptyNodesRecursively {
            <#
            .SYNOPSIS
                Helper function to recursively close empty XML nodes
            #>
            param (
                [Parameter(Mandatory = $true)][System.Xml.XmlElement]$XmlNode
            )

            foreach ($ChildNode in $XmlNode.ChildNodes) {
                if ($ChildNode -is [System.Xml.XmlElement]) {
                    # Recursively close empty child nodes
                    Close-EmptyNodesRecursively -XmlNode $ChildNode

                    # Check if the node is empty
                    if (-not $ChildNode.HasChildNodes -and -not $ChildNode.HasAttributes) {

                        # Check if it's a base node
                        if ($BaseNodeNames -contains $ChildNode.LocalName) {
                            # self-close it
                            $ChildNode.IsEmpty = $true
                        }
                        # Special case for ProductSigners because it's a required node inside each SigningScenario but can't be empty
                        elseif ($ChildNode.LocalName -eq 'ProductSigners') {
                            # self-close it
                            $ChildNode.IsEmpty = $true
                        }
                        else {
                            # If it's not a base node, remove it
                            [System.Void]$ChildNode.ParentNode.RemoveChild($ChildNode)
                        }
                    }
                }
            }
        }
    }
    Process {
        # Load the XML file
        [System.Xml.XmlDocument]$Xml = Get-Content -Path $XmlFilePath

        # Start the recursive function from the root element
        Close-EmptyNodesRecursively -XmlNode $Xml.DocumentElement
    }
    End {
        # Save the changes back to the XML file
        $Xml.Save($XmlFilePath)
    }
}
Export-ModuleMember -Function 'Close-EmptyXmlNodes_Semantic'
