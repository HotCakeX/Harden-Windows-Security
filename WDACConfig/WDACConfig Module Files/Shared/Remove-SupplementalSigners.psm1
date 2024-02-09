Function Remove-SupplementalSigners {
    <#
.SYNOPSIS
    Removes the entire SupplementalPolicySigners block
    and any Signer in Signers node that have the same ID as the SignerIds of the SupplementalPolicySigner(s) in <SupplementalPolicySigners>...</SupplementalPolicySigners> node
    from a CI policy XML file
.NOTES
    It doesn't do anything if the input policy file has no SupplementalPolicySigners block.
    It will also always check if the Signers node is not empty, like
   <Signers>
   </Signers>

   if it is then it will close it: <Signers />

   The function can run infinite number of times on the same file.
.PARAMETER Path
    The path to the CI policy XML file
.INPUTS
    System.IO.FileInfo
.OUTPUTS
    System.Void
#>
    [CmdletBinding()]
    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [System.IO.FileInfo]$Path
    )

    begin {

        # Make sure the input file is compliant with the CI policy schema
        Test-CiPolicy -XmlFile $Path | Out-Null

        # Get the XML content from the file
        [System.Xml.XmlDocument]$XMLContent = Get-Content -Path $Path

    }

    Process {

        # Get the SiPolicy node
        [System.Xml.XmlElement]$SiPolicyNode = $XMLContent.SiPolicy

        # Declare the namespace manager and add the default namespace with a prefix
        [System.Xml.XmlNamespaceManager]$NameSpace = New-Object -TypeName System.Xml.XmlNamespaceManager -ArgumentList $XMLContent.NameTable
        $NameSpace.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

        # Check if the SupplementalPolicySigners node exists and has child nodes
        if ($SiPolicyNode.SupplementalPolicySigners -and $SiPolicyNode.SupplementalPolicySigners.HasChildNodes) {

            Write-Verbose -Message 'Removing the SupplementalPolicySigners block and their corresponding Signers'

            # Select the SupplementalPolicySigners node using XPath and the namespace manager
            [System.Xml.XmlElement[]]$NodesToRemove_SupplementalPolicySigners = $SiPolicyNode.SelectNodes('//ns:SupplementalPolicySigners', $NameSpace)

            # Get the SignerIds of the nodes inside of the SupplementalPolicySigners nodes - <SupplementalPolicySigners>...</SupplementalPolicySigners>
            [System.Xml.XmlElement[]]$SupplementalPolicySignerIDs = $SiPolicyNode.SupplementalPolicySigners.SelectNodes("//ns:SupplementalPolicySigner[starts-with(@SignerId, 'ID_SIGNER_')]", $NameSpace)

            # Get the unique SignerIds
            [System.String[]]$SupplementalPolicySignerIDs = $SupplementalPolicySignerIDs.SignerId | Select-Object -Unique

            # An array to store the nodes to remove
            [System.Xml.XmlElement[]]$NodesToRemove_Signers = @()

            # Select all the Signer nodes in <Signers>...</Signers> that have the same ID as the SignerIds of the SupplementalPolicySigners nodes
            foreach ($SignerID in $SupplementalPolicySignerIDs) {
                $NodesToRemove_Signers += $SiPolicyNode.Signers.SelectNodes("//ns:Signer[@ID='$SignerID']", $NameSpace)
            }

            # Loop through the Signer nodes to remove
            foreach ($SignerNode in $NodesToRemove_Signers) {
                # Remove the Signer from the Signers node
                $SiPolicyNode.Signers.RemoveChild($SignerNode) | Out-Null
            }

            # Loop through the <SupplementalPolicySigners>..</SupplementalPolicySigners> nodes to remove, in case there are multiple!
            foreach ($Node in $NodesToRemove_SupplementalPolicySigners) {

                # Remove the <SupplementalPolicySigners> node from the parent node which is $SiPolicyNode
                $SiPolicyNode.RemoveChild($Node) | Out-Null
            }
        }

        # Check if the Signers node is empty, if it is then close it
        if (-NOT $SiPolicyNode.Signers.HasChildNodes) {

            # Create a new self-closing element with the same name and attributes as the old one
            [System.Xml.XmlElement]$NewSignersNode = $XMLContent.CreateElement('Signers', 'urn:schemas-microsoft-com:sipolicy')

            foreach ($Attribute in $SiPolicyNode.Signers.Attributes) {
                $NewSignersNode.SetAttribute($Attribute.Name, $Attribute.Value)
            }

            # Select the Signers node using XPath and the namespace manager
            [System.Xml.XmlElement]$OldSignersNode = $XMLContent.SelectSingleNode('//ns:Signers', $NameSpace)

            # Replace the old element with the new one
            $SiPolicyNode.ReplaceChild($NewSignersNode, $OldSignersNode) | Out-Null
        }

    }

    End {
        # Save the modified XML content to a file
        $XMLContent.Save($Path)
    }

}

Export-ModuleMember -Function 'Remove-SupplementalSigners'
