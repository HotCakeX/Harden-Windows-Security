Function Remove-OrphanAllowedSignersAndCiSigners_IDBased {
    <#
    .SYNOPSIS
        Removes elements with invalid SignerIds from the CiSigners and AllowedSigners nodes in a CI policy XML file
        These are elements with SignerIds that are not found in any <Signer> in the <Signers> node
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
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$Path
    )

    Begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Load the XML file
        [System.Xml.XmlDocument]$Xml = Get-Content -Path $Path

        # Create an XmlNamespaceManager for namespace resolution
        [System.Xml.XmlNamespaceManager]$NsManager = New-Object System.Xml.XmlNamespaceManager -ArgumentList $Xml.NameTable
        $NsManager.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

        # Get the list of valid signer IDs from the Signers node
        [System.String[]]$ValidSignerIds = $Xml.SelectNodes('//ns:Signers/ns:Signer', $NsManager) | ForEach-Object -Process { $_.ID }

        Function Remove-InvalidSignerIds {
            <#
        .SYNOPSIS
            Removes nodes with invalid SignerIds from the given XmlNodeList
        .INPUTS
            System.Xml.XmlNodeList
        .OUTPUTS
            System.Void
        .PARAMETER NodeList
            The XmlNodeList to remove invalid SignerIds from
        #>
            Param (
                [Parameter(Mandatory = $true)][System.Xml.XmlNodeList]$NodeList
            )

            foreach ($Node in $NodeList) {
                if ($ValidSignerIds -notcontains $Node.SignerId) {
                    [System.Void]$Node.ParentNode.RemoveChild($Node)
                }
            }
        }
    }

    Process {

        # Get CiSigners and AllowedSigners nodes
        [System.Xml.XmlNodeList]$CiSigners = $Xml.SelectNodes('//ns:CiSigners/ns:CiSigner', $NsManager)
        [System.Xml.XmlNodeList]$AllowedSigners12 = $Xml.SelectNodes('//ns:SigningScenarios/ns:SigningScenario[@Value="12"]/ns:ProductSigners/ns:AllowedSigners/ns:AllowedSigner', $NsManager)
        [System.Xml.XmlNodeList]$AllowedSigners131 = $Xml.SelectNodes('//ns:SigningScenarios/ns:SigningScenario[@Value="131"]/ns:ProductSigners/ns:AllowedSigners/ns:AllowedSigner', $NsManager)

        # Remove invalid signer IDs from CiSigners and AllowedSigners
        Remove-InvalidSignerIds $CiSigners
        Remove-InvalidSignerIds $AllowedSigners12
        Remove-InvalidSignerIds $AllowedSigners131

    }
    End {
        # Save the changes to the XML file
        $Xml.Save($Path)
    }
}
Export-ModuleMember -Function 'Remove-OrphanAllowedSignersAndCiSigners_IDBased'
