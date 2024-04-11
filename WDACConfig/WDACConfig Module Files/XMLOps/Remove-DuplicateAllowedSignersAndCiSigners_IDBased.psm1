Function Remove-DuplicateAllowedSignersAndCiSigners_IDBased {
    <#
    .SYNOPSIS
        Removes duplicate SignerIds from the CiSigners and AllowedSigners nodes from each Signing Scenario in a CI policy XML file
        The criteria for removing duplicates is the SignerId attribute of the CiSigner and AllowedSigner nodes
    .PARAMETER Path
        The path to the CI policy XML file
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
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

        Function Remove-DuplicateSignerIds {
            <#
        .SYNOPSIS
            Removes duplicate SignerIds from the given XmlNodeList
        #>
            Param(
                [Parameter(Mandatory = $true)][System.Xml.XmlNodeList]$NodeList
            )

            [System.String[]]$UniqueSignerIds = @()

            foreach ($Node in $NodeList) {
                if ($UniqueSignerIds -notcontains $Node.SignerId) {
                    $UniqueSignerIds += $Node.SignerId
                }
                else {
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

        # Remove duplicate signer IDs from CiSigners and AllowedSigners
        Remove-DuplicateSignerIds $CiSigners
        Remove-DuplicateSignerIds $AllowedSigners12
        Remove-DuplicateSignerIds $AllowedSigners131
    }

    End {
        # Save the changes to the XML file
        $Xml.Save($Path)
    }
}
Export-ModuleMember -Function 'Remove-DuplicateAllowedSignersAndCiSigners_IDBased'
