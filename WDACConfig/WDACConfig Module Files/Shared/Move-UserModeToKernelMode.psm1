Function Move-UserModeToKernelMode {
    <#
    .SYNOPSIS
        Moves all User mode AllowedSigners in the User mode signing scenario to the Kernel mode signing scenario and then
        deletes the entire User mode signing scenario block
    .INPUTS
        System.String
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [System.String]$FilePath
    )
    # Importing the $PSDefaultParameterValues to the current session, prior to everything else
    . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

    # Load the XML file as an XmlDocument object
    $Xml = [System.Xml.XmlDocument](Get-Content -Path $FilePath)

    # Get the SigningScenario nodes as an array
    $signingScenarios = $Xml.SiPolicy.SigningScenarios.SigningScenario

    # Find the SigningScenario node with Value 131 and store it in a variable
    $signingScenario131 = $signingScenarios | Where-Object -FilterScript { $_.Value -eq '131' }

    # Find the SigningScenario node with Value 12 and store it in a variable
    $signingScenario12 = $signingScenarios | Where-Object -FilterScript { $_.Value -eq '12' }

    # Get the AllowedSigners node from the SigningScenario node with Value 12
    $AllowedSigners12 = $signingScenario12.ProductSigners.AllowedSigners

    # Check if the AllowedSigners node has any child nodes
    if ($AllowedSigners12.HasChildNodes) {
        # Loop through each AllowedSigner node from the SigningScenario node with Value 12
        foreach ($AllowedSigner in $AllowedSigners12.AllowedSigner) {
            # Create a new AllowedSigner node and copy the SignerId attribute from the original node
            # Use the namespace of the parent element when creating the new element
            $NewAllowedSigner = $Xml.CreateElement('AllowedSigner', $signingScenario131.NamespaceURI)
            $NewAllowedSigner.SetAttribute('SignerId', $AllowedSigner.SignerId)

            # Append the new AllowedSigner node to the AllowedSigners node of the SigningScenario node with Value 131
            # out-null to prevent console display
            $signingScenario131.ProductSigners.AllowedSigners.AppendChild($NewAllowedSigner) | Out-Null
        }

        # Remove the SigningScenario node with Value 12 from the XML document
        # out-null to prevent console display
        $Xml.SiPolicy.SigningScenarios.RemoveChild($signingScenario12) | Out-Null
    }

    # Remove Signing Scenario 12 block only if it exists and has no allowed signers (i.e. is empty)
    if ($signingScenario12 -and $AllowedSigners12.count -eq 0) {
        # Remove the SigningScenario node with Value 12 from the XML document
        $Xml.SiPolicy.SigningScenarios.RemoveChild($signingScenario12)
    }

    # Save the modified XML document to a new file
    $Xml.Save($FilePath)
}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Move-UserModeToKernelMode'
