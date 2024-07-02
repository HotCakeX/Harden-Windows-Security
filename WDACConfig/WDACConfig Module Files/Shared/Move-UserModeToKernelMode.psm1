Function Move-UserModeToKernelMode {
    <#
    .SYNOPSIS
        Moves all User mode AllowedSigners in the User mode signing scenario to the Kernel mode signing scenario and then
        deletes the entire User mode signing scenario block
    .PARAMETER FilePath
        The path to the XML file to be modified
    .INPUTS
        System.String
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ [System.IO.File]::Exists($_) })]
        [System.String]$FilePath
    )
    . "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\PSDefaultParameterValues.ps1"

    # Load the XML file as an XmlDocument object
    $Xml = [System.Xml.XmlDocument](Get-Content -Path $FilePath)

    # Get the SigningScenario nodes as an array
    $SigningScenarios = $Xml.SiPolicy.SigningScenarios.SigningScenario

    foreach ($SigningScenario in $SigningScenarios) {
        # Find the SigningScenario node with Value 12 and store it in a variable
        if ($SigningScenario.Value -eq '12') {
            [System.Xml.XmlElement]$SigningScenario12 = $SigningScenario
        }
        # Find the SigningScenario node with Value 131 and store it in a variable
        if ($SigningScenario.Value -eq '131') {
            [System.Xml.XmlElement]$SigningScenario131 = $SigningScenario
        }
    }

    # Get the AllowedSigners node from the SigningScenario node with Value 12
    $AllowedSigners12 = $SigningScenario12.ProductSigners.AllowedSigners

    # Check if the AllowedSigners node has any child nodes
    if ($AllowedSigners12.HasChildNodes) {
        # Loop through each AllowedSigner node from the SigningScenario node with Value 12
        foreach ($AllowedSigner in $AllowedSigners12.AllowedSigner) {
            # Create a new AllowedSigner node and copy the SignerId attribute from the original node
            # Use the namespace of the parent element when creating the new element
            $NewAllowedSigner = $Xml.CreateElement('AllowedSigner', $SigningScenario131.NamespaceURI)
            $NewAllowedSigner.SetAttribute('SignerId', $AllowedSigner.SignerId)

            # Append the new AllowedSigner node to the AllowedSigners node of the SigningScenario node with Value 131
            [System.Void]$SigningScenario131.ProductSigners.AllowedSigners.AppendChild($NewAllowedSigner)
        }

        # Remove the SigningScenario node with Value 12 from the XML document
        [System.Void]$Xml.SiPolicy.SigningScenarios.RemoveChild($SigningScenario12)
    }

    # Remove Signing Scenario 12 block only if it exists and has no allowed signers (i.e. is empty)
    if ($SigningScenario12 -and $AllowedSigners12.count -eq 0) {
        # Remove the SigningScenario node with Value 12 from the XML document
        $Xml.SiPolicy.SigningScenarios.RemoveChild($SigningScenario12)
    }

    # Save the modified XML document to a new file
    $Xml.Save($FilePath)
}
Export-ModuleMember -Function 'Move-UserModeToKernelMode'
