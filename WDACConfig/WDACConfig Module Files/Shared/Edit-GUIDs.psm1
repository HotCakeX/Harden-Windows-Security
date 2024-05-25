Function Edit-GUIDs {
    <#
    .SYNOPSIS
        A helper function to swap GUIDs in a WDAC policy XML file
    .INPUTS
        System.String
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    param(
        [System.String]$PolicyIDInput,
        [System.IO.FileInfo]$PolicyFilePathInput
    )

    [System.String]$PolicyID = "{$PolicyIDInput}"

    # Read the xml file as an xml object
    [System.Xml.XmlDocument]$Xml = Get-Content -Path $PolicyFilePathInput

    # Define the new values for PolicyID and BasePolicyID
    [System.String]$newPolicyID = $PolicyID
    [System.String]$newBasePolicyID = $PolicyID

    # Replace the old values with the new ones
    $Xml.SiPolicy.PolicyID = $newPolicyID
    $Xml.SiPolicy.BasePolicyID = $newBasePolicyID

    # Save the modified xml file
    $Xml.Save($PolicyFilePathInput)
}
Export-ModuleMember -Function 'Edit-GUIDs'
