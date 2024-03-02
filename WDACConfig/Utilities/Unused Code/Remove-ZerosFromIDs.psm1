Function Remove-ZerosFromIDs {
    <#
    .SYNOPSIS
        Can remove _0 from the ID and SignerId of all the elements in the policy xml file
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [System.String]$FilePath
    )
    # Load the xml file
    [System.Xml.XmlDocument]$Xml = Get-Content -Path $FilePath

    # Get all the elements with ID attribute
    $Elements = $Xml.SelectNodes('//*[@ID]')

    # Loop through the elements and replace _0 with empty string in the ID value and SignerId value
    foreach ($Element in $Elements) {
        $Element.ID = $Element.ID -replace '_0', ''
        # Check if the element has child elements with SignerId attribute
        if ($Element.HasChildNodes) {
            # Get the child elements with SignerId attribute
            $childElements = $Element.SelectNodes('.//*[@SignerId]')
            # Loop through the child elements and replace _0 with empty string in the SignerId value
            foreach ($childElement in $childElements) {
                $childElement.SignerId = $childElement.SignerId -replace '_0', ''
            }
        }
    }

    # Get the CiSigners element by name
    $CiSigners = $Xml.SiPolicy.CiSigners

    # Check if the CiSigners element has child elements with SignerId attribute
    if ($CiSigners.HasChildNodes) {
        # Get the child elements with SignerId attribute
        $CiSignersChildren = $CiSigners.ChildNodes
        # Loop through the child elements and replace _0 with empty string in the SignerId value
        foreach ($CiSignerChild in $CiSignersChildren) {
            $CiSignerChild.SignerId = $CiSignerChild.SignerId -replace '_0', ''
        }
    }

    # Save the modified xml file
    $Xml.Save($FilePath)
}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Remove-ZerosFromIDs'
