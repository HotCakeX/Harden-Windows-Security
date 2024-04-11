Function Remove-DuplicateFileAttribRef_IDBased {
    <#
    .SYNOPSIS
        Loops through each Signer element in <Signers> node in the XML file and removes duplicate FileAttribRef elements inside them
        Based on the RuleID attribute
        This is according to the ConfigCI Schema
    .PARAMETER XmlFilePath
        The path to the XML file to be modified
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    Param(
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath
    )

    Begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Load the XML file
        [System.Xml.XmlDocument]$Xml = Get-Content -Path $XmlFilePath
    }

    Process {

        # Iterate through each Signer element
        foreach ($Signer in $Xml.SiPolicy.Signers.Signer) {

            # Create a hashtable to track unique FileAttribRef IDs
            [System.Collections.Hashtable]$UniqueFileAttribRefs = @{}

            # Iterate through each FileAttribRef element of the current signer
            foreach ($FileAttribRef in $Signer.FileAttribRef) {

                # Get the RuleID attribute value of the current FileAttribRef element
                [System.String]$FileAttribRefID = $FileAttribRef.RuleID

                # Check if the current FileAttribRef ID already exists in the hashtable
                if (-not $UniqueFileAttribRefs.ContainsKey($FileAttribRefID)) {

                    # If not, add it to the hashtable and keep the FileAttribRef element
                    $UniqueFileAttribRefs[$FileAttribRefID] = $true
                }
                else {
                    # If it exists, remove the duplicate FileAttribRef element
                    [System.Void]$Signer.RemoveChild($FileAttribRef)
                }
            }
        }
    }

    End {
        # Save the modified XML back to the file
        $Xml.Save($XmlFilePath)
    }
}
Export-ModuleMember -Function 'Remove-DuplicateFileAttribRef_IDBased'
