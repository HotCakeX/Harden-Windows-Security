function Remove-UnreferencedFileRuleRefs {
    <#
    .SYNOPSIS
        Removes <FileRuleRef> elements from the <FileRulesRef> node of each Signing Scenario that are not referenced by any <Allow> element in the <FileRules> node
    .PARAMETER xmlFilePath
        The path to the XML file to be modified
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
        [System.Xml.XmlDocument]$XmlContent = Get-Content $XmlFilePath
    }
    Process {
        # Define the namespace to use with the namespace manager
        [System.Xml.XmlNamespaceManager]$NsManager = New-Object -TypeName System.Xml.XmlNamespaceManager -ArgumentList $XmlContent.NameTable
        $NsManager.AddNamespace('def', 'urn:schemas-microsoft-com:sipolicy')

        # Find all Allow elements and store their IDs
        $AllowedIds = foreach ($Item in ($XmlContent.SelectNodes('//def:Allow', $NsManager))) {
            $Item.ID
        }

        # Find all FileRuleRef elements
        $fileRuleRefs = $XmlContent.SelectNodes('//def:FileRuleRef', $NsManager)

        foreach ($fileRuleRef in $fileRuleRefs) {
            # Check if the RuleID attribute is not in the list of allowed IDs
            if ($AllowedIds -notcontains $fileRuleRef.RuleID) {
                # Remove the FileRuleRef element if it's not referenced
                [System.Void]$fileRuleRef.ParentNode.RemoveChild($fileRuleRef)
            }
        }
    }
    End {
        # Save the modified XML back to the file or to a new file
        $XmlContent.Save($XmlFilePath)
    }
}
Export-ModuleMember -Function 'Remove-UnreferencedFileRuleRefs'
