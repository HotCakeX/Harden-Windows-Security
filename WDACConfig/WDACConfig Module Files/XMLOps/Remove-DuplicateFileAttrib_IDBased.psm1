Function Remove-DuplicateFileAttrib_IDBased {
    <#
        .SYNOPSIS
            Takes a path to an XML file and removes duplicate FileAttrib elements from the <FileRules> node
            and duplicate FileRuleRef elements from the <ProductSigners> node under each <SigningScenarios> node
            and duplicate FileAttribRef elements from the <Signer> node under each <Signers> node.

            The criteria for removing duplicates is the ID attribute of the FileAttrib elements and the RuleID attribute of the FileRuleRef elements
        .PARAMETER XmlFilePath
            The path to the XML file to be modified.
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
        # Load the XML file
        [System.Xml.XmlDocument]$Xml = Get-Content -Path $XmlFilePath

        # Define namespace manager
        [System.Xml.XmlNamespaceManager]$NsMgr = New-Object -TypeName System.Xml.XmlNamespaceManager -ArgumentList $Xml.NameTable
        $NsMgr.AddNamespace('sip', 'urn:schemas-microsoft-com:sipolicy')
    }

    Process {
        . "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\PSDefaultParameterValues.ps1"

        # Get all FileAttrib elements
        [System.Xml.XmlNodeList]$FileAttribs = $Xml.SelectNodes('//sip:FileRules/sip:FileAttrib', $NsMgr)

        # Track seen FileAttrib IDs
        [System.Collections.Hashtable]$SeenFileAttribIDs = @{}

        # Loop through each FileAttrib element
        foreach ($FileAttrib in $FileAttribs) {

            [System.String]$FileAttribID = $FileAttrib.ID

            # Check if the FileAttrib ID has been seen before
            if ($SeenFileAttribIDs.ContainsKey($FileAttribID)) {

                [WDACConfig.VerboseLogger]::Write("Remove-DuplicateFileAttrib: Removed duplicate FileAttrib with ID: $FileAttribID")
                [System.Void]$FileAttrib.ParentNode.RemoveChild($FileAttrib)
            }
            else {
                # If not seen before, add to seen FileAttrib IDs
                $SeenFileAttribIDs[$FileAttribID] = $true
            }
        }

        # Get all ProductSigners under SigningScenarios
        [System.Xml.XmlNodeList]$SigningScenarios = $Xml.SelectNodes('//sip:SigningScenarios/sip:SigningScenario', $NsMgr)

        # Loop through each SigningScenario
        foreach ($Scenario in $SigningScenarios) {

            # Track seen FileRuleRef IDs
            [System.Collections.Hashtable]$SeenFileRuleRefIDs = @{}

            # Get all FileRuleRef elements under ProductSigners
            $FileRuleRefs = $Scenario.ProductSigners.FileRulesRef.FileRuleRef

            # Loop through each FileRuleRef element
            foreach ($FileRuleRef in $FileRuleRefs) {

                [System.String]$FileRuleRefID = $FileRuleRef.RuleID

                # Check if the FileRuleRef ID has been seen before
                if ($SeenFileRuleRefIDs.ContainsKey($FileRuleRefID)) {

                    [WDACConfig.VerboseLogger]::Write("Remove-DuplicateFileAttrib: Removed duplicate FileRuleRef with ID: $FileRuleRefID")
                    [System.Void]$FileRuleRef.ParentNode.RemoveChild($FileRuleRef)
                }
                else {
                    # If not seen before, add to seen FileRuleRef IDs
                    $SeenFileRuleRefIDs[$FileRuleRefID] = $true
                }
            }
        }

        # Get all Signers
        [System.Xml.XmlNodeList]$Signers = $Xml.SelectNodes('//sip:Signers/sip:Signer', $NsMgr)

        # Loop through each Signer
        foreach ($Signer in $Signers) {

            # Get all FileAttribRef elements under the Signer
            [System.Xml.XmlElement[]]$FileAttribRefs = foreach ($Item in $Signer.ChildNodes) {
                if ($Item.Name -eq 'FileAttribRef') {
                    $Item
                }
            }

            # Track seen FileAttribRef IDs
            [System.Collections.Hashtable]$SeenFileAttribRefIDs = @{}

            # Loop through each FileAttribRef element
            foreach ($FileAttribRef in $FileAttribRefs) {

                [System.String]$FileAttribRefID = $FileAttribRef.RuleID

                # Check if the FileAttribRef ID has been seen before
                if ($SeenFileAttribRefIDs.ContainsKey($FileAttribRefID)) {

                    [WDACConfig.VerboseLogger]::Write("Remove-DuplicateFileAttrib: Removed duplicate FileAttribRef with ID: $FileAttribRefID")
                    [System.Void]$Signer.RemoveChild($FileAttribRef)
                }
                else {
                    # If not seen before, add to seen FileAttribRef IDs
                    $SeenFileAttribRefIDs[$FileAttribRefID] = $true
                }
            }
        }
    }
    End {
        # Save the modified XML
        $Xml.Save($XmlFilePath)
    }
}
Export-ModuleMember -Function 'Remove-DuplicateFileAttrib_IDBased'
