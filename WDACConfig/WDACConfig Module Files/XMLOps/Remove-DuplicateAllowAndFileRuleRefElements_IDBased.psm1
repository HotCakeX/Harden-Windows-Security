Function Remove-DuplicateAllowAndFileRuleRefElements_IDBased {
    <#
    .SYNOPSIS
        Removes duplicates <Allow> elements from the <FileRules> nodes
        and <FileRuleRef> elements from the <FileRulesRef> nodes in every <ProductSigners> node of each <SigningScenario> node

        The criteria for removing duplicates is the ID attribute of the <Allow> elements and the RuleID attribute of the <FileRuleRef> elements
    .PARAMETER XmlFilePath
        The file path of the XML document to be modified
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
        . "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\PSDefaultParameterValues.ps1"

        # Load the XML document from the specified file path
        [System.Xml.XmlDocument]$XmlDocument = Get-Content -Path $XmlFilePath

        # Create a namespace manager for handling XML namespaces
        [System.Xml.XmlNamespaceManager]$NsMgr = New-Object -TypeName System.Xml.XmlNamespaceManager -ArgumentList $XmlDocument.NameTable
        $NsMgr.AddNamespace('sip', 'urn:schemas-microsoft-com:sipolicy')
    }

    Process {
        # Remove duplicate <Allow> elements within the <FileRules> section
        [System.Xml.XmlNodeList]$AllowElements = $XmlDocument.SelectNodes('//sip:FileRules/sip:Allow', $NsMgr)

        [System.Collections.Hashtable]$UniqueAllowIDs = @{}

        foreach ($AllowElement in $AllowElements) {

            [System.String]$AllowID = $AllowElement.ID

            if ($UniqueAllowIDs.ContainsKey($AllowID)) {

                Write-Verbose "Removing duplicate Allow element with ID: $AllowID"
                [System.Void]$AllowElement.ParentNode.RemoveChild($AllowElement)
            }
            else {
                $UniqueAllowIDs[$AllowID] = $true
            }
        }

        # Remove duplicate <FileRuleRef> elements within <FileRulesRef> under <ProductSigners> nodes
        [System.Xml.XmlNodeList]$SigningScenarios = $XmlDocument.SelectNodes('//sip:SigningScenarios/sip:SigningScenario', $NsMgr)

        foreach ($Scenario in $SigningScenarios) {

            $ProductSigners = $Scenario.ProductSigners

            $FileRulesRefs = $ProductSigners.FileRulesRef

            foreach ($FileRulesRef in $FileRulesRefs) {

                [System.Collections.Hashtable]$UniqueFileRuleRefIDs = @{}

                [System.Xml.XmlElement[]]$FileRuleRefs = $FileRulesRef.FileRuleRef

                foreach ($FileRuleRef in $FileRuleRefs) {

                    [System.String]$RuleID = $FileRuleRef.RuleID

                    if ($UniqueFileRuleRefIDs.ContainsKey($RuleID)) {

                        Write-Verbose "Removing duplicate FileRuleRef element with ID: $RuleID"
                        [System.Void]$FileRulesRef.RemoveChild($FileRuleRef)
                    }
                    else {
                        $UniqueFileRuleRefIDs[$RuleID] = $true
                    }
                }
            }
        }
    }

    End {
        # Save the modified XML document back to the original file path
        $XmlDocument.Save($XmlFilePath)
    }
}
Export-ModuleMember -Function 'Remove-DuplicateAllowAndFileRuleRefElements_IDBased'
