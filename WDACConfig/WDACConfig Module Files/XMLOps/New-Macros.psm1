Function New-Macros {
    <#
    .SYNOPSIS
        Creates Macros in the CI policy XML and adds them as multi-valued AppIDs to each element in the <FileRules> node
    .PARAMETER XmlFilePath
        The path to the XML file containing the CI policy
    .PARAMETER InputObject
        This should be a hashtable that contains directory paths and audit logs
    .INPUTS
        System.Collections.Hashtable
        System.IO.FileInfo
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    Param (
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath,
        [Parameter(Mandatory = $true)][System.Collections.Hashtable]$InputObject
    )
    Begin {

        $Macros = New-Object -TypeName 'System.Collections.Generic.HashSet[System.String]'

        # If user selected directory paths to be passed to this function
        if ($null -ne $InputObject['SelectedDirectoryPaths'] -and $InputObject['SelectedDirectoryPaths'].count -gt 0) {

            # loop over each exe in all directories
            foreach ($Exe in ([WDACConfig.FileUtility]::GetFilesFast($InputObject['SelectedDirectoryPaths'], $null, '.exe'))) {

                # Get the Extended File Info of the current exe file
                [WDACConfig.ExFileInfo]$ExFileInfo = [WDACConfig.ExFileInfo]::GetExtendedFileInfo($Exe)

                # make sure the OriginalFileName is not null for the current exe
                if ($null -ne $ExFileInfo.OriginalFileName) {
                    # Send the OriginalFileName to the Macros HashSet
                    [System.Void]$Macros.Add($ExFileInfo.OriginalFileName)
                }
                else {
                    [WDACConfig.Logger]::Write("New-Macros: OriginalFileName property is empty for the file: $($Exe.FullName)")
                }
            }
        }

        # If audit logs were passed to this function
        if ($null -ne $InputObject['SelectedAuditLogs'] -and $InputObject['SelectedAuditLogs'].count -gt 0) {

            # Add the OriginalFileName value of all of the executable files that exist or don't exist on the disk from audit logs to the Macros HashSet
            foreach ($Item in $InputObject['SelectedAuditLogs']) {
                if ((([System.IO.FileInfo]$Item.'File Name').Extension -eq '.exe') -and (-NOT ([System.String]::IsNullOrWhiteSpace($Item.OriginalFileName)))) {
                    [System.Void]$Macros.Add($Item.OriginalFileName)
                }
            }
        }

        # Break from the begin block if there is no macros (aka OriginalFileNames) to add to the policy
        if ($Macros.Count -eq 0) { return }

        # Load the XML file
        [System.Xml.XmlDocument]$Xml = Get-Content -Path $XmlFilePath

        # Define the namespace manager
        [System.Xml.XmlNamespaceManager]$Ns = New-Object -TypeName System.Xml.XmlNamespaceManager -ArgumentList $Xml.NameTable
        $Ns.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

        # Find the Macros node
        $MacrosNode = $Xml.SelectSingleNode('//ns:Macros', $Ns)

        # Check if Macros node doesn't exist
        if (($null -eq $MacrosNode ) -and ($MacrosNode -isnot [System.Xml.XmlElement])) {
            # Create the Macros node
            [System.Xml.XmlElement]$MacrosNode = $Xml.CreateElement('Macros', $Xml.DocumentElement.NamespaceURI)
            [System.Void]$Xml.DocumentElement.AppendChild($MacrosNode)
        }

        # Create a hashtable to store the mapping of Macro IDs to their values
        [System.Collections.Hashtable]$MacroAppIDMapping = @{}

        # Ensuring that the MacroIDs are unique - comes handy when merging multiple Macros from different policies into one
        foreach ($Macro in $Macros) {
            $RandomizedGUID = [System.Guid]::NewGuid().ToString().Replace('-', '')
            $MacroAppIDMapping["AppID.$RandomizedGUID"] = $Macro
        }

        # To store the AppIDs array as a single string
        $AppIDsArray = New-Object -TypeName 'System.Text.StringBuilder'
    }
    Process {

        if ($Macros.Count -eq 0) { return }

        foreach ($Macro in $MacroAppIDMapping.Keys) {

            # Create new Macro node
            [System.Xml.XmlElement]$NewMacroNode = $Xml.CreateElement('Macro', $MacrosNode.NamespaceURI)
            # It is important for the ID to be "Id" and not "ID" like the rest of the elements to be valid against the Schema
            $NewMacroNode.SetAttribute('Id', $Macro)
            $NewMacroNode.SetAttribute('Value', $MacroAppIDMapping[$Macro])
            # Add the new node to the Macros node
            [System.Void]$MacrosNode.AppendChild($NewMacroNode)

            [System.Void]$AppIDsArray.Append("`$($Macro)")
        }

        # Update AppIDs for elements between <FileRules> and </FileRules>
        $FileRulesNode = $Xml.SelectSingleNode('//ns:FileRules', $Ns)
        if ($FileRulesNode) {
            # Make sure to exclude the .exe files from the AppIDs because only AddIns such as DLLs should have the AppIDs applied to them.
            # AppIDs applied to .exe files make them unrunnable and trigger blocked event.
            # Also exclude .sys files since driver load can only be done by secure kernel
            $FileRulesToModify = foreach ($Node in $FileRulesNode.ChildNodes) {
                if (($Node.Name -in 'Allow', 'Deny', 'FileAttrib', 'FileRule') -and ($Node.FriendlyName -notmatch '.*\.(exe|sys).*')) {
                    $Node
                }
            }

            foreach ($Rule in $FileRulesToModify) {
                $Rule.SetAttribute('AppIDs', $AppIDsArray.ToString())
            }
        }
    }
    End {
        if ($Macros.Count -eq 0) { return }

        # Save the modified XML back to the file
        $Xml.Save($XmlFilePath)
    }
}
Export-ModuleMember -Function 'New-Macros'
