Function New-Macros {
    <#
    .SYNOPSIS
        Creates Macros in the CI policy XML and adds them as multi-valued AppIDs to each element in the <FileRules> node
    .PARAMETER XmlFilePath
        The path to the XML file containing the CI policy
    .PARAMETER Macros
        The list of Macros to create. These are the values of the Macros.
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    Param (
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath,
        [Parameter(Mandatory = $true)][System.String[]]$Macros
    )
    Begin {

        # We don't need duplicate Macros values to exist in the XML policy file
        $Macros = $Macros | Select-Object -Unique

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

        for ($I = 0; $I -lt $Macros.Length; $I++) {
            # The IDs of the macros will be in the "appid.<number>" format
            $MacroAppIDMapping["appid.$I"] = $Macros[$I]
        }

        # To store the AppIDs array as a single string
        $AppIDsArray = $null
    }
    Process {

        foreach ($Macro in $MacroAppIDMapping.Keys) {

            # Create new Macro node
            [System.Xml.XmlElement]$NewMacroNode = $Xml.CreateElement('Macro', $MacrosNode.NamespaceURI)
            # It is important for the ID to be "Id" and not "ID" like the rest of the elements to be valid against the Schema
            $NewMacroNode.SetAttribute('Id', $Macro)
            $NewMacroNode.SetAttribute('Value', $MacroAppIDMapping[$Macro])
            # Add the new node to the Macros node
            [System.Void]$MacrosNode.AppendChild($NewMacroNode)

            [System.String]$AppIDsArray += "`$($Macro)"
        }

        # Update AppIDs for elements between <FileRules> and </FileRules>
        $FileRulesNode = $Xml.SelectSingleNode('//ns:FileRules', $Ns)
        if ($FileRulesNode) {
            # Make sure to exclude the .exe files from the AppIDs because only AddIns such as DLLs should have the AppIDs applied to them.
            # AppIDs applied to .exe files make them unrunnable and trigger blocked event.
            # Also exclude .sys files since driver load can only be done by secure kernel

            # '.*\.(exe|sys)\s(FileRule|FileAttribute|Hash).*'
            $FileRulesToModify = $FileRulesNode.ChildNodes | Where-Object -FilterScript { ($_.Name -in 'Allow', 'Deny', 'FileAttrib', 'FileRule') -and ($_.FriendlyName -notmatch '.*\.(exe|sys).*') }

            $FileRulesToModify | ForEach-Object -Process {
                $_.SetAttribute('AppIDs', [System.String]$AppIDsArray)
            }
        }
    }
    End {
        # Save the modified XML back to the file
        $Xml.Save($XmlFilePath)
    }
}
Export-ModuleMember -Function 'New-Macros'
