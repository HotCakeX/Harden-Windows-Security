Function Checkpoint-Macros {
    <#
    .SYNOPSIS
        Backs up and restores Macros nodes in CI policy XML files.
    .DESCRIPTION
        This function can backup the Macros nodes from multiple XML files by outputting them for storage in a variable.
        It can also restore the Macros nodes to a single policy file from the backups variable.
    .NOTES
        Each valid CI policy XML file only contains a single Macros node.
    .PARAMETER Backup
        Switch parameter to indicate that the function should backup the Macros nodes.
    .PARAMETER XmlFilePathIn
        The path(s) to the XML file(s) to backup the Macros nodes from.
    .PARAMETER Restore
        Switch parameter to indicate that the function should restore the Macros nodes from the backups.
    .PARAMETER XmlFilePathOut
        The path to the XML file to restore the Macros nodes to.
    .PARAMETER MacrosBackup
        The backups of the Macros nodes to restore.
    .INPUTS
        System.IO.FileInfo[]
        System.Management.Automation.SwitchParameter
        System.Xml.XmlElement[]
    .OUTPUTS
        System.Xml.XmlElement[]
    #>
    [CmdletBinding()]
    [OutputType([System.Xml.XmlElement[]])]
    Param (
        [Parameter(Mandatory = $false, ParameterSetName = 'backup')][System.Management.Automation.SwitchParameter]$Backup,
        [Parameter(Mandatory = $false, ParameterSetName = 'backup')][System.IO.FileInfo[]]$XmlFilePathIn,

        [Parameter(Mandatory = $false, ParameterSetName = 'Restore')][System.Management.Automation.SwitchParameter]$Restore,
        [Parameter(Mandatory = $false, ParameterSetName = 'Restore')][System.IO.FileInfo]$XmlFilePathOut,
        [Parameter(Mandatory = $false, ParameterSetName = 'Restore')][System.Xml.XmlElement[]]$MacrosBackup
    )
    Process {

        if ($Backup) {

            $MacrosNodesToBackup = @()
            foreach ($XMLPath in $XmlFilePathIn) {
                # Load the XML file
                [System.Xml.XmlDocument]$Xml = New-Object System.Xml.XmlDocument
                $Xml.Load($XMLPath.FullName)

                # Define the namespace manager
                [System.Xml.XmlNamespaceManager]$Ns = New-Object System.Xml.XmlNamespaceManager($Xml.NameTable)
                $Ns.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

                # Find the Macros node
                $MacrosNode = $Xml.SelectSingleNode('//ns:Macros', $Ns)
                if ($null -ne $MacrosNode) {
                    $MacrosNodesToBackup += $MacrosNode.Clone()
                }
            }
            # Output the Macros nodes for backup if they exist, otherwise return null
            return $MacrosNodesToBackup.Count -gt 0 ? $MacrosNodesToBackup : $null
        }

        if ($Restore) {

            # Load the XML file
            [System.Xml.XmlDocument]$Xml = New-Object System.Xml.XmlDocument
            $Xml.Load($XmlFilePathOut.FullName)

            if ($null -eq $MacrosBackup) {
                [WDACConfig.Logger]::Write('Checkpoint-Macros: No Macros nodes to restore.')
                return
            }

            # Define the namespace manager
            [System.Xml.XmlNamespaceManager]$Ns = New-Object System.Xml.XmlNamespaceManager($Xml.NameTable)
            $Ns.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

            # Remove the current Macros nodes if they exist in the XML file
            $CurrentMacrosNodes = $Xml.SelectNodes('//ns:Macros', $Ns)
            foreach ($Node in $CurrentMacrosNodes) {
                [System.Void]$Xml.DocumentElement.RemoveChild($Node)
            }

            # Create a new Macros node
            $NewMacrosNode = $Xml.CreateElement('Macros', $Xml.DocumentElement.NamespaceURI)

            # Combine all Macro elements into the new Macros node
            foreach ($BackupNode in $MacrosBackup) {
                foreach ($Macro in $BackupNode.ChildNodes) {
                    $ImportedMacro = $Xml.ImportNode($Macro, $true)
                    [System.Void]$NewMacrosNode.AppendChild($ImportedMacro)
                }
            }

            # Append the new Macros node to the XML file
            [System.Void]$Xml.DocumentElement.AppendChild($NewMacrosNode)
        }
    }
    End {
        # Save the modified XML back to the file
        if ($Restore) {
            $Xml.Save($XmlFilePathOut.FullName)
        }
    }
}

Export-ModuleMember -Function 'Checkpoint-Macros'
