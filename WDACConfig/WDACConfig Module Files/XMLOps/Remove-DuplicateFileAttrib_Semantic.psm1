function Remove-DuplicateFileAttrib_Semantic {
    <#
    .SYNOPSIS
        A function that deduplicates the <FileAttrib> elements inside the <FileRules> node.
        It successfully detects duplicate <FileAttrib> elements based on their properties. For example,
        if two <FileAttrib> elements have the same MinimumFileVersion and one of these properties of them are the same (FileName, InternalName, FileDescription, FilePath, and ProductName), they are considered half-duplicates.
        In order to be considered fully duplicate, they must also be associated with Signers whose IDs are in the same SigningScenario.

        So for example, if two <FileAttrib> elements have the same FileName and MinimumFileVersion, but they are associated with 2 different Signers, one in kernel mode and the other in user mode signing scenario, they are not considered duplicates.

        After deduplication, the function updates the FileAttribRef RuleID for associated Signers by setting the RuleID of the removed duplicate FileAttrib elements to the RuleID of the unique remaining FileAttrib element.

        This is according to the CI Schema
    .PARAMETER XmlFilePath
        The path to the XML file to be processed
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$XmlFilePath
    )
    Begin {
        # Load the XML file
        [System.Xml.XmlDocument]$XmlDoc = New-Object -TypeName System.Xml.XmlDocument
        $XmlDoc.Load($XmlFilePath)

        # Create a namespace manager
        [System.Xml.XmlNamespaceManager]$NsMgr = New-Object -TypeName System.Xml.XmlNamespaceManager -ArgumentList $XmlDoc.NameTable
        $NsMgr.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

        # Define a hashtable to store FileAttrib elements based on their properties
        [System.Collections.Hashtable]$FileAttribHash = @{}

        # Define a hashtable to store FileAttrib elements along with their associated Signer IDs
        [System.Collections.Hashtable]$FileAttribSignerHash = @{}

        # Define a hashtable to store Signer IDs and their associated SigningScenario IDs
        [System.Collections.Hashtable]$SignerScenarioHash = @{}
    }
    Process {
        # Iterate through each FileAttrib element
        foreach ($FileAttrib in $XmlDoc.SelectNodes('//ns:FileAttrib', $NsMgr)) {

            # Get the relevant properties
            [System.String]$MinimumFileVersion = $FileAttrib.GetAttribute('MinimumFileVersion')
            [System.String]$FileName = $FileAttrib.GetAttribute('FileName')
            [System.String]$InternalName = $FileAttrib.GetAttribute('InternalName')
            [System.String]$FileDescription = $FileAttrib.GetAttribute('FileDescription')
            [System.String]$FilePath = $FileAttrib.GetAttribute('FilePath')
            [System.String]$ProductName = $FileAttrib.GetAttribute('ProductName')

            # Generate a unique key based on relevant properties
            [System.String]$Key = "$MinimumFileVersion-$FileName-$InternalName-$FileDescription-$FilePath-$ProductName"

            # Check if the key already exists in the hashtable
            if (-not $FileAttribHash.ContainsKey($Key)) {

                # If not, add the key and create a new array to store the FileAttrib element
                $FileAttribHash[$Key] = @($FileAttrib)
            }
            else {
                # If the key already exists, append the FileAttrib element to the existing array
                $FileAttribHash[$Key] += $FileAttrib
            }

            # Get the Signer ID associated with this FileAttrib
            $SignerID = $XmlDoc.SelectSingleNode("//ns:Signer[ns:FileAttribRef/@RuleID='$($FileAttrib.GetAttribute('ID'))']/@ID", $NsMgr).Value

            # Add the FileAttrib and its associated Signer ID to the hashtable
            if (-not $FileAttribSignerHash.ContainsKey($Key)) {

                # If not, add the key and create a new array to store the Signer ID
                $FileAttribSignerHash[$Key] = @($SignerID)
            }
            else {
                # If the key already exists, append the Signer ID to the existing array
                $FileAttribSignerHash[$Key] += $SignerID
            }

            # Get the SigningScenario ID associated with this Signer ID
            $SigningScenarioID = $XmlDoc.SelectSingleNode("//ns:SigningScenario[ns:ProductSigners/ns:AllowedSigners/ns:AllowedSigner[@SignerId='$SignerID']]/@ID", $NsMgr).Value

            # Add the Signer ID and its associated SigningScenario ID to the hashtable
            if (-not $SignerScenarioHash.ContainsKey($SignerID)) {

                # add the Signer ID and create a new array to store the SigningScenario ID
                $SignerScenarioHash[$SignerID] = @($SigningScenarioID)
            }
            else {
                # If the Signer ID already exists, append the SigningScenario ID to the existing array
                $SignerScenarioHash[$SignerID] += $SigningScenarioID
            }
        }

        # Iterate through the hashtable to find and remove duplicates
        foreach ($Key in $FileAttribHash.Keys) {

            # If there's more than one FileAttrib element for this key
            if ($FileAttribHash[$Key].Count -gt 1) {

                # Get the unique Signer IDs associated with the FileAttrib elements
                $SignerIDs = $FileAttribSignerHash[$Key] | Select-Object -Unique

                # Get the unique SigningScenario IDs associated with the Signer IDs
                $ScenarioIDs = foreach ($ID in $SignerIDs) {
                    $SignerScenarioHash[$ID]
                }
                $ScenarioIDs = $ScenarioIDs | Select-Object -Unique

                # If there are multiple unique SigningScenario IDs associated with this set of Signer IDs
                if ($ScenarioIDs.Count -gt 1) {
                    # Skip deduplication as the Signer IDs are in different Signing scenarios, meaning both User and Kernel modes are involved so it shouldn't be touched
                    continue
                }
                else {
                    # Remove duplicates by keeping only the first FileAttrib element
                    $FirstFileAttrib = $FileAttribHash[$Key] | Select-Object -First 1

                    # Iterate through the remaining FileAttrib elements
                    for ($i = 1; $i -lt $FileAttribHash[$Key].Count; $i++) {

                        # Get the duplicate FileAttrib element to remove based on the index
                        $FileAttribToRemove = $FileAttribHash[$Key][$i]

                        # Update FileAttribRef RuleID for associated Signers
                        foreach ($Item in $SignerIDs) {

                            # Get the Signer element associated with this Signer ID
                            $Signer = $XmlDoc.SelectSingleNode("//ns:Signer[@ID='$Item']", $NsMgr)

                            # Get the FileAttribRef element associated with the duplicate FileAttrib element
                            $FileAttribRef = $Signer.SelectSingleNode("ns:FileAttribRef[@RuleID='$($FileAttribToRemove.GetAttribute('ID'))']", $NsMgr)

                            # Updating the RuleID of the duplicate <FileAttribRef> of the Signer before removing it and setting it to the RuleID of the unique remaining FileAttrib element
                            if ($Null -ne $FileAttribRef) {

                                if ($FirstFileAttrib.GetAttribute('ID') -notin $Signer.FileAttribRef.RuleID) {

                                    $FileAttribRef.SetAttribute('RuleID', $FirstFileAttrib.GetAttribute('ID'))
                                }
                            }
                        }
                        # Remove the duplicate FileAttrib element
                        [WDACConfig.Logger]::Write("Remove-DuplicateFileAttrib: Removed duplicate FileAttrib with ID: $($FileAttribToRemove.GetAttribute('ID'))")
                        [System.Void]$FileAttribToRemove.ParentNode.RemoveChild($FileAttribToRemove)
                    }
                }
            }
        }
    }

    End {
        $XmlDoc.Save($XmlFilePath)
    }
}
Export-ModuleMember -Function 'Remove-DuplicateFileAttrib_Semantic'
