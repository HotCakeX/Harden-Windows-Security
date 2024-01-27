Function Copy-CiRules {
    <#
    .DESCRIPTION
        Copies the rules from one CI policy XML file to another
    .PARAMETER SourceFile
        The source CI policy XML file
    .PARAMETER DestinationFile
        The destination CI policy XML file
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        None
    #>
    [CmdletBinding ()]
    Param (    
        [Parameter (Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [System.IO.FileInfo]$SourceFile,

        [Parameter (Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [System.IO.FileInfo]$DestinationFile
    )

    # Load the XML files as objects
    [Xml.XmlDocument]$SourceFileContent = Get-Content -Path $SourceFile
    [Xml.XmlDocument]$DestinationFileContent = Get-Content -Path $DestinationFile

    # Replace the rules block in $DestinationFileContent with the rules block in $SourceFileContent
    # Use the ImportNode method to create a copy of the rules node from $SourceFileContent
    # The second parameter ($true) indicates a deep clone, meaning that the node and its descendants are copied
    # https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmldocument.importnode
    [Xml.XmlNode]$Rules = $DestinationFileContent.ImportNode($SourceFileContent.SiPolicy.Rules, $true)
    # Use the ReplaceChild method to replace the rules node in $DestinationFileContent with the copied node
    $DestinationFileContent.SiPolicy.ReplaceChild($Rules, $DestinationFileContent.SiPolicy.Rules) | Out-Null

    # Save the modified XML file
    $DestinationFileContent.Save($DestinationFile)
}
Export-ModuleMember -Function Copy-CiRules
