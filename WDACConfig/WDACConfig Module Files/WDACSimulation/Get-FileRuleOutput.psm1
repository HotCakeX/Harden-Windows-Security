
Function Get-FileRuleOutput {
    <#
    .SYNOPSIS
        a function that accepts WDAC policy XML content and creates an output array that contains the file rules that are based on file hashes
    .PARAMETER Xml
        The WDAC Policy XML file content as XMLDocument object
    .NOTES
        The function is intentionally not made to handle Allow all rules since checking for their existence happens in the main cmdlet
    .INPUTS
        System.Xml.XmlDocument
    .OUTPUTS
        System.Object[]
    #>
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [parameter(Mandatory = $true)][System.Xml.XmlDocument]$Xml
    )
    Begin {
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false
        . "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\PSDefaultParameterValues.ps1"

        # Create an empty array to store the output
        $OutputHashInfoProcessing = New-Object -TypeName System.Collections.Generic.HashSet[WDACConfig.PolicyHashObj]
    }

    Process {

        # Loop through each file rule in the xml file
        foreach ($FileRule in $Xml.SiPolicy.FileRules.Allow) {

            # Extract the hash value from the Hash attribute
            [System.String]$Hashvalue = $FileRule.Hash

            # Extract the hash type from the FriendlyName attribute using regex
            [System.String]$HashType = $FileRule.FriendlyName -replace '.* (Hash (Sha1|Sha256|Page Sha1|Page Sha256|Authenticode SIP Sha256))$', '$1'

            # Extract the file path from the FriendlyName attribute using regex
            [System.IO.FileInfo]$FilePathForHash = $FileRule.FriendlyName -replace ' (Hash (Sha1|Sha256|Page Sha1|Page Sha256|Authenticode SIP Sha256))$', ''

            # Add the extracted values of the current Hash rule to the output HashSet
            $OutputHashInfoProcessing.Add([WDACConfig.PolicyHashObj]::New(
                    $HashValue,
                    $HashType,
                    $FilePathForHash
                ))
        }

        # Only keep the Authenticode Hash SHA256
        $OutputHashInfoProcessing = $OutputHashInfoProcessing.Where({ $_.hashtype -eq 'Hash Sha256' })
    }

    End {
        # Return the output array
        Write-Verbose -Message "Get-FileRuleOutput: Returning $($OutputHashInfoProcessing.Count) file rules that are based on file hashes"
        return $OutputHashInfoProcessing
    }
}
Export-ModuleMember -Function 'Get-FileRuleOutput'
