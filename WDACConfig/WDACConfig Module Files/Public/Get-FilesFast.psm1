Function Get-FilesFast {
    <#
   .SYNOPSIS
        a flexible and fast scriptblock that can accept directory paths and file paths as input and return a list of FileInfo objects that are compliant with the WDAC policy.
        It supports custom extensions to filter by as well.
    .INPUTS
        System.IO.DirectoryInfo[]
        System.IO.FileInfo[]
        System.String[]
    .OUTPUTS
        System.IO.FileInfo[]
    .PARAMETER Directory
        The directories to process
    .PARAMETER File
        The files to process
    .PARAMETER ExtensionsToFilterBy
        The extensions to filter by. If not supplied, the default extensions are used which are all WDAC supported extensions.
        Accepts Wildcards, if used, all files will be returned.
   #>
    Param (
        [Parameter(Mandatory = $false)][System.IO.DirectoryInfo[]]$Directory,
        [Parameter(Mandatory = $false)][System.IO.FileInfo[]]$File,
        [Parameter(Mandatory = $false)][System.String[]]$ExtensionsToFilterBy
    )

    Begin {
        # If custom extensions are supplied then use them, otherwise use the default extensions
        if ($null -ne $ExtensionsToFilterBy -and $ExtensionsToFilterBy.count -gt 0) {
            $Extensions = [System.Collections.Generic.HashSet[System.String]]::new(
                [System.String[]]$ExtensionsToFilterBy,
                # Make it case-insensitive
                [System.StringComparer]::InvariantCultureIgnoreCase
            )
        }
        else {
            # Define a HashSet of file extensions to filter by
            $Extensions = [System.Collections.Generic.HashSet[System.String]]::new(
                [System.String[]] ('.sys', '.exe', '.com', '.dll', '.rll', '.ocx', '.msp', '.mst', '.msi', '.js', '.vbs', '.ps1', '.appx', '.bin', '.bat', '.hxs', '.mui', '.lex', '.mof'),
                # Make it case-insensitive
                [System.StringComparer]::InvariantCultureIgnoreCase
            )
        }

        # Define a HashSet to store the final output
        $Output = [System.Collections.Generic.HashSet[System.IO.FileInfo]]@()

        $Options = [System.IO.EnumerationOptions]@{
            IgnoreInaccessible    = $true
            RecurseSubdirectories = $true
            AttributesToSkip      = 'None'
        }
    }

    Process {
        if ($null -ne $Directory -and $Directory.Count -gt 0) {

            foreach ($Path in $Directory) {
                [System.IO.Enumeration.FileSystemEnumerator[System.IO.FileInfo]]$Enum = $Path.EnumerateFiles('*', $Options).GetEnumerator()
                while ($true) {
                    try {
                        # Move to the next file
                        if (-not $Enum.MoveNext()) {
                            # If we reach the end of the enumeration, we break out of the loop
                            break
                        }
                        # Check if the file extension is in the Extensions HashSet or Wildcard was used
                        if ($Extensions.Contains($Enum.Current.Extension) -or ($Extensions.Contains('*'))) {
                            # add the file to the output
                            [System.Void]$Output.Add($Enum.Current)
                        }
                    }
                    catch {}
                }
            }
        }

        if ($null -ne $File -and $File.Count -gt 0) {
            $Output.UnionWith([System.IO.FileInfo[]]($File.Where({ $Extensions.Contains($_.Extension) })))
        }
    }

    End {
        if ($null -ne $Output -and $Output.Count -gt 0 ) {
            Return ([System.IO.FileInfo[]]$Output)
        }
        else {
            Return $null
        }
    }
}
Export-ModuleMember -Function 'Get-FilesFast'
