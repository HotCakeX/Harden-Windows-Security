function Get-ExtendedFileInfo {
  [CmdletBinding()]
  [OutputType([ordered])]
  param (
    [Parameter(Mandatory = $true)][System.IO.FileInfo]$Path
  )

  <#
  .DESCRIPTION
    This function returns the file properties of a file for SpecificFileNameLevel in FilePublisher WDAC rule level
  .PARAMETER Path
    The path to the file
  .OUTPUTS
    Ordered
  .INPUTS
    System.IO.FileInfo
  #>

  Begin {
    # Get the file object
    [System.IO.FileInfo]$File = Get-Item -LiteralPath $Path

    # Create an ordered hashtable to store the file properties
    $FileInfo = [ordered]@{}
  }
  process {
    # Add the properties to the hashtable
    $FileInfo['FileDescription'] = $File.VersionInfo.FileDescription
    $FileInfo['InternalName'] = $File.VersionInfo.InternalName
    $FileInfo['FileName'] = $File.VersionInfo.OriginalFilename
    $FileInfo['PackageFamilyName'] = $File.PackageFamilyName
    $FileInfo['ProductName'] = $File.VersionInfo.ProductName
    $FileInfo['Filepath'] = $Path
  }
  End {
    # Remove any empty values from the hashtable
    @($FileInfo.keys) | ForEach-Object -Process {
      if (!$FileInfo[$_]) { $FileInfo.Remove($_) }
    }

    # Return the ordered hashtable
    return $FileInfo
  }
}

Export-ModuleMember -Function 'Get-ExtendedFileInfo'
