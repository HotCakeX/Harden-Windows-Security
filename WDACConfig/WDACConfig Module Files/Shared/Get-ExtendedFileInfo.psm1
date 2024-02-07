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

    # If the Get-Item cmdlet didn't find any of these properties then initiate Com object creation to get them if they are available
    # Only these 3 properties are checked because the Com object method can't get the other ones
    if ((-NOT $FileInfo['FileName']) -or (-NOT $FileInfo['FileDescription']) -or (-NOT $FileInfo['ProductName'])) {

      # Create a Shell.Application object
      [System.__ComObject]$Shell = New-Object -ComObject Shell.Application

      # Get the folder and file names from the path
      [System.String]$Folder = Split-Path $Path
      [System.String]$File = Split-Path $Path -Leaf

      # Get the ShellFolder and ShellFile objects from the Shell.Application object
      [System.__ComObject]$ShellFolder = $Shell.Namespace($Folder)
      [System.__ComObject]$ShellFile = $ShellFolder.ParseName($File)

      # Get the properties from the ShellFile object using their property ID
      # Null coalescing operator can't be used because the hashtable values are not null, just empty
      $FileInfo['FileDescription'] = $FileInfo['FileDescription'] ? $FileInfo['FileDescription'] : $ShellFolder.GetDetailsOf($ShellFile, 34)
      $FileInfo['FileName'] = $FileInfo['FileName'] ? $FileInfo['FileName'] : $ShellFolder.GetDetailsOf($ShellFile, 165)
      $FileInfo['ProductName'] = $FileInfo['ProductName'] ? $FileInfo['ProductName'] : $ShellFolder.GetDetailsOf($ShellFile, 297)

      # Release the Shell.Application object
      [Runtime.InteropServices.Marshal]::ReleaseComObject($Shell) | Out-Null

    }

    # Return the ordered hashtable
    return $FileInfo
  }
}

Export-ModuleMember -Function 'Get-ExtendedFileInfo'
