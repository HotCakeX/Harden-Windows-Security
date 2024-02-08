function Get-ExtendedFileInfo {
  [CmdletBinding()]
  [OutputType([ordered])]
  param (
    [Parameter(Mandatory = $true)][System.IO.FileInfo]$Path
  )

  <#
  .DESCRIPTION
    This function returns the file properties of a file for SpecificFileNameLevel in FilePublisher WDAC rule level
  .NOTES
    All the returned properties must be strings because Compare-SignerAndCertificate performs string comparison with the Signers' info from the XML file
    For example, FileInfo object for the FilePath property should be flattened to string
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
    $FileInfo['FileDescription'] = [System.String]$File.VersionInfo.FileDescription
    $FileInfo['InternalName'] = [System.String]$File.VersionInfo.InternalName
    $FileInfo['FileName'] = [System.String]$File.VersionInfo.OriginalFilename
    $FileInfo['PackageFamilyName'] = [System.String]$File.PackageFamilyName
    $FileInfo['ProductName'] = [System.String]$File.VersionInfo.ProductName
    $FileInfo['FilePath'] = [System.String]$Path
  }
  End {
    # Remove any empty values from the hashtable
    @($FileInfo.keys) | ForEach-Object -Process {
      if (!$FileInfo[$_]) { $FileInfo.Remove($_) }
    }

    # If the Get-Item cmdlet didn't find any of these properties then initiate Com object creation to get them if they are available
    # Only these 2 properties are checked because the Com object method can't get the other ones
    if ((-NOT $FileInfo['FileDescription']) -or (-NOT $FileInfo['ProductName'])) {

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
      $FileInfo['FileDescription'] = $FileInfo['FileDescription'] ? $FileInfo['FileDescription'] : [System.String]$ShellFolder.GetDetailsOf($ShellFile, 34)
      $FileInfo['ProductName'] = $FileInfo['ProductName'] ? $FileInfo['ProductName'] : [System.String]$ShellFolder.GetDetailsOf($ShellFile, 297)

      # Release the Shell.Application object
      [Runtime.InteropServices.Marshal]::ReleaseComObject($Shell) | Out-Null

    }

    # If the Get-Item cmdlet couldn't find the OriginalFileName property of the file, use Get-AppLockerFileInformation's output and parse it for OriginalFileName string
    if (-NOT $FileInfo['FileName']) {

      try {

        Write-Verbose -Message "OriginalFileName property not found. Using Get-AppLockerFileInformation's output and parsing it for OriginalFileName string."

        [System.String]$OriginalFileNameRaw = (Get-AppLockerFileInformation -Path $Path).Publisher

        if ((-NOT ([System.String]::IsNullOrWhiteSpace($OriginalFileNameRaw)))) {

          # Split the input by the backslash (\) characters
          [System.String[]]$Parts = $OriginalFileNameRaw.Split('\')

          if (($Parts -is [System.String[]]) -and ($Parts.Count -gt 0)) {

            # Get the last part of the split string which contains OriginalFileName and Version
            [System.String]$VersionAndName = $Parts[-1]

            if ((-NOT ([System.String]::IsNullOrWhiteSpace($VersionAndName)))) {

              # Split the last part by the comma (,) characters and get the first part which contains OriginalFileName
              [System.String]$ExtractedOriginalFileNameAttrib = $VersionAndName.Split(',')[0]

              if ((-NOT ([System.String]::IsNullOrWhiteSpace($ExtractedOriginalFileNameAttrib)))) {

                # Assign the OriginalFileName to the FileName property
                $FileInfo['FileName'] = $ExtractedOriginalFileNameAttrib

                Write-Verbose -Message "OriginalFileName property found using Get-AppLockerFileInformation: $ExtractedOriginalFileNameAttrib"
              }
            }
          }
        }
      }
      catch {
        # Gracefully handle the error since it should not stop the execution
        Write-Verbose -Message "There was an error while trying to get the OriginalFileName property using Get-AppLockerFileInformation. Error: $($_.Exception.Message)"
      }
    }

    # Return the ordered hashtable
    return $FileInfo
  }
}

Export-ModuleMember -Function 'Get-ExtendedFileInfo'
