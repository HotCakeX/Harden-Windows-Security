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
  .INPUTS
    System.IO.FileInfo
  .OUTPUTS
    Ordered
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
        Write-Verbose -Message "There was an error while trying to get the OriginalFileName property using Get-AppLockerFileInformation cmdlet: $($_.Exception.Message)"
      }
    }
  }
  End {
    # Return the ordered hashtable
    return $FileInfo
  }
}

Export-ModuleMember -Function 'Get-ExtendedFileInfo'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDGKnZdks5GOQd9
# Bb/QyAjPPx3wxtXJLJpd25GgZqy636CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
# LDQz/68TAAAAAAAEMA0GCSqGSIb3DQEBDQUAME8xEzARBgoJkiaJk/IsZAEZFgNj
# b20xIjAgBgoJkiaJk/IsZAEZFhJIT1RDQUtFWC1DQS1Eb21haW4xFDASBgNVBAMT
# C0hPVENBS0VYLUNBMCAXDTIzMTIyNzExMjkyOVoYDzIyMDgxMTEyMTEyOTI5WjB5
# MQswCQYDVQQGEwJVSzEeMBwGA1UEAxMVSG90Q2FrZVggQ29kZSBTaWduaW5nMSMw
# IQYJKoZIhvcNAQkBFhRob3RjYWtleEBvdXRsb29rLmNvbTElMCMGCSqGSIb3DQEJ
# ARYWU3B5bmV0Z2lybEBvdXRsb29rLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAKb1BJzTrpu1ERiwr7ivp0UuJ1GmNmmZ65eckLpGSF+2r22+7Tgm
# pEifj9NhPw0X60F9HhdSM+2XeuikmaNMvq8XRDUFoenv9P1ZU1wli5WTKHJ5ayDW
# k2NP22G9IPRnIpizkHkQnCwctx0AFJx1qvvd+EFlG6ihM0fKGG+DwMaFqsKCGh+M
# rb1bKKtY7UEnEVAsVi7KYGkkH+ukhyFUAdUbh/3ZjO0xWPYpkf/1ldvGes6pjK6P
# US2PHbe6ukiupqYYG3I5Ad0e20uQfZbz9vMSTiwslLhmsST0XAesEvi+SJYz2xAQ
# x2O4n/PxMRxZ3m5Q0WQxLTGFGjB2Bl+B+QPBzbpwb9JC77zgA8J2ncP2biEguSRJ
# e56Ezx6YpSoRv4d1jS3tpRL+ZFm8yv6We+hodE++0tLsfpUq42Guy3MrGQ2kTIRo
# 7TGLOLpayR8tYmnF0XEHaBiVl7u/Szr7kmOe/CfRG8IZl6UX+/66OqZeyJ12Q3m2
# fe7ZWnpWT5sVp2sJmiuGb3atFXBWKcwNumNuy4JecjQE+7NF8rfIv94NxbBV/WSM
# pKf6Yv9OgzkjY1nRdIS1FBHa88RR55+7Ikh4FIGPBTAibiCEJMc79+b8cdsQGOo4
# ymgbKjGeoRNjtegZ7XE/3TUywBBFMf8NfcjF8REs/HIl7u2RHwRaUTJdAgMBAAGj
# ggJzMIICbzA8BgkrBgEEAYI3FQcELzAtBiUrBgEEAYI3FQiG7sUghM++I4HxhQSF
# hqV1htyhDXuG5sF2wOlDAgFkAgEIMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1Ud
# DwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYB
# BQUHAwMwHQYDVR0OBBYEFOlnnQDHNUpYoPqECFP6JAqGDFM6MB8GA1UdIwQYMBaA
# FICT0Mhz5MfqMIi7Xax90DRKYJLSMIHUBgNVHR8EgcwwgckwgcaggcOggcCGgb1s
# ZGFwOi8vL0NOPUhPVENBS0VYLUNBLENOPUhvdENha2VYLENOPUNEUCxDTj1QdWJs
# aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
# LERDPU5vbkV4aXN0ZW50RG9tYWluLERDPWNvbT9jZXJ0aWZpY2F0ZVJldm9jYXRp
# b25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwgccG
# CCsGAQUFBwEBBIG6MIG3MIG0BggrBgEFBQcwAoaBp2xkYXA6Ly8vQ049SE9UQ0FL
# RVgtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZp
# Y2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Tm9uRXhpc3RlbnREb21haW4sREM9Y29t
# P2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0
# aG9yaXR5MA0GCSqGSIb3DQEBDQUAA4ICAQA7JI76Ixy113wNjiJmJmPKfnn7brVI
# IyA3ZudXCheqWTYPyYnwzhCSzKJLejGNAsMlXwoYgXQBBmMiSI4Zv4UhTNc4Umqx
# pZSpqV+3FRFQHOG/X6NMHuFa2z7T2pdj+QJuH5TgPayKAJc+Kbg4C7edL6YoePRu
# HoEhoRffiabEP/yDtZWMa6WFqBsfgiLMlo7DfuhRJ0eRqvJ6+czOVU2bxvESMQVo
# bvFTNDlEcUzBM7QxbnsDyGpoJZTx6M3cUkEazuliPAw3IW1vJn8SR1jFBukKcjWn
# aau+/BE9w77GFz1RbIfH3hJ/CUA0wCavxWcbAHz1YoPTAz6EKjIc5PcHpDO+n8Fh
# t3ULwVjWPMoZzU589IXi+2Ol0IUWAdoQJr/Llhub3SNKZ3LlMUPNt+tXAs/vcUl0
# 7+Dp5FpUARE2gMYA/XxfU9T6Q3pX3/NRP/ojO9m0JrKv/KMc9sCGmV9sDygCOosU
# 5yGS4Ze/DJw6QR7xT9lMiWsfgL96Qcw4lfu1+5iLr0dnDFsGowGTKPGI0EvzK7H+
# DuFRg+Fyhn40dOUl8fVDqYHuZJRoWJxCsyobVkrX4rA6xUTswl7xYPYWz88WZDoY
# gI8AwuRkzJyUEA07IYtsbFCYrcUzIHME4uf8jsJhCmb0va1G2WrWuyasv3K/G8Nn
# f60MsDbDH1mLtzGCAxgwggMUAgEBMGYwTzETMBEGCgmSJomT8ixkARkWA2NvbTEi
# MCAGCgmSJomT8ixkARkWEkhPVENBS0VYLUNBLURvbWFpbjEUMBIGA1UEAxMLSE9U
# Q0FLRVgtQ0ECEx4AAAAEjzQsNDP/rxMAAAAAAAQwDQYJYIZIAWUDBAIBBQCggYQw
# GAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQx
# IgQgQdf01IEgwE3RLx3Fmlh6RBebttjdJ7n2O4dnWXzLfbgwDQYJKoZIhvcNAQEB
# BQAEggIAApEURl4i8a4c4DSJW5ZVgC6O/k3BkM0pvwp3ON9XkB4zJS7C3ED2vJ93
# lXoFoK9MMsFQM+payY9iBwA9uucnq51S2VJY0eDDeB/BrVdLTjisgsIzMBz1Ur0I
# t9KYbGSbZkx7Dl3bZ5bVf0FtBjPXfNUVsOb0v84Ccx4Qk4V5NeN5FiNFshLnV3SF
# t68C13r/0JMyN0feU5FDbl6oJyL4Y/MhB4vCeH1C4QajlQYDv2ed3EnJFgzbG753
# wiSRS5s7AIk4td2+YL1tsZIMZwca1b18RsSpEdIEH+NFJMno1iAVLA0c/Nvjxbwr
# DZ0k8/7MhgS2IRvVf6pRt6a0FV2lRl/T8AcV7hsw04HMhSDeMhUanDPDCyvPcx0L
# AQHcDwwdtczQZ+3aHlIRqwuxRzJQVvo9EsvJp9ivLDER6KsBTQnCflCcQTS5qroi
# xe4EkLRSOHykHpnVBXg+XRlPq4ZtwoylJ+rDmYYc9XfijmcreHrcF7BrgxSW2jTu
# zp0LjLgOyXFiFIiUFLrfFaP+nL4Vpnet4av6nRSacHw0UiT8IkXvXwovI9UIr85P
# 7njqIamkiFjY9QFZfY4zG/xCPnpoACiCdX6Ik42dBC13iuxd8omXqz702Sizo/74
# IOLWSZgMhg4cD7N1I2vxBH9by93QOYUKyXyEUAds5rNdpAtGlFc=
# SIG # End signature block
