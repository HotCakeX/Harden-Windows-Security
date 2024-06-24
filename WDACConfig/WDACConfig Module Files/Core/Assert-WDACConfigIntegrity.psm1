Function Assert-WDACConfigIntegrity {
    [CmdletBinding(
        DefaultParameterSetName = 'SaveLocally'
    )]
    [OutputType([System.String], [System.Object[]])]
    param (
        [Alias('S')]
        [Parameter(Mandatory = $false, ParameterSetName = 'SaveLocally')]
        [System.Management.Automation.SwitchParameter]$SaveLocally,

        [Alias('P')]
        [Parameter(Mandatory = $false, ParameterSetName = 'SaveLocally')]
        [ValidateScript({ Test-Path -Path $_ -PathType 'Container' })]
        [System.IO.FileInfo]$Path = "$ModuleRootPath\..\Utilities\",

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )
    begin {
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -Force -FullyQualifiedName @(
            "$ModuleRootPath\Shared\Update-Self.psm1",
            "$ModuleRootPath\Shared\Write-ColorfulText.psm1"
        )

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-Self -InvocationStatement $MyInvocation.Statement }

        # Define the output file name and the URL of the cloud CSV file
        [System.String]$OutputFileName = 'Hashes.csv'
        [System.Uri]$Url = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/WDACConfig/Utilities/Hashes.csv'

        # Download the cloud CSV file and convert it to an array of objects
        [System.Object[]]$CloudCSV = (Invoke-WebRequest -Uri $Url -ProgressAction SilentlyContinue).Content | ConvertFrom-Csv

        # An empty array to store the final results
        $FinalOutput = New-Object -TypeName System.Collections.Generic.List[PSCustomObject]
    }
    process {

        Write-Verbose -Message 'Looping through the WDACConfig module files'
        foreach ($File in ([WDACConfig.FileUtility]::GetFilesFast($ModuleRootPath, $null, '*'))) {

            # Making sure the PowerShell Gallery file in the WDACConfig module's folder is skipped
            if ($File.Name -eq 'PSGetModuleInfo.xml') {
                Write-Verbose -Message "Skipping the extra file: $($File.Name)"
                continue
            }

            # Read the file as a byte array - This way we can get hashes of a file in use by another process where Get-FileHash would fail
            [System.Byte[]]$Bytes = [System.IO.File]::ReadAllBytes($File)

            #Region SHA2-512 calculation
            # Create a SHA512 object
            [System.Security.Cryptography.SHA512]$Sha512 = [System.Security.Cryptography.SHA512]::Create()

            # Compute the hash of the byte array
            [System.Byte[]]$HashBytes = $Sha512.ComputeHash($Bytes)

            # Dispose the SHA512 object
            $Sha512.Dispose()

            # Convert the hash bytes to a hexadecimal string to make it look like the output of the Get-FileHash which produces hexadecimals (0-9 and A-F)
            # If [System.Convert]::ToBase64String was used, it'd return the hash in base64 format, which uses 64 symbols (A-Z, a-z, 0-9, + and /) to represent each byte
            [System.String]$HashString = [System.BitConverter]::ToString($HashBytes)

            # Remove the dashes from the hexadecimal string
            $HashString = $HashString.Replace('-', '')
            #Endregion SHA2-512 calculation

            #Region SHA3-512 calculation
            try {
                [System.Security.Cryptography.SHA3_512]$SHA3_512 = [System.Security.Cryptography.SHA3_512]::Create()

                # Compute the hash of the byte array
                [System.Byte[]]$SHA3_512HashBytes = $SHA3_512.ComputeHash($Bytes)

                # Dispose the SHA3_512 object
                $SHA3_512.Dispose()

                # Convert the hash bytes to a hexadecimal string to make it look like the output of the Get-FileHash which produces hexadecimals (0-9 and A-F)
                # If [System.Convert]::ToBase64String was used, it'd return the hash in base64 format, which uses 64 symbols (A-Z, a-z, 0-9, + and /) to represent each byte
                [System.String]$SHA3_512HashString = [System.BitConverter]::ToString($SHA3_512HashBytes)

                # Remove the dashes from the hexadecimal string
                $SHA3_512HashString = $SHA3_512HashString.Replace('-', '')
            }
            catch [System.PlatformNotSupportedException] {
                Write-Verbose -Message 'The SHA3-512 algorithm is not supported on this system. Requires build 24H2 or higher.'
            }
            #Endregion SHA3-512 calculation

            # Create a custom object to store the relative path, file name and the hash of the file
            $FinalOutput.Add([PSCustomObject]@{
                    RelativePath     = [System.String]([System.IO.Path]::GetRelativePath($ModuleRootPath, $File.FullName))
                    FileName         = [System.String]$File.Name
                    FileHash         = [System.String]$HashString
                    FileHashSHA3_512 = [System.String]$SHA3_512HashString
                })
        }

        if ($SaveLocally) {
            Write-Verbose -Message "Saving the results to a CSV file in $($Path.FullName)"
            $FinalOutput | Export-Csv -Path (Join-Path -Path $Path -ChildPath $OutputFileName) -Force
        }
    }
    end {
        Write-Verbose -Message 'Comparing the local files hashes with the ones in the cloud'
        [System.Object[]]$ComparisonResults = Compare-Object -ReferenceObject $CloudCSV -DifferenceObject $FinalOutput -Property RelativePath, FileName, FileHash | Where-Object -Property SideIndicator -EQ '=>'

        if ($ComparisonResults) {
            Write-Warning -Message 'Tampered files detected!'
            Write-ColorfulText -Color PinkBoldBlink -InputText 'The following files are different from the ones in the cloud:'
            $ComparisonResults
        }
        else {
            Write-ColorfulText -Color NeonGreen -InputText 'All of your local WDACConfig files are genuine.'
        }
    }
    <#
.SYNOPSIS
    Gets the SHA2-512 hashes of files in the WDACConfig and compares them with the ones in the cloud and shows the differences.
    It also calculates the SHA3-512 hashes of the files and will completely switch to this new algorithm after Windows build 24H2 is reached GA.
.DESCRIPTION
    The Assert-WDACConfigIntegrity function scans all the relevant files in the WDACConfig's folder and its subfolders, calculates their SHA2-512 hashes in hexadecimal format,
    Then it downloads the cloud CSV file from the GitHub repository and compares the hashes of the local files with the ones in the cloud.
    By doing so, you can ascertain that the files in your local WDACConfig folder are identical to the ones in the cloud and devoid of any interference.
    If there is any indication of tampering, the outcomes will be displayed on the console.
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Assert-WDACConfigIntegrity
.PARAMETER SaveLocally
    Indicates that the function should save the results to a CSV file locally.
    You don't need to use this parameter.
.PARAMETER Path
    Specifies the path to save the CSV file to. The default path is the Utilities folder in the WDACConfig's folder.
    This is used before uploading to GitHub to renew the hashes.
    You don't need to use this parameter.
.PARAMETER SkipVersionCheck
    Indicates that the function should skip the version check and not run the updater.
.PARAMETER Verbose
    Indicates that the function should display verbose messages.
.INPUTS
    System.Management.Automation.SwitchParameter
    System.IO.FileInfo
.OUTPUTS
    System.String
    System.Object[]
.EXAMPLE
    Assert-WDACConfigIntegrity
#>
}


# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD3vkemtShWfZhy
# mygRSMAaTBRmvabzOtlTdB07mkEKx6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgtpHzllpNLP4rMubolzRhCEqaS73b/bi9UW6WYHkJFrcwDQYJKoZIhvcNAQEB
# BQAEggIAQ9dxpH8Byd3YGwyoGJahJtUP0qE4rBVsRlhZPEUSYeWVkfffk5oNstHx
# ftOx98hgOb1bngsvQ4BwQIoBa8RCAXdgqWlqFHzdTtRTuVbXPUJD6UWwyoAhTbZA
# gPRshCMaQTYGK3FeJBQ8AKVjjDVB4/vlHgjGkJwZzr+eGzCa/pvVHaNxajjHjesK
# 9R52sxtCuhTgEUQCAwxMqAyNy1Vh5lt6mmL47dQrVAdaMCxCSCbigscBO0q6xDV0
# AbtPiwuYwNLVNSFdWZ/m5KKZdyYNpiMRZS5uYAJKsPn2ZL0CaVfPs55emoFWpjBv
# eP3k+MgidiJ1MwMMnP4sBi+bKh6liA/gnOb1qidldVbt62QF9iih3QAI2i2TQU2j
# WU2ILCeGOBXCVf9pW1VFU/b5z1D7buBYS9q+WzajdBSv74MWiYSkif8Vf57j89RM
# znhg1PE3PStvq45a25el/NeISWjmtegvEpIJhItpD8dlgM2kgXKA4p6WR7Xm/c2B
# AI3IKp740j4mtQBMzmvZS8PjxRKXJZxK/J7qGJdWl5gRzzHafmzNXv/2244MckIF
# 2UFWxgejx81eGdhO94o3ZOqZTO4YSMIq60MEkuIWt3tMnuBlXVzHAnjEv/4713zl
# jm8uwsw5HKLW2QTE6o8oggJXniHwvqgK+9ER/n/kUROhKtMO0bk=
# SIG # End signature block
