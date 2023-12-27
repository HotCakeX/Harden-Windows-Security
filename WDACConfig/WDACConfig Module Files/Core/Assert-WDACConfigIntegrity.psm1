Function Assert-WDACConfigIntegrity {
    [CmdletBinding(
        DefaultParameterSetName = 'SaveLocally'
    )]
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
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Importing the required sub-modules
        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Update-self.psm1" -Force

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-self -InvocationStatement $MyInvocation.Statement }

        # Define the output file name and the URL of the cloud CSV file
        [System.String]$OutputFileName = 'Hashes.csv'
        [System.Uri]$Url = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/WDACConfig/Utilities/Hashes.csv'

        # Download the cloud CSV file and convert it to an array of objects
        [System.Object[]]$CloudCSV = (Invoke-WebRequest -Uri $Url -ProgressAction SilentlyContinue).Content | ConvertFrom-Csv

        # An empty array to store the final results
        [System.Object[]]$FinalOutput = @()
    }
    process {

        Write-Verbose -Message 'Looping through the WDACConfig module files'
        foreach ($File in Get-ChildItem -Path $ModuleRootPath -Recurse -File -Force) {

            # Making sure the PowerShell Gallery file in the WDACConfig module's folder is skipped
            if ($File.Name -eq 'PSGetModuleInfo.xml') {
                Write-Verbose -Message "Skipping the extra file: $($File.Name)"
                continue
            }

            # Create a custom object to store the relative path, file name and the hash of the file
            $FinalOutput += [PSCustomObject]@{
                RelativePath = [System.String]([System.IO.Path]::GetRelativePath($ModuleRootPath, $File.FullName))
                FileName     = [System.String]$File.Name
                FileHash     = [System.String](Get-FileHash -Path $File.FullName -Algorithm 'SHA512').Hash
            }
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
.DESCRIPTION
    The Assert-WDACConfigIntegrity function scans all the relevant files in the WDACConfig's folder and its subfolders, calculates their SHA2-512 hashes using the Get-FileHash cmdlet.
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAPwKE0KmDwFjK4
# jLrvYuYbxIml8ApUbatIkMpKN52mDaCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQg2UW4NUw0kY1PLesF5PyIRIVnkYDyCVu4eLqmgKEHc0IwDQYJKoZIhvcNAQEB
# BQAEggIAZm0Iq4kDnItFnpaIo5HNSzWAhnv4Riepc784FvB1WVeAIlRuPqdObjcn
# EjQd73N+OQdWrr34ihuh6pcZljt2RXQj8VnGSwKq77T+gJtvqdCXJIlPa1kSFC32
# Pc/on3s2uTerBu99+KrzbZMJULujvG0Y+LzefhcZdekZ0yNaIFAohvvAjryN/Na+
# lwcnCSf34djgg6LAUHY9M4SSsn0a5+MrNC1oeIxsmlrEgI9HO9P+jwWabeNZNJAv
# 1xUNk732mW7bxy9nTDkfRZB7vwNzc/9hev1f6OaQHYA+lhU46p155vfB63UXanXc
# 5japq/9SasetvsJKLC/OWOHbwSEMO7efEftv3z1II8aJp5FJrGiVeZCDVmqAwklA
# 795Z4NfCvtI4zyeZYm3x49bCvHckx6Io6XxDuYQRse/q4XKfy85Olz4T8YlL9D2z
# tJe4DdRQuKXP7ikMeik2DJ3h0Uxi0hvJFxKsgeu/bUuDdgfjlzojfzoPn2cSSd4/
# KZRluyEJ/yEvLQFfSH68go8mG48ZzOiC2708TQQQUcooxyvw1WvV1QZhUoAbVUpr
# cUQsAD0vElSm8aqYokEuTW49X2Wl6nzGu56AKVL2aO5hK8kKA1a8qKyr0ikIbh9i
# E00oc70P5MDCzPH3OLoGJ6qv1Qsac0QkDZVPsyAqQ1UkA8L8qHw=
# SIG # End signature block
