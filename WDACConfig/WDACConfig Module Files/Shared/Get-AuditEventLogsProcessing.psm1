Function Get-AuditEventLogsProcessing {
    <#
    .SYNOPSIS
        Function to separately capture FileHashes of deleted files and FilePaths of available files from Event Viewer Audit Logs
    .PARAMETER Date
        The date from which the Event Viewer Audit Logs should be scanned
    .INPUTS
        System.DateTime
    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    param (
        [System.DateTime]$Date
    )

    begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"
        # Importing the required sub-modules
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-GlobalRootDrives.psm1" -Force

        # Get the local disks mappings
        [System.Object[]]$DriveLettersGlobalRootFix = Get-GlobalRootDrives

        # Defining a custom object to store the results and return it at the end
        $AuditEventLogsProcessingResults = [PSCustomObject]@{
            # Defining object properties as arrays that store file paths
            AvailableFilesPaths = [System.IO.FileInfo[]]@()
            DeletedFileHashes   = [System.IO.FileInfo[]]@()
        }
    }

    process {

        # Event Viewer Code Integrity logs scan
        foreach ($event in Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; ID = 3076 } -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_.TimeCreated -ge $Date } ) {

            $Xml = [System.Xml.XmlDocument]$event.toxml()

            $Xml.event.eventdata.data | ForEach-Object -Begin { $Hash = @{} } -Process { $Hash[$_.name] = $_.'#text' } -End { [pscustomobject]$Hash } | ForEach-Object -Process {

                # Define the regex pattern
                [System.String]$Pattern = '\\Device\\HarddiskVolume(\d+)\\(.*)$'

                if ($_.'File Name' -match $Pattern) {
                    [System.Int64]$HardDiskVolumeNumber = $Matches[1]
                    [System.String]$RemainingPath = $Matches[2]
                    [PSCustomObject]$GetLetter = $DriveLettersGlobalRootFix | Where-Object -FilterScript { $_.devicepath -eq "\Device\HarddiskVolume$HardDiskVolumeNumber" }
                    [System.IO.FileInfo]$UsablePath = "$($GetLetter.DriveLetter)$RemainingPath"
                    $_.'File Name' = $_.'File Name' -replace $Pattern, $UsablePath
                }

                # Check if the file is currently on the disk
                if (Test-Path -Path $_.'File Name') {
                    $AuditEventLogsProcessingResults.AvailableFilesPaths += $_.'File Name'
                }

                # If the file is not currently on the disk, extract its hashes from event log
                else {
                    $AuditEventLogsProcessingResults.DeletedFileHashes += $_ | Select-Object -Property FileVersion, 'File Name', PolicyGUID, 'SHA256 Hash', 'SHA256 Flat Hash', 'SHA1 Hash', 'SHA1 Flat Hash'
                }
            }
        }
    }

    end {
        # return the results as an object
        return $AuditEventLogsProcessingResults
    }
}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Get-AuditEventLogsProcessing'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAZkeevuXYK9598
# mszlPQU2DgXNo/eecZkTRhJK4bv5R6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgmYC7H01Sxn7JF+rNCWzwySBXzvY+quZPkGftdAGs3CUwDQYJKoZIhvcNAQEB
# BQAEggIAR0MNyh2lmPujaQZLDbjN5WJantOAa3XwKLbRYUlsrks4oKTaQWHIs/Km
# DSJAAEBNmOdhjFOJYwSe4Gtji3SmH3cUgJgR+BwSfpAy+Croqwzuxm6ptCnzD4qs
# 03/EGZik38ouoYwKhv5cVjypDf0MIn0SF/qG830ASbptrzXoMbP0LrqiIFu6v4SK
# NXAIOaf+Ak3LCHOauxr9qTcwwYa+dQiaX6Qt38a5O7x0k/3h4jqrGZQqctMLw/i9
# /F26MmVpdX0mav0bqpI2oJGyrefLQL+18TwBAKzdv+CMsp8H4XfSbIx0e3MkmEpn
# 9wrWE6RLu7KMQrVZBBjVhWC1Ld2O6Hef977V+x0wI8dW2RH2oF6iDJ/BmMplGs6k
# FY5si0o/7oRwz5j3AA9bJY1I1TAIAikMkBWNgTXSdBRvuiLvsgEbzoXmeSIhLUSV
# CQQBlZZeWuFZG/kDYnHtyOXNpwqCigCsTHKTpkc7f3u3s65teT0yBWuYAUwRhy1m
# QmEJQxoKyyvgh4cMANj6yuOizDi3OfSMpxrrM/CdM6lbagZWR77/exmvqcF+zken
# I/VLKhaG5SL86cAYKAa0uJVaFjcyzF3ckIJ3lngtyKJkB7DLgvhtNRXlF25/nQGG
# ENEAnn0TWFQ4XgaHvPc0GESj7FOIRmrSsvvREZRmRckrGw4oq/A=
# SIG # End signature block
