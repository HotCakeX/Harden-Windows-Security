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
    [OutputType([PSCustomObject])]
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB9Z/aiTxr039lL
# GEzuqMBlT8DUQG3IfNGtcpLZ770XGKCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgvbup/h8tRBceZg2jgRCJH8c7gy5CmNRcQovWQi59ho0wDQYJKoZIhvcNAQEB
# BQAEggIAVPgaU58fHl3ejmsB5hOuzgwrq5HHDXqD1l6KfNPiCpzuqPJLbSO+2BYc
# phAbkEFKtOWjuEisgo6EqbltrxX6rks1QZJLpnJfhwIH5FfXNp0hxFs/ihLZ2HtC
# DFVw6TVFYabY5D5r9CNMdBVMOiJv5VZBkYZinFV0dHdIPJWXtcMQYeowid4qFjpM
# emNwI4FfgggyYnW0wmRYmGlhPzo4xSqK1kimPY5f2Q8uey5VF+82rHCdsF4uWNC0
# vz+iFoZoEsh980r+FcGOHbG+p1COrAsREegtzq8Cw658CzQSURUfa5ow/6Fmpixc
# 1HUylZVQKYWXxwkjQmzKtxCRTx7loPEytWRUwgjA8lfILk89nvhJGoF9nYBgEPXt
# dPFJmf9AKDNpMowaaT75VKEq1CrXK2wubY4OYEdv+5aQmJ8pgl214U9mSZc976jG
# 53VP+h0Yoxd7S/K65YftNGpmOCDFzllLzEp6qzPVmS1N+ebUrpTsrsLm/3HgYp1F
# MLoacvvMmiAwH8vgC69IP7NU/YtBKGdiV1dp72Ow7J5v/t87iRO8XceBkj/kbL+5
# nThcdKVu6LH+a8vhkUUDnOyKq2LBEsyT7xLQSQ3bl8j5HnyGACwSVl0Q6jGGaSNb
# u8n276dgv9dB8lQ3hpeSW65+LABO2rWU0hZDDP6JzHqh3qmmH5M=
# SIG # End signature block
