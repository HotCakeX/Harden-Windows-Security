Function Get-KernelModeDriversAudit {
    <#
    .DESCRIPTION
        This function will scan the Code Integrity event logs for kernel mode drivers that have been loaded since the audit mode policy has been deployed
        and will return a folder containing symbolic links to the driver files.
        It does this by:
            1. Scanning the Code Integrity event logs for kernel mode drivers that have been loaded since the audit mode policy has been deployed
            2. Converting each event to XML
            3. Converting the XML to a PowerShell object
            4. Replacing the global root file paths with the drive letters to create consumable paths
            5. Removing duplicates based on SHA256 hash
            6. Saving the file paths to a variable
            7. Filtering based on files that exist with .sys and .dll extensions
            8. Removing duplicates based on file path
            9. Creating a temporary folder to store the symbolic links to the driver files
            10. Creating symbolic links to the driver files
            11. Returning the folder containing the symbolic links to driver files
    .INPUTS
        None
    .OUTPUTS
        System.IO.DirectoryInfo
    #>
    [CmdletBinding()]
    param()

    begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Importing the required sub-modules
        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-GlobalRootDrives.psm1" -Force

        # Get the local disks mappings
        [System.Object[]]$DriveLettersGlobalRootFix = Get-GlobalRootDrives

        [System.IO.FileInfo[]]$KernelModeDriversPaths = @()
        [System.Object[]]$RawData = @()

        [System.DateTime]$ScanStartDate = Get-CommonWDACConfig -StrictKernelModePolicyTimeOfDeployment
    }

    process {
        # Event Viewer Code Integrity logs scan for Audit logs based on the input date
        foreach ($Event in Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; ID = 3076 } -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_.TimeCreated -ge $ScanStartDate } ) {

            # Convert the event to XML
            $Xml = [System.Xml.XmlDocument]$Event.toxml()

            # Convert the XML to a PowerShell object
            $Xml.event.eventdata.data | ForEach-Object -Begin { $Hash = @{} } -Process { $Hash[$_.name] = $_.'#text' } -End { [pscustomobject]$Hash } | ForEach-Object -Process {

                # Define the regex pattern
                [System.String]$Pattern = '\\Device\\HarddiskVolume(\d+)\\(.*)$'

                # Replace the global root file paths with the drive letters to create consumable paths
                if ($_.'File Name' -match $Pattern) {
                    [System.Int64]$HardDiskVolumeNumber = $Matches[1]
                    [System.String]$RemainingPath = $Matches[2]
                    [PSCustomObject]$GetLetter = $DriveLettersGlobalRootFix | Where-Object -FilterScript { $_.devicepath -eq "\Device\HarddiskVolume$HardDiskVolumeNumber" }
                    [System.IO.FileInfo]$UsablePath = "$($GetLetter.DriveLetter)$RemainingPath"
                    $_.'File Name' = $_.'File Name' -replace $Pattern, $UsablePath
                }
                # Add the processed object to the array of raw data
                $RawData += $_
            }
        }

        Write-Debug -Message "RawData count without processing: $($RawData.count)"

        Write-Verbose -Message 'Removing duplicates based on SHA256 hash'
        $RawData = $RawData | Group-Object -Property 'SHA256 Hash' | ForEach-Object -Process { $_.Group[0] }

        Write-Debug -Message "RawData count after deduplication based on SHA256 hash: $($RawData.count)"

        Write-Verbose -Message 'Saving the file paths to a variable'
        [System.IO.FileInfo[]]$KernelModeDriversPaths = $RawData.'File Name'

        Write-Verbose -Message 'Filtering based on files that exist with .sys and .dll extensions'
        $KernelModeDriversPaths = $KernelModeDriversPaths | Where-Object -FilterScript { ($_.Extension -in ('.sys', '.dll')) -and ($_.Exists) }

        Write-Debug -Message "KernelModeDriversPaths count after filtering based on files that exist with .sys extension: $($KernelModeDriversPaths.count)"

        Write-Verbose -Message 'Removing duplicates based on file path'
        $KernelModeDriversPaths = $KernelModeDriversPaths | Group-Object -Property 'FullName' | ForEach-Object -Process { $_.Group[0] }

        Write-Debug -Message "KernelModeDriversPaths count after deduplication based on file path: $($KernelModeDriversPaths.count)"

        Write-Verbose -Message 'Creating a temporary folder to store the symbolic links to the driver files'
        [System.IO.DirectoryInfo]$SymLinksStorage = New-Item -Path ($UserTempDirectoryPath + 'SymLinkStorage' + $(New-Guid)) -ItemType Directory -Force

        Write-Verbose -Message 'Creating symbolic links to the driver files'
        Foreach ($File in $KernelModeDriversPaths) {
            New-Item -ItemType SymbolicLink -Path "$SymLinksStorage\$($File.Name)" -Target $File.FullName | Out-Null
        }
    }
    end {
        Write-Verbose -Message 'Returning the folder containing the symbolic links to driver files'
        return [System.IO.DirectoryInfo]$SymLinksStorage
    }
}
Export-ModuleMember -Function 'Get-KernelModeDriversAudit'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD/0FXBh+t97OM7
# 4JGmyi5Xjz08jvSf+ZU1KQ6zRKHu36CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgjmoZoj2rrsuS7Wph5ct7wINVQpO4pan/azq0IuB5tEQwDQYJKoZIhvcNAQEB
# BQAEggIAiOJId3cYQnZ58sNiiSLXtHHYy7xNzfLkZBl93p9djIJRwcUDw4ox21dN
# OI+eIEVYUNUruTdNb4NDLnZWVWvmOjTCfGjGOwOtqFoJbaHPQLotIXTvyxG/yen+
# r/MklNsNBXmr8ecn3q41RzmdHMZneiDAGB3PdIua9SvvZvAT095FORyITBYWis9t
# Eu5u9xmeccmZYAPCWq+9w7NnRXclFntyq5U4HwfuS4XTwIml+iP6ZRAzVKOjP8Ny
# tekdJtPd1duP51buEKS4Bq9/EvDMOOYyYY/vPUqOr2eHN4egOFOYmUDWQ/ezo7yT
# h2tRDD9+xX71b2u6dLllT0pxrIVkn6Lbbw+mdB1PR7iXrg+WqnvK1MYXvjAdSxX9
# sEGyRbDpAoliVdslUDJsQUyj8eIFQeKbgrztOruiMBJk47qGZ4UcISQ2QKwES7vL
# /61/3yw1N7UcEFFSsG5diD7DvGcV65mlio56Q9jXrYm2L5IkqnY/8qlP1N4WDJJk
# AV0UCZncuMIGvv5am6VuLN73Bcv1zOTBleh/7zEosNkcyimxN1xpl9eFakOEtnE2
# xNADstsNev/ONrgI4JNHkCkHbwubFmWvecmxCKAqzjaVZKaxNKqQO81y1FyywvuF
# iHccsKYcpih/ysfasQTQyRfN188I2p2rSlHEDtCQY6O64ke1B7I=
# SIG # End signature block
