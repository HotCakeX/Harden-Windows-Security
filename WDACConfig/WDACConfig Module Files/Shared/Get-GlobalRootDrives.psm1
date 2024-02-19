Function Get-GlobalRootDrives {
    <#
    .SYNOPSIS
        A function that gets the DriveLetter mappings in the global root namespace
        And fixes these: \Device\Harddiskvolume
    .LINK
        https://superuser.com/questions/1058217/list-every-device-harddiskvolume
    .INPUTS
        None. You cannot pipe objects to this function.
    .OUTPUTS
        System.Object[]
    #>
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param ()
    # Importing the $PSDefaultParameterValues to the current session, prior to everything else
    . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

    # Import the kernel32.dll functions using P/Invoke if they don't exist
    if (-NOT ('WDACConfig.Win32Utils' -as [System.Type]) ) {
        Add-Type -Path "$ModuleRootPath\C#\Kernel32dll.cs"
    }

    # Initialize some variables for storing the volume names, paths, and mount points
    [System.UInt32]$lpcchReturnLength = 0
    [System.UInt32]$Max = 65535
    [System.Text.StringBuilder]$SbVolumeName = New-Object -TypeName System.Text.StringBuilder -ArgumentList ($Max, $Max)
    [System.Text.StringBuilder]$SbPathName = New-Object -TypeName System.Text.StringBuilder -ArgumentList ($Max, $Max)
    [System.Text.StringBuilder]$SbMountPoint = New-Object -TypeName System.Text.StringBuilder -ArgumentList ($Max, $Max)

    # Find the first volume in the system and get a handle to it
    [System.IntPtr]$VolumeHandle = [WDACConfig.Win32Utils]::FindFirstVolume($SbVolumeName, $Max)

    # Loop through all the volumes in the system
    do {
        # Get the volume name as a string
        [System.String]$Volume = $SbVolumeName.toString()
        # Get the mount point for the volume, if any
        [System.Boolean]$unused = [WDACConfig.Win32Utils]::GetVolumePathNamesForVolumeNameW($Volume, $SbMountPoint, $Max, [System.Management.Automation.PSReference]$lpcchReturnLength)
        # Get the device path for the volume, if any
        [System.UInt32]$ReturnLength = [WDACConfig.Win32Utils]::QueryDosDevice($Volume.Substring(4, $Volume.Length - 1 - 4), $SbPathName, [System.UInt32]$Max)

        # If the device path is found, create a custom object with the drive mapping information
        if ($ReturnLength) {
            [System.Collections.Hashtable]$DriveMapping = @{
                DriveLetter = $SbMountPoint.toString()
                VolumeName  = $Volume
                DevicePath  = $SbPathName.ToString()
            }
            # Write the custom object to the output stream
            Write-Output -InputObject (New-Object -TypeName PSObject -Property $DriveMapping)
        }
        else {
            # If no device path is found, write a message to the output stream
            Write-Output -InputObject 'No mountpoint found for: ' + $Volume
        }
        # Find the next volume in the system and repeat the loop
    } while ([WDACConfig.Win32Utils]::FindNextVolume([System.IntPtr]$VolumeHandle, $SbVolumeName, $Max))

}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Get-GlobalRootDrives'

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCsZLhPfuFuafao
# Cy3eCO5I05uYUQ1MLaC9l+ZmvHnnIKCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgBI6wkocU9PPziLyIRibs18HkFJKEoabhvtqax4mDZbwwDQYJKoZIhvcNAQEB
# BQAEggIAH87UuBGqthftVE12vx7vjd2qPo7CqWViQbSG/NIfDNlzeub6SeRkQXE7
# mZInuFiHE5LjpoQFGN6WqjDprvI0XzKKOkKyKapHoDdAQyX0YihL1P7LZaJzO5D0
# 1AQW0ij9euyCW4Sw/Q+13cardvfZupoIXISUATbQCss+QP4fQ6gZvdSmZ10NgoZA
# kbbTxmCSnW34wxEMh1tdS+ZGpcYffGKpWuCyY/VlENNjVuddZtFGfCRfcf4oQSqb
# Xi1yt2MWlasD14lfYy64xjcwUO3Wpki5QGt/PNUhOjY2J8UwjHzf1lfyUsp/3fif
# 7lJ1yx5A2W4CITYwsPy6Vdhf0V+jtZpUKpsF425QSMJib0hWhBq6fV3B+v6PzDIT
# niJsRJVa4nfsBzRb2xTPkZ3LXd7dkW9A+zR15BmUDXMcNOZEfwUM9DwpHEUOMohk
# slKHRey32pjGPoNhHxsQqPGp2pRT/Iufyaa3OOhzoBuKp5ktnS2hJOO+VWCVmRt+
# FKKXlvCq0mwh8K5GwvdDnDaZAKeFjLF8PThFrzgs1DB1MjN77FgW5HdhAl9bSxUu
# le1YTQHnFcElZB5e0gpXVZKAQqpPEBiwgC1mdKwKtnUHtVlbvxYP6VK+voivvYrh
# 4ClbHNOiN4TKwX73ERLm+6iIiYSua2z5fhfU/kbmJ+YpXIbIRnM=
# SIG # End signature block
