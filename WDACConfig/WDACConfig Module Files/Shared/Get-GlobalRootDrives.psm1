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
        System.Objects[]
    #>
    [CmdletBinding()]
    param ()
    # Importing the $PSDefaultParameterValues to the current session, prior to everything else
    . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

    # Import the kernel32.dll functions using P/Invoke
    [System.String]$Signature = @'
[DllImport("kernel32.dll", SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool GetVolumePathNamesForVolumeNameW([MarshalAs(UnmanagedType.LPWStr)] string lpszVolumeName,
[MarshalAs(UnmanagedType.LPWStr)] [Out] StringBuilder lpszVolumeNamePaths, uint cchBuferLength,
ref UInt32 lpcchReturnLength);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr FindFirstVolume([Out] StringBuilder lpszVolumeName,
uint cchBufferLength);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool FindNextVolume(IntPtr hFindVolume, [Out] StringBuilder lpszVolumeName, uint cchBufferLength);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

'@
    # Add the signature to the current session as a new type
    Add-Type -ErrorAction SilentlyContinue -Language CSharp -MemberDefinition $Signature -Name 'Win32Utils' -Namespace 'PInvoke' -Using PInvoke, System.Text

    # Initialize some variables for storing the volume names, paths, and mount points
    [System.UInt32]$lpcchReturnLength = 0
    [System.UInt32]$Max = 65535
    [System.Text.StringBuilder]$SbVolumeName = New-Object -TypeName System.Text.StringBuilder($Max, $Max)
    [System.Text.StringBuilder]$SbPathName = New-Object -TypeName System.Text.StringBuilder($Max, $Max)
    [System.Text.StringBuilder]$SbMountPoint = New-Object -TypeName System.Text.StringBuilder($Max, $Max)

    # Find the first volume in the system and get a handle to it
    [System.IntPtr]$VolumeHandle = [PInvoke.Win32Utils]::FindFirstVolume($SbVolumeName, $Max)

    # Loop through all the volumes in the system
    do {
        # Get the volume name as a string
        [System.String]$Volume = $SbVolumeName.toString()
        # Get the mount point for the volume, if any
        [System.Boolean]$unused = [PInvoke.Win32Utils]::GetVolumePathNamesForVolumeNameW($Volume, $SbMountPoint, $Max, [System.Management.Automation.PSReference]$lpcchReturnLength)
        # Get the device path for the volume, if any
        [System.UInt32]$ReturnLength = [PInvoke.Win32Utils]::QueryDosDevice($Volume.Substring(4, $Volume.Length - 1 - 4), $SbPathName, [System.UInt32]$Max)

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
    } while ([PInvoke.Win32Utils]::FindNextVolume([System.IntPtr]$VolumeHandle, $SbVolumeName, $Max))

}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Get-GlobalRootDrives'

# SIG # Begin signature block
# MIILhgYJKoZIhvcNAQcCoIILdzCCC3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBhKOTbUX+aXzbG
# hWj1JIG/78XwTpDsFEovIkl/Y3eyiaCCB88wggfLMIIFs6ADAgECAhNUAAAABzgp
# /t9ITGbLAAAAAAAHMA0GCSqGSIb3DQEBDQUAMEQxEzARBgoJkiaJk/IsZAEZFgNj
# b20xFDASBgoJkiaJk/IsZAEZFgRCaW5nMRcwFQYDVQQDEw5CaW5nLVNFUlZFUi1D
# QTAgFw0yMzEyMjcwODI4MDlaGA8yMTMzMTIyNzA4MzgwOVoweDELMAkGA1UEBhMC
# VUsxFjAUBgNVBAoTDVNweU5ldEdpcmwgQ28xKjAoBgNVBAMTIUhvdENha2VYIENv
# ZGUgU2lnbmluZyBDZXJ0aWZpY2F0ZTElMCMGCSqGSIb3DQEJARYWU3B5bmV0Z2ly
# bEBvdXRsb29rLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANsD
# szHV9Ea21AhOw4a35P1R30HHtmz+DlWKk/a4FvYQivl9dd+f+SZaybl0O96H6YNp
# qLnx7KD9TSEBbB+HxjE39GfWoX2R1VlPaDqkbGMA0XmnUB+/5CsbhktY4gbvJpW5
# LWXk0xUmCSvLMs7eiuBOGNs3zw5xVVNhsES6/aYMCWREI9YPTVbh7En6P4uZOisy
# K2tZtkSe/TXabfr1KtNhELr3DpTNtJBMBLzhz8d6ztJExKebFqpiaNqF7TpTOTRI
# 4P02k6u6lsWMz/rH9mMHdGSyBJ3DEyJGL9QT4jO4BFLHsxHuWTpjxnqxZNjwLTjB
# NEhH+VcKIIy2iWHfWwK2Nwr/3hzDbfqsWrMrXvvCqGpei+aZTxyplbMPpmd5myKo
# qLI58zc7cMi/HuAbbjo1YWxd/J1shHifMfhXfuncjHr7RTGC3BaEzwirQ12t1Z2K
# Zn2AhLnhSElbgZppt+WS4bmzT6L693srDxSMcBpRcu8NyDteLVCmgfBGXDdfAKEZ
# KXPi9liV0b66YQWnBp9/3bYwtYTh5VwjfSVAMfWsrMpIeGmvGUcsnQCqCxCulHKX
# onoYmbyotyOiXObXVgzB2G0k+VjxiFTSb1ENf3GJV1FJbzbch/p/tASY9w2L7kT/
# l+/Nnp4XOuPDYhm/0KWgEH7mUyq4KkP/BG/on7Q5AgMBAAGjggJ+MIICejA8Bgkr
# BgEEAYI3FQcELzAtBiUrBgEEAYI3FQjinCqC5rhWgdmZEIP42AqB4MldgT6G3Kk+
# mJFMAgFkAgEOMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDAM
# BgNVHRMBAf8EAjAAMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYBBQUHAwMwHQYDVR0O
# BBYEFFr7G/HfmP3Om/RStyhaEtEFmSYKMB8GA1UdEQQYMBaBFEhvdGNha2V4QG91
# dGxvb2suY29tMB8GA1UdIwQYMBaAFChQ2b1sdIHklqMDHsFKcUCX6YREMIHIBgNV
# HR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPUJpbmctU0VSVkVSLUNBLENO
# PVNlcnZlcixDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2Vy
# dmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1CaW5nLERDPWNvbT9jZXJ0aWZpY2F0
# ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9u
# UG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaBnWxkYXA6Ly8v
# Q049QmluZy1TRVJWRVItQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZp
# Y2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9QmluZyxEQz1jb20/
# Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRo
# b3JpdHkwDQYJKoZIhvcNAQENBQADggIBAE/AISQevRj/RFQdRbaA0Ffk3Ywg4Zui
# +OVuCHrswpja/4twBwz4M58aqBSoR/r9GZo69latO74VMmki83TX+Pzso3cG5vPD
# +NLxwAQUo9b81T08ZYYpdWKv7f+9Des4WbBaW9AGmX+jJn+JLAFp+8V+nBkN2rS9
# 47seK4lwtfs+rVMGBxquc786fXBAMRdk/+t8G58MZixX8MRggHhVeGc5ecCRTDhg
# nN68MhJjpwqsu0sY2NeKz5gMSk6wvt+NDPcfSZyNo1uSEMKTl/w5UH7mnrv0D4fZ
# UOY3cpIwbIagwdBuFupKG/m1I2LXZdLgGfOtZyZyw+c5Kd0KlMxonBiVoqN7PvoA
# 7sfwDI7PMLMQ3mseFbIpSUQGXHGeyouN1jF5ciySfHnW1goiG8tfDKNAT7WEz+ZT
# c1iIH+lCDUV/LmFD1Bvj2A9Q01C9BsScH+9vb2CnIwaSmfFRI6PY9cKOEHdy/ULi
# hp72QBd6W6ZQMZWXI5m48DdiKlQGA1aCdNN6+C0of43a7L0rAtLPYKySpd6gc34I
# h7/DgGLqXg0CO4KtbGdEWfKHqvh0qYLRmo/obhyVMYib4ceKrCcdc9aVlng/25nE
# ExvokF0vVXKSZkRUAfNHmmfP3lqbjABHC2slbStolocXwh8CoN8o2iOEMnY/xez0
# gxGYBY5UvhGKMYIDDTCCAwkCAQEwWzBEMRMwEQYKCZImiZPyLGQBGRYDY29tMRQw
# EgYKCZImiZPyLGQBGRYEQmluZzEXMBUGA1UEAxMOQmluZy1TRVJWRVItQ0ECE1QA
# AAAHOCn+30hMZssAAAAAAAcwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIB
# DDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEE
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg1nCz/i3Murcm
# +kjQ9rnuWqDh9opDTUsOI0tLy/FPlqMwDQYJKoZIhvcNAQEBBQAEggIAORJwFU2M
# O17N6MjDo4sV0FqQvf7YuD8x/qDJk1ts315a7Jotsijf2NYb4u0ED9vJomCaPatt
# xxZSQTwvUhmh8KngwqOcTBPZSpyyDe9HIj8WMi/YfHmJ3anxT5cYcDZLqrrPmHa+
# hlPkg0cEsqyj0lJbhE3jRgxodh2ws1UHRBfxBY7H+as/mcjq6R7HDjG1XXChJs8A
# cGh+8nBvtJB2X7/uqkPCzAC/1RfbQHrBbm2NO1yjEg2hR7j2ORoVmFgZkrfIb4Bx
# D1yxEvxnRlWbtAihoOHfaOrwvOEEdAz8seUA0+XrR3qhsdyziKNPonZeJVca6kMO
# dN+4OUwI+O5DxnkZYNzgUj7bQanYQxMZ+jDRp14yvrlN1F4KfNIzPstj3+u3B62C
# VWiEr34zU7paeRyaVppAc/emJtvLIsFWDQJbDSvKddhUDQCMQrsx9doqsh4VB7x4
# vbSdF3Zjtk7FkHn3LfnGUjN1UsLed0Y5hX6c7E3ldCWzweL94a7tJxJVRrx1kYFK
# gmZe16Rd53YHzzLHZYBIK72T2mukC2ylr3ka5xRg5Vyt/EkmaajLJeus8QpIXnGF
# NlwHhi8WWG/q4jOWPLkYRWdoIc9ApM24rGO6CqPXyEVIh043OQ08QuBTY3ytTmVi
# M9W0LgspESA4dixMSiFkH6SkHrCTA4iI9P8=
# SIG # End signature block
