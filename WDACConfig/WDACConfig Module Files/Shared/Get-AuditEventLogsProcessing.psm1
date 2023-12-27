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
# MIILhgYJKoZIhvcNAQcCoIILdzCCC3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAZkeevuXYK9598
# mszlPQU2DgXNo/eecZkTRhJK4bv5R6CCB88wggfLMIIFs6ADAgECAhNUAAAABzgp
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgmYC7H01Sxn7J
# F+rNCWzwySBXzvY+quZPkGftdAGs3CUwDQYJKoZIhvcNAQEBBQAEggIAp7MBJguC
# X4Wb9xUpCxqSYBVX+Cdbo8p9NshaT8qR+aCpBQL/w5p5kBtwUKudGmpBQII2D9It
# 6t4OhmKQyCEX8a7DrH4x6nvsZuzKuxkwL7lik78NTFhU6P8/7gR3bKhhsMpeNo2G
# e/0MISB5TKQNclZnFd4x6hUXUbCZmO9Wf9iMH/Fdc/6j0dtbD99U/ZkcW3lKtjbd
# JqezqLy5xOc4QKsbn2vwBm4iGf5VlcVVfuJ3tFe6KCuqkhdvhoKawfOmeTMdQCv+
# sHoQHqVa8inb2TRtLIGXL81qBA7BDUNBlAucpRFrZmVJa/XgqgE2ua91qlj3dQIa
# fiuDZQv17fv7pngGR9+iSw7onBDq1Qqvo+qHht1Lt9GXGRVQbQkOgb425DbOwx5x
# WLO8VuD8lJlwo4usP6EiwnHsQreaIqTA+48y+YJSWQB/sESgwCf4vBg0F5TIvwlw
# 69bgN4vOoGz4eJs/ripcj6wQPyW4sbBQGhaV8VZnijJV1R7AvJrA4wzxf3xniM3h
# RE2kdSyQwV3GJkQp9qmqQo/4wq46PvXu4g6kDBVHMkR7BhHEBNfHRJM+dDvCmOZs
# KCcbRg1zhAq1gsDe80m/HgWLmtBqyr4pIHsfQVKmWq0eR0KfQLwPJU2bb1w1xO4d
# XBP1a/LiurpPcAUoWDqIkR/Vk0PeJLSk92c=
# SIG # End signature block
