Function Get-SignTool {
    <#
    .SYNOPSIS
        Gets the path to SignTool.exe and verifies it to make sure it's not tampered
    .PARAMETER SignToolExePath
        Path to the SignTool.exe
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $false)][System.String]$SignToolExePath
    )
    # Importing the $PSDefaultParameterValues to the current session, prior to everything else
    . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

    # If Sign tool path wasn't provided by parameter, try to detect it automatically, if fails, stop the operation
    if (!$SignToolExePath) {
        if ($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64') {
            if ( Test-Path -Path 'C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe') {
                $SignToolExePath = 'C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe'
            }
            else {
                Throw [System.IO.FileNotFoundException] 'signtool.exe could not be found'
            }
        }
        elseif ($Env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
            if (Test-Path -Path 'C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe') {
                $SignToolExePath = 'C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe'
            }
            else {
                Throw [System.IO.FileNotFoundException] 'signtool.exe could not be found'
            }
        }
    }
    try {
        # Validate the SignTool executable
        # Setting the minimum version of SignTool that is allowed to be executed
        [System.Version]$WindowsSdkVersion = '10.0.22621.2428'
        [System.Boolean]$GreenFlag1 = (((Get-Item -Path $SignToolExePath).VersionInfo).ProductVersionRaw -ge $WindowsSdkVersion)
        [System.Boolean]$GreenFlag2 = (((Get-Item -Path $SignToolExePath).VersionInfo).FileVersionRaw -ge $WindowsSdkVersion)
        [System.Boolean]$GreenFlag3 = ((Get-Item -Path $SignToolExePath).VersionInfo).CompanyName -eq 'Microsoft Corporation'
        [System.Boolean]$GreenFlag4 = ((Get-AuthenticodeSignature -FilePath $SignToolExePath).Status -eq 'Valid')
        [System.Boolean]$GreenFlag5 = ((Get-AuthenticodeSignature -FilePath $SignToolExePath).StatusMessage -eq 'Signature verified.')
    }
    catch {
        Throw [System.Security.VerificationException] 'SignTool executable could not be verified.'
    }
    # If any of the 5 checks above fails, the operation stops
    if (!$GreenFlag1 -or !$GreenFlag2 -or !$GreenFlag3 -or !$GreenFlag4 -or !$GreenFlag5) {
        Throw [System.Security.VerificationException] 'The SignTool executable was found but could not be verified. Please download the latest Windows SDK to get the newest SignTool executable. Official download link: http://aka.ms/WinSDK'
    }
    else {
        return $SignToolExePath
    }
}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Get-SignTool'

# SIG # Begin signature block
# MIILhgYJKoZIhvcNAQcCoIILdzCCC3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBzSkVXcvwqvn6/
# WIH+y7ZylDo+phFjzp4oGak+7y2N8KCCB88wggfLMIIFs6ADAgECAhNUAAAABzgp
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgHtBa/Wv98yQA
# p8zhiap4AyK5+xVZA/jMy7ti59jNgU0wDQYJKoZIhvcNAQEBBQAEggIAiUd8JSNY
# QbPvd7nK4p8gUWElKfBIUfHCvsy3gnMg45oe/1SG7uPs+GiSmrYdREFFUEeeQJf+
# FMzxyHaDQEHlZfMTlusUuYCyJEBtaLuEYHj/f0tOC4mo4BFJ8UNFyyoMPgi/fl1b
# lXcDVQZkrYdcx9ljE60t8GZ64eYg0TElfjCW58b0asmp0vSbBDjWWY3vL0USeZj4
# tdNflbEWoUhN5459D2wjhRjzjDWDFRmIYXwCSPyykBDbYemNsBVOHYvd5I1ULr/Q
# utsefqpiPACHVYeSfa6BNjS/3YaUxYAM0vaamjOpN85I1/+gQpcXW0TxoHjmqnoi
# 7fgMIhzatcwcV0A2I3hNBQ37zTfAzSmk1Hu5hYY70Oye2luFW0g54SSjnMUI4h47
# wFNJ4xwVOF8+FRAv93sUDA6Gt8J8CstjKxBf2QEOEMuIkznSJQ+S9HkXWlMXGbys
# r052g9rgvgUAxoKMnKcyYUNcBNQJQl5pL63WMcWzyGdk7gfyNjhXIjJKWH4fxPa6
# xurmo9nTgw5ufWmcRfkcAVaKlGlthbphfNZv7anxC/XUTw6e4+H2QF4szBZa0l1Y
# NFsxsInNOa5KEbdnaFV/1FsAO/WaeVD2iDxv3pbp5EAXPelM1FYzD2Wo1DA6/zBw
# l9I9dtvOVLdsWBHAzj+u/KLaPGSQVyVLmmc=
# SIG # End signature block
