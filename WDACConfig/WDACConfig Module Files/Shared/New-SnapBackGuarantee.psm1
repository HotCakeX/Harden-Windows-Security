Function New-SnapBackGuarantee {
    <#
    .SYNOPSIS
        A function that arms the system with a snapback guarantee in case of a reboot during the base policy enforcement process.
        This will help prevent the system from being stuck in audit mode in case of a power outage or a reboot during the base policy enforcement process.
    .PARAMETER Path
        The directory path of the base policy file that will be enforced.
    .INPUTS
        System.IO.DirectoryInfo
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true)]
        [System.IO.DirectoryInfo]$Path
    )

    # Using CMD and Scheduled Task Method

    Write-Verbose -Message 'Creating the scheduled task for Snap Back Guarantee'

    # Creating the scheduled task action
    [Microsoft.Management.Infrastructure.CimInstance]$TaskAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c C:\EnforcedModeSnapBack.cmd'
    # Creating the scheduled task trigger
    [Microsoft.Management.Infrastructure.CimInstance]$TaskTrigger = New-ScheduledTaskTrigger -AtLogOn
    # Creating the scheduled task principal, will run the task under the system account using its well-known SID
    [Microsoft.Management.Infrastructure.CimInstance]$Principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -RunLevel Highest
    # Setting the task to run with the highest priority. This is to ensure that the task runs as soon as possible after the reboot. It runs even on logon screen before user logs on too.
    [Microsoft.Management.Infrastructure.CimInstance]$TaskSettings = New-ScheduledTaskSettingsSet -Hidden -Compatibility Win8 -DontStopIfGoingOnBatteries -Priority 0 -AllowStartIfOnBatteries
    # Register the scheduled task
    Register-ScheduledTask -TaskName 'EnforcedModeSnapBack' -Action $TaskAction -Trigger $TaskTrigger -Principal $Principal -Settings $TaskSettings -Force | Out-Null

    # Saving the EnforcedModeSnapBack.cmd file to the root of C drive
    # It contains the instructions to revert the base policy to enforced mode
    Set-Content -Force 'C:\EnforcedModeSnapBack.cmd' -Value @"
REM Deploying the Enforced Mode SnapBack CI Policy
CiTool --update-policy "$Path\EnforcedMode.cip" -json
REM Deleting the Scheduled task responsible for running this CMD file
schtasks /Delete /TN EnforcedModeSnapBack /F
REM Deleting the CI Policy file
del /f /q "$Path\EnforcedMode.cip"
REM Deleting this CMD file itself
del "%~f0"
"@

}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'New-SnapBackGuarantee'

# An alternative way to do this which is less reliable because RunOnce key can be deleted by 3rd party programs during installation etc.
<#
                # Using PowerShell and RunOnce Method

                # Defining the registry path for RunOnce key
                [System.String]$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
                # Defining the command that will be executed by the RunOnce key in case of a reboot
                [System.String]$Command = @"
CiTool --update-policy "$((Get-Location).Path)\EnforcedMode.cip" -json; Remove-Item -Path "$((Get-Location).Path)\EnforcedMode.cip" -Force
"@
                # Saving the command to a file that will be executed by the RunOnce key in case of a reboot
                $Command | Out-File -FilePath 'C:\EnforcedModeSnapBack.ps1' -Force
                # Saving the command that runs the EnforcedModeSnapBack.ps1 file in the next reboot to the RunOnce key
                New-ItemProperty -Path $RegistryPath -Name '*CIPolicySnapBack' -Value "powershell.exe -WindowStyle `"Hidden`" -ExecutionPolicy `"Bypass`" -Command `"& {&`"C:\EnforcedModeSnapBack.ps1`";Remove-Item -Path 'C:\EnforcedModeSnapBack.ps1' -Force}`"" -PropertyType String -Force | Out-Null
#>

# If the alternative way is used, this should be added to the Finally block under the:
# Enforced Mode Snapback removal after base policy has already been successfully re-enforced

<#
# For PowerShell Method
# Remove-Item -Path 'C:\EnforcedModeSnapBack.ps1' -Force
# Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Name '*CIPolicySnapBack' -Force
#>
# SIG # Begin signature block
# MIILhgYJKoZIhvcNAQcCoIILdzCCC3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCANm945iMpLXiWF
# zoC15NssHyExMKixDcfmFlU0fftXa6CCB88wggfLMIIFs6ADAgECAhNUAAAABzgp
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgVrJQk7Jk/T/V
# loc+tYvZLoCxRr6K3BjG5zeSmJupiycwDQYJKoZIhvcNAQEBBQAEggIAPGUo5wRy
# sU7DyNdSqDNhOUPwKpC4QFtPiLCYJI/Kl9YByceWXoYCmI8W8PNDDKAnYEtCrVvA
# MnpEJE8omxLxJHUlgfn3+h674ZEqHpjgEael/TKEk+C1ad6y50eCTLJBirMwVHJa
# hXKmEIkl7nnPCOlZANKDiDt+g+fhUBNlS6/05o8fObLI72ZmGgsrNoi5IjVwEYpo
# lxdKCQ9+iBSe/F22MHvatQqXCBBjm1Q6/RmFEJvRRFBMy9Fdn++ra5C8+1LhwraY
# y+7OGl0oD1lYGZSmmXGDyM6i1N8mE2mNVkbyyibeCcRZAmEhNrnlC0md2GABstit
# GGny4v+ucumvB+m2+Tbejt5CZ4N8+KlYv2mcR2nirfbl10QSuZPGsiKsNKlIUGYB
# 3cM9gqFgTnW4/FUMXuE9jBCPvRfYsGjvm9xxzcJqjxpnkyRrfK4aLrpHmUN3O5Mu
# IVimzaale77ixxBiswy8WaOH4CkIQuQIyVZbbh7xHv4qpIVJPQ/7ERZ0FP7B4ZWc
# Wo3386zMJvfJ6hMQf0qJqWtwA5vwUeFt2lOzUZqz5L0OLBFA0LBN4kxpxK6Z7nNb
# CvARBzT+itV56JU0Z+/4vG0r7gy9bDtzSu/pmMig90VzDYXsR+oB0ey+TSxZ2OlF
# djQ6/Jlj0jJgP+cYOPKFCoXPFEPy6tpb8M0=
# SIG # End signature block
