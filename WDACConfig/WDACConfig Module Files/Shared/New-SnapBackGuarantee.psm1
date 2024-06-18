Function New-SnapBackGuarantee {
    <#
    .SYNOPSIS
        A function that arms the system with a snapback guarantee in case of a reboot during the base policy enforcement process.
        This will help prevent the system from being stuck in audit mode in case of a power outage or a reboot during the base policy enforcement process.
    .PARAMETER Path
        The path to the EnforcedMode.cip file that will be used to revert the base policy to enforced mode in case of a reboot.
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    Param(
        [parameter(Mandatory = $true)]
        [System.IO.FileInfo]$Path
    )

    # Using CMD and Scheduled Task Method

    Write-Verbose -Message 'Creating the scheduled task for Snap Back Guarantee'

    # Creating the scheduled task action
    [Microsoft.Management.Infrastructure.CimInstance]$TaskAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c `"$UserConfigDir\EnforcedModeSnapBack.cmd`""
    # Creating the scheduled task trigger
    [Microsoft.Management.Infrastructure.CimInstance]$TaskTrigger = New-ScheduledTaskTrigger -AtLogOn
    # Creating the scheduled task principal, will run the task under the system account using its well-known SID
    [Microsoft.Management.Infrastructure.CimInstance]$Principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -RunLevel Highest
    # Setting the task to run with the highest priority. This is to ensure that the task runs as soon as possible after the reboot. It runs even on logon screen before user logs on too.
    [Microsoft.Management.Infrastructure.CimInstance]$TaskSettings = New-ScheduledTaskSettingsSet -Hidden -Compatibility Win8 -DontStopIfGoingOnBatteries -Priority 0 -AllowStartIfOnBatteries
    # Register the scheduled task
    $null = Register-ScheduledTask -TaskName 'EnforcedModeSnapBack' -Action $TaskAction -Trigger $TaskTrigger -Principal $Principal -Settings $TaskSettings -Force

    # Saving the EnforcedModeSnapBack.cmd file to the UserConfig directory in Program Files
    # It contains the instructions to revert the base policy to enforced mode
    Set-Content -Force -LiteralPath (Join-Path -Path $UserConfigDir 'EnforcedModeSnapBack.cmd') -Value @"
REM Deploying the Enforced Mode SnapBack CI Policy
CiTool --update-policy "$Path" -json
REM Deleting the Scheduled task responsible for running this CMD file
schtasks /Delete /TN EnforcedModeSnapBack /F
REM Deleting the CI Policy file
del /f /q "$Path"
REM Deleting this CMD file itself
del "%~f0"
"@

}
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
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB5a/araSn3OQ2S
# 0Ae5gTuaDQr/Xu8QIQCE45YD+erNQaCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQg4EQQiEsaoR63vxiuaprHgwze3OrU9X3H8WELiRHJInowDQYJKoZIhvcNAQEB
# BQAEggIAMmHKVwXwKU9316MybuK6OCMb8Yn9cRxuFNkbXzXpilc4DmlJwjdaKFAA
# Ce4Hz98hd8LhA1YYH6OOqZqSGFRBowD8FdMOKUaK9LJ88Rt6pdxIPel8fNxJiMU3
# nn+Qj++Ck3MOdXCGiiQZGYW2Mw2033XodPCVnMn5Ex3tNm3QSoeqbc3CuPkniqVD
# tJ4hreEF6DPaGwHIpp5dOqhm3NrI9ekRqXNzkA/wdQ3OMcidYMpL4C5aZkUXF2S1
# Rkc5edK60CzW1O8cDVD+0nzadjxWDOi6gaOgFK1t5sUMpTGuHZBMMCsNDwXtJq2H
# 2Z2RYaZsErkZOgqu/WG+v8Q3YAR222H6vbvJ8xmg326YcMg9XWDlDziOOtGTLkvq
# tIcYubA3qfQvHwISNNv0uiawdiTxzy+bKFZCrlS8Zvd/THVgprNxcQ5lQyDM5cmW
# RPIypGaDXEWIO/CIt2fRNDS9IKXgbVaLa+1ggAcjYAd1KXd5ZEj3bKsfKw0c5mI2
# n1GioroYpiPk25USj6cuqxix0Z2MD/pyJOxxB/GHTYZu25CO1jfuIQBkT2dvPwXC
# luj9zdX8/IH5qpD3ii/Hr5YTB7JXFmkyoCK5m4V+IBR5szumAdphrq7r6nyArXHt
# 0a+WoAMfRyJT6TlRZzRgH36tNwD8VJSiuADuezMfX9BRAsqafb8=
# SIG # End signature block
