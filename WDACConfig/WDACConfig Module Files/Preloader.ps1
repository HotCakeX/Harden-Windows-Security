# Stopping the module process if any error occurs
$global:ErrorActionPreference = 'Stop'

if (!$IsWindows) {
    Throw [System.PlatformNotSupportedException] 'The WDACConfig module only runs on Windows operation systems.'
}

# Specifies that the WDACConfig module requires Administrator privileges
#Requires -RunAsAdministrator

function Set-ConstantVariable {
    <#
    .SYNOPSIS
        Performs precise check to ensure that a global variable is not already pre-defined with a potentially malicious value.
        Even a single space change in the value of the variable will be detected.
    #>
    param (
        [System.String]$Name,
        $Value,
        [System.String]$Description,
        [System.String]$Option,
        [System.String]$Scope
    )
    if ((Test-Path -Path "Variable:\$Name") -eq $true) {
        $ExistingValue = [System.String]$(Get-Variable -Name $Name -Scope Global -ValueOnly)
        if ($ExistingValue -ne $Value) {
            throw "Variable '$Name' already exists with a different value: ($ExistingValue). For security reasons, cannot continue the operation. Please close and reopen the PowerShell session and try again."
        }
    }
    else {
        try {
            New-Variable -Name $Name -Value $Value -Option $Option -Scope $Scope -Description $Description -Force
        }
        catch {
            Throw [System.InvalidOperationException] "Could not set the required global variable: $Name"
        }
    }
}

# Create tamper resistant global/script variables (if they don't already exist) - They are automatically imported in the caller's environment
Set-ConstantVariable -Name 'MSFTRecommendedBlockRulesURL' -Value 'https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac.md' -Option 'Constant' -Scope 'Global' -Description 'User Mode block rules'
Set-ConstantVariable -Name 'MSFTRecommendedDriverBlockRulesURL' -Value 'https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md' -Option 'Constant' -Scope 'Global' -Description 'Kernel Mode block rules'
# Set-ConstantVariable -Name 'UserAccountDirectoryPath' -Value ((Get-CimInstance Win32_UserProfile -Filter "SID = '$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)'").LocalPath) -Option 'Constant' -Scope 'Script' -Description 'Securely retrieved User profile directory'
Set-ConstantVariable -Name 'Requiredbuild' -Value '22621.3447' -Option 'Constant' -Scope 'Script' -Description 'Minimum required OS build number'
Set-ConstantVariable -Name 'OSBuild' -Value ([System.Environment]::OSVersion.Version.Build) -Option 'Constant' -Scope 'Script' -Description 'Current OS build version'
Set-ConstantVariable -Name 'UBR' -Value (Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR') -Option 'Constant' -Scope 'Script' -Description 'Update Build Revision (UBR) number'
Set-ConstantVariable -Name 'FullOSBuild' -Value "$OSBuild.$UBR" -Option 'Constant' -Scope 'Script' -Description 'Create full OS build number as seen in Windows Settings'
Set-ConstantVariable -Name 'ModuleRootPath' -Value ($PSScriptRoot) -Option 'Constant' -Scope 'Global' -Description 'Storing the value of $PSScriptRoot in a global constant variable to allow the internal functions to use it when navigating the module structure'
Set-ConstantVariable -Name 'CISchemaPath' -Value "$Env:SystemDrive\Windows\schemas\CodeIntegrity\cipolicy.xsd" -Option 'Constant' -Scope 'Global' -Description 'Storing the path to the WDAC Code Integrity Schema XSD file'
Set-ConstantVariable -Name 'UserConfigDir' -Value "$Env:ProgramFiles\WDACConfig" -Option 'Constant' -Scope 'Global' -Description 'Storing the path to the WDACConfig folder in the Program Files'
Set-ConstantVariable -Name 'UserConfigJson' -Value "$UserConfigDir\UserConfigurations\UserConfigurations.json" -Option 'Constant' -Scope 'Global' -Description 'Storing the path to User Config JSON file in the WDACConfig folder in the Program Files'

Set-ConstantVariable -Name 'FindWDACCompliantFiles' -Value $([System.Management.Automation.ScriptBlock]::Create({
            Param ($Paths)
            [System.String[]]$Extensions = @('*.sys', '*.exe', '*.com', '*.dll', '*.rll', '*.ocx', '*.msp', '*.mst', '*.msi', '*.js', '*.vbs', '*.ps1', '*.appx', '*.bin', '*.bat', '*.hxs', '*.mui', '*.lex', '*.mof')
            $Output = Get-ChildItem -Recurse -File -LiteralPath $Paths -Include $Extensions -Force
            Return $Output
        })) -Option 'Constant' -Scope 'Global' -Description 'Scriptblock that gets the WDAC Compliant files from a list of directories'

Set-ConstantVariable -Name 'WriteFinalOutput' -Value $([System.Management.Automation.ScriptBlock]::Create({
            Param ([System.IO.FileInfo[]]$Paths)
            Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force
            foreach ($Path in $Paths) {
                Write-ColorfulText -Color Lavender -InputText "The file '$($Path.Name)' has been saved in '$UserConfigDir'"
            }
        })) -Option 'Constant' -Scope 'Global' -Description 'Scriptblock that writes the final output of some cmdlets'

Set-ConstantVariable -Name 'CalculateCIPolicyVersion' -Value $([System.Management.Automation.ScriptBlock]::Create({
            Param ([System.String]$Number)

            Try {
                # Convert the string to a 64-bit integer
                $Number = [System.UInt64]::Parse($Number)

                # Extract the version parts by splitting the 64-bit integer into four 16-bit segments and convert each segment to its respective part of the version number
                [System.UInt16]$Part1 = ($Number -band '0xFFFF000000000000') -shr '48' # mask isolates the highest 16 bits of a 64-bit number.
                [System.UInt16]$Part2 = ($Number -band '0x0000FFFF00000000') -shr '32' # mask isolates the next 16 bits.
                [System.UInt16]$Part3 = ($Number -band '0x00000000FFFF0000') -shr '16' # mask isolates the third set of 16 bits.
                [System.UInt16]$Part4 = $Number -band '0x000000000000FFFF' # mask isolates the lowest 16 bits.

                # Form the version string
                [System.Version]$version = "$Part1.$Part2.$Part3.$Part4"
                Return $version
            }
            catch {
                Return $Number
            }

        })) -Option 'Constant' -Scope 'Global' -Description 'Scriptblock that converts a 64-bit unsigned integer into version type, used for converting the numbers from CiTool.exe output to proper versions'

Set-ConstantVariable -Name 'IncrementVersion' -Value $([System.Management.Automation.ScriptBlock]::Create({
            param (
                [System.Version]$Version
            )

            if ($Version.Revision -lt [System.Int32]::MaxValue) {
                $NewVersion = [System.Version]::new($Version.Major, $Version.Minor, $Version.Build, $Version.Revision + 1)
            }
            elseif ($Version.Build -lt [System.Int32]::MaxValue) {
                $NewVersion = [System.Version]::new($Version.Major, $Version.Minor, $Version.Build + 1, 0)
            }
            elseif ($Version.Minor -lt [System.Int32]::MaxValue) {
                $NewVersion = [System.Version]::new($Version.Major, $Version.Minor + 1, 0, 0)
            }
            elseif ($Version.Major -lt [System.Int32]::MaxValue) {
                $NewVersion = [System.Version]::new($Version.Major + 1, 0, 0, 0)
            }
            else {
                Throw 'Version has reached its maximum value.'
            }

            return $NewVersion
        })) -Option 'Constant' -Scope 'Global' -Description 'Scriptblock that can recursively increment an input version by one, and is aware of the max limit'

# Make sure the current OS build is equal or greater than the required build number
if (-NOT ([System.Decimal]$FullOSBuild -ge [System.Decimal]$Requiredbuild)) {
    Throw [System.PlatformNotSupportedException] "You are not using the latest build of the Windows OS. A minimum build of $Requiredbuild is required but your OS build is $FullOSBuild`nPlease go to Windows Update to install the updates and then try again."
}

# Enables additional progress indicators for Windows Terminal and Windows
$PSStyle.Progress.UseOSCIndicator = $true

# Loop through all the relevant files in the module
foreach ($File in (Get-ChildItem -Recurse -File -Path $ModuleRootPath -Include '*.ps1', '*.psm1')) {
    # Get the signature of the current file
    [System.Management.Automation.Signature]$Signature = Get-AuthenticodeSignature -FilePath $File
    # Ensure that they are code signed properly and have not been tampered with.
    if (($Signature.SignerCertificate.Thumbprint -eq '1c1c9082551b43eec17c0301bfb2f27031a4d8c8') -and ($Signature.Status -in 'Valid', 'UnknownError')) {
        # If the file is signed properly, then continue to the next file
    }
    else {
        Throw [System.Security.SecurityException] "The module has been tampered with, signature status of the file $($File.FullName) is $($Signature.Status)"
    }
}

<#
The reason behind this:

https://github.com/MicrosoftDocs/WDAC-Toolkit/pull/365
https://github.com/MicrosoftDocs/WDAC-Toolkit/issues/362

Features:

Short-circuits the cmdlet and finishes in 2 seconds.
put in the preloader script so it only runs once in the runspace.
No output is shown whatsoever (warning, error etc.)
Any subsequent attempts to run New-CiPolicy cmdlet will work normally without any errors or warnings.
The path I chose exists in Windows by default, and it contains very few PEs, something that is required for that error to be produced.
Test-Path is used for more resiliency.
-PathToCatroot is used and set to the same path as -ScanPath, this combination causes the operation to gracefully end prematurely.
The XML file is never created.
XML file is created but then immediately deleted. Its file name is random to minimize name collisions.
#>

if (Test-Path -LiteralPath 'C:\Program Files\Windows Defender\Offline' -PathType Container) {
    [System.String]$RandomGUID = [System.Guid]::NewGuid().ToString()
    New-CIPolicy -UserPEs -ScanPath 'C:\Program Files\Windows Defender\Offline' -Level hash -FilePath ".\$RandomGUID.xml" -NoShadowCopy -PathToCatroot 'C:\Program Files\Windows Defender\Offline' -WarningAction SilentlyContinue
    Remove-Item -LiteralPath ".\$RandomGUID.xml" -Force
}

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDXw80cYswbw2Fb
# NfQm1G9uNnnhuKFWKphY3CbQG7FQEKCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgPzCE9zaudQ0mvP0gOYxTeCXpevAOp8hmmByOpuiLhr0wDQYJKoZIhvcNAQEB
# BQAEggIAOI5i1WU1JPzzHOSejWwCz3UxUKtTaM4A14QN0wfTyErOc/zgDgtSAC1M
# ZPYHFmPeWvUjMwDWnUYb0ao7Xa/CfOMNc4woQrjXOsyyimNfxJtwRwo+jfM1dqc2
# ms1U/ReqkDJwZxmphhBbB9g4PdMj25ez5oERsj4C6Fks23Zm9Htg85UyJMpSI50o
# lZurDyst8DYtUsSkndAiJ6AUR3Mpx8pwNXOq54Mh5SujCh02gbzIy0ga4fegWVwW
# MsaCnQpErm3heBGTeDsoZYy1BoG522oFak87AoRreuSXz+V6cBwtPXuxUECip97M
# R2znV9QqwTldRHGOFA0IU5CjxNFXXp5zN36Aq2fxYXjb4qTmdlV4GY5HThxUYnmx
# bXzaj+oosqv2vIm/SDcnJGgGzX7uYqr8S4AX24M2dH2ZQg427QIWokMYV3dS+n8y
# xLvhooHElRIKyB91fdl2HZwDIb/p52Rt2z+bUBGTusqIxlfcM/VMkquwpqzIhqk5
# xCsLK8jbKMVOKAZyfZFNXU9IrzfTIt4rQAwFa8l6SmrMwnGBaTzrO9HA9UkExdb6
# uhIQCIK/oC2FHDBXlj3dUePT2D1mIwn7mhUfB5l2hUDezwmhYKa7vKWNQ6rDR7yy
# 0Jy7hNPduAu3VKkFNzNImYrkdUGIIpExHIYYD3731gYIk0Efb+o=
# SIG # End signature block
