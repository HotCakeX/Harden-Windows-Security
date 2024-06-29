<#
Load order of the WDACConfig module

1. The Preloader.ps1 file (aka ScriptsToProcess defined in the manifest)
2. All Individual sub-modules (All psm1 files defined in the NestedModules array in the manifest)
3. The WDACConfig.psm1 (aka RootModule defined in the manifest)
4. The cmdlet that the user invoked on the command line, if any.
#>

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

# Make sure the current OS build is equal or greater than the required build number
if (-NOT ([System.Decimal]$FullOSBuild -ge [System.Decimal]$Requiredbuild)) {
    Throw [System.PlatformNotSupportedException] "You are not using the latest build of the Windows OS. A minimum build of $Requiredbuild is required but your OS build is $FullOSBuild`nPlease go to Windows Update to install the updates and then try again."
}

# This is required for the EKUs to work.
# Load all the DLLs in the PowerShell folder, providing .NET types for the module
# These types are required for the folder picker with multiple select options. Also the module manifest no longer handles assembly as it's not necessary anymore.
foreach ($Dll in (Convert-Path -Path ("$([psobject].Assembly.Location)\..\*.dll"))) {
    try {
        Add-Type -Path $Dll
    }
    catch {}
}

# Import all C# codes at once so they will get compiled together, have resolved dependencies and recognize each others' classes/types
Add-Type -Path (Get-ChildItem -File -Recurse -Path "$ModuleRootPath\C#").FullName -ReferencedAssemblies ('System',
    'System.Security.Cryptography.Pkcs',
    'System.Security.Cryptography.X509Certificates',
    'System.Security.Cryptography',
    'System.Xml',
    'System.Formats.Asn1',
    'System.IO',
    'System.Runtime.InteropServices',
    'System.Collections',
    'System.Xml.ReaderWriter',
    'System.Collections.NonGeneric',
    'System.Management',
    'System.Globalization')

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\CoreExt\ArgumentCompleters.ps1"

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCCbCEoVvzF3HfP
# 3eQ4bi3IVLVc+fdXewcuFKEs0YI0q6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgK2tRR7Jr6MuejnCAixOsMnW7iaLVi3gYkNSUehiSYTIwDQYJKoZIhvcNAQEB
# BQAEggIAH4t02ra1fruG73cSdnXY0TJJjVA+TvDKhNFCNJMcQiKN6XGKPe2TrONp
# Xg95Sz815YbrZCBZezNDBgXOX1jh91gDq4cyYbsytXCN/PKnIPN5gIqYqYlqVNip
# NwTfzc3L07kU4u+t8STFqkz1/olU3TOHzdsxVcrBXHccqrqz1sZVNbSR1SoW6uF1
# Sxj0yM6aEwjcr1ytbv+t/Ve1b6xkno0Hlk1/65RRu11LFbqrhkS/J3+B30FY1DjL
# O2hOdJfE9B23TqXxna+uUITfH7/Su6KyD+rCh1CXrjrQjfxNNg7qHGQHFWroF/TR
# CDTdig4FmcouREAFL1h1SV5d7zWHQl0J62zihXsh5VJ/cYgGIKRQP7xTH6RVuAzZ
# 3GSCrhY25RO4TEsrM76UK2gc9FHiiWy/Hr8gY5ghB27KEQT0EsA+8lcR02K6fNGB
# 6lNTHd0VmHUZB1feK7cG4tqEFdbkB4ZrfBLYOT9Y1Bjw2YUHVZpfnnLC3Ir6lVnG
# jZC9TS5vv5wgBJQmrqXcma3OHTh6mnblK/JJ1iIj6sbT2ujUEkoj4usCYYZlr6uZ
# 3cvQcNaurOEuEKyZCAE3duQQypTlq5fXYMXTGBCbvtJaQaUcEuyP25RVIk9YJhD4
# QXFssm5gdxRu/fh9RI5fyHQH2yMceuPN8Rw6nWYEq8e4R0cKyXY=
# SIG # End signature block
