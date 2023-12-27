@{

    # Script module or binary module file associated with this manifest.
    RootModule           = 'WDACConfig.psm1'

    # Version number of this module.
    ModuleVersion        = '0.2.8'

    # Supported PSEditions
    CompatiblePSEditions = @('Core')

    # ID used to uniquely identify this module
    GUID                 = '79920947-efb5-48c1-a567-5b02ebe74793'

    # Author of this module
    Author               = 'HotCakeX'

    # Company or vendor of this module
    CompanyName          = 'SpyNetGirl'

    # Copyright statement for this module
    Copyright            = '(c) 2023-2024'

    # Description of the functionality provided by this module
    Description          = @'

This is an advanced PowerShell module for WDAC (Windows Defender Application Control) and automates a lot of tasks.


🟢 Please see the GitHub page for Full details and everything about the module: https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig


🛡️ Here is the list of module's cmdlets

✔️ New-WDACConfig: https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig

✔️ New-SupplementalWDACConfig: https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-SupplementalWDACConfig

✔️ Remove-WDACConfig: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Remove-WDACConfig

✔️ Edit-WDACConfig: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-WDACConfig

✔️ Edit-SignedWDACConfig: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-SignedWDACConfig

✔️ Deploy-SignedWDACConfig: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-SignedWDACConfig

✔️ Confirm-WDACConfig: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Confirm-WDACConfig

✔️ New-DenyWDACConfig: https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-DenyWDACConfig

✔️ Set-CommonWDACConfig: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig

✔️ New-KernelModeWDACConfig: https://github.com/HotCakeX/Harden-Windows-Security/wiki/New%E2%80%90KernelModeWDACConfig

✔️ Get-CommonWDACConfig: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Get-CommonWDACConfig

✔️ Invoke-WDACSimulation: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Invoke-WDACSimulation

✔️ Remove-CommonWDACConfig: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Remove-CommonWDACConfig

✔️ Assert-WDACConfigIntegrity: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Assert-WDACConfigIntegrity

To get help and syntax on PowerShell console, type:
"Get-Command -Module WDACConfig"
"Get-Help New-WDACConfig"
"Get-Help New-SupplementalWDACConfig"
"Get-Help Remove-WDACConfig"
"Get-Help Edit-WDACConfig"
"Get-Help Edit-SignedWDACConfig"
"Get-Help Deploy-SignedWDACConfig"
"Get-Help Confirm-WDACConfig"
"Get-Help New-DenyWDACConfig"
"Get-Help Set-CommonWDACConfig"
"Get-Help New-KernelModeWDACConfig"
"Get-Help Get-CommonWDACConfig"
"Get-Help Invoke-WDACSimulation"
"Get-Help Remove-CommonWDACConfig"
"Get-Help Assert-WDACConfigIntegrity"
'@

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion    = '7.4.0'

    # Name of the PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # DotNetFrameworkVersion = ''

    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # ClrVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules = @()

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    ScriptsToProcess     = @('Preloader.ps1')

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules        = @('Core\New-WDACConfig.psm1',
        'Core\Remove-WDACConfig.psm1',
        'Core\Deploy-SignedWDACConfig.psm1',
        'Core\Confirm-WDACConfig.psm1',
        'Core\Edit-WDACConfig.psm1',
        'Core\Edit-SignedWDACConfig.psm1',
        'Core\New-SupplementalWDACConfig.psm1',
        'Core\New-DenyWDACConfig.psm1',
        'Core\Set-CommonWDACConfig.psm1',
        'Core\New-KernelModeWDACConfig.psm1',
        'Core\Invoke-WDACSimulation.psm1',
        'Core\Get-CommonWDACConfig.psm1',
        'Core\Remove-CommonWDACConfig.psm1',
        'Core\Assert-WDACConfigIntegrity.psm1')

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport    = @('New-WDACConfig',
        'Remove-WDACConfig',
        'Deploy-SignedWDACConfig',
        'Confirm-WDACConfig',
        'Edit-WDACConfig',
        'Edit-SignedWDACConfig',
        'New-SupplementalWDACConfig',
        'New-DenyWDACConfig',
        'Set-CommonWDACConfig',
        'New-KernelModeWDACConfig',
        'Invoke-WDACSimulation',
        'Get-CommonWDACConfig',
        'Remove-CommonWDACConfig',
        'Assert-WDACConfigIntegrity')

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport      = @('New-WDACConfig',
        'Remove-WDACConfig',
        'Deploy-SignedWDACConfig',
        'Confirm-WDACConfig',
        'Edit-WDACConfig',
        'Edit-SignedWDACConfig',
        'New-SupplementalWDACConfig',
        'New-DenyWDACConfig',
        'Set-CommonWDACConfig',
        'New-KernelModeWDACConfig',
        'Invoke-WDACSimulation',
        'Get-CommonWDACConfig',
        'Remove-CommonWDACConfig',
        'Assert-WDACConfigIntegrity')

    # Variables to export from this module
    VariablesToExport    = '*'

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport      = @()

    # DSC resources to export from this module
    # DscResourcesToExport = @()

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    FileList             = @(
        'WDACConfig.psd1',
        'WDACConfig.psm1',
        'Preloader.ps1',
        'Core\New-WDACConfig.psm1',
        'Core\Deploy-SignedWDACConfig.psm1',
        'Core\Remove-WDACConfig.psm1',
        'Core\Confirm-WDACConfig.psm1',
        'Core\Edit-WDACConfig.psm1',
        'Core\Edit-SignedWDACConfig.psm1',
        'Core\New-SupplementalWDACConfig.psm1',
        'Core\New-DenyWDACConfig.psm1',
        'Core\Set-CommonWDACConfig.psm1',
        'Core\New-KernelModeWDACConfig.psm1',
        'Core\Invoke-WDACSimulation.psm1',
        'Core\Get-CommonWDACConfig.psm1',
        'Core\Remove-CommonWDACConfig.psm1',
        'Core\Assert-WDACConfigIntegrity.psm1',
        'CoreExt\PSDefaultParameterValues.ps1',
        'Resources\Resources2.ps1',
        'Resources\ArgumentCompleters.ps1'
        'Resources\WDAC Policies\DefaultWindows_Enforced_Kernel.xml',
        'Resources\WDAC Policies\DefaultWindows_Enforced_Kernel_NoFlights.xml',
        'Shared\Confirm-CertCN.psm1',
        'Shared\Get-AuditEventLogsProcessing.psm1',
        'Shared\Get-BlockRulesMeta.psm1',
        'Shared\Get-FileRules.psm1',
        'Shared\Get-GlobalRootDrives.psm1',
        'Shared\Get-RuleRefs.psm1',
        'Shared\Get-SignTool.psm1',
        'Shared\Move-UserModeToKernelMode.psm1',
        'Shared\New-EmptyPolicy.psm1',
        'Shared\Set-LogSize.psm1',
        'Shared\Test-FilePath.psm1',
        'Shared\Update-self.psm1',
        'Shared\Write-ColorfulText.psm1',
        'Shared\New-SnapBackGuarantee.psm1'
    )

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData          = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags         = @('WDAC', 'Windows-Defender-Application-Control', 'Windows', 'Security', 'Microsoft', 'Application-Control', 'App-Control-for-Business', 'Application-Whitelisting', 'BYOVD')

            # A URL to the license for this module.
            LicenseUri   = 'https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE'

            # A URL to the main website for this project.
            ProjectUri   = 'https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig'

            # A URL to an icon representing this module.
            IconUri      = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/WDACConfig/icon.png'

            # ReleaseNotes of this module
            ReleaseNotes = @'

Full Change log available in GitHub releases: https://github.com/HotCakeX/Harden-Windows-Security/releases

'@

            # Prerelease string of this module
            # Prerelease = ''

            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            # RequireLicenseAcceptance = $false

            # External dependent modules of this module
            # ExternalModuleDependencies = @()

        } # End of PSData hashtable

    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    HelpInfoURI          = 'https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig'

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''

}

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA1cvTergMkL7v0
# PJ6VcKlAHgFMHOyGssNR6TRRpVwyPaCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgcPLe13EqOYiUW1wake1FBppASDlm9qlcc5VZwVXEEjswDQYJKoZIhvcNAQEB
# BQAEggIAUDImTHchEiu2uxZuSZdxbIbxs68bNTy1iBLsIIhx+mZsGqgLmzuih1cI
# Uzog+G5Q4vhUMH85AnjWkIEBFUis+qa9CLjYU/5uIv9cDNMVS5avkHaNf48xfWXJ
# a9KgA6wbG/mQkChzECqaCsMIMyCGGqSyxuicx0qUKgYRxZMW6oLuMo9AK5amGKie
# 3w+OB7NP0c2nHTY9FdYe8ROF6gsEOBBzPsX2KTOrcJE9CRSSpnIkdxMQVpOW7Hb2
# 1ICh+ZVihUmgPsOj3QJweMmE9gcsmD2fNoRgrLGEBGzmtAqJPkJ1Dcs6SOMC4Eur
# g7A7LfF6Me7FZIJM2yxWOK2ebdUfmX5ELO2AZ9uVdh18AszJ/sqdXMbRdxPzywav
# DUytD1KR1TdC0L2ODeZFmGMK2940YiiVhyKA+C6uOxFC6UeSJUnhaBu375z8OP8G
# ox7cxJ3wm+FkYiDMMjNa9OWy3gMtClTqq9n5j8EXzaMU+ZaVFUT6ApkqDGFkQM0D
# HpFnQBXwq+e5ULRwJzYpj6z/4hpviMuq0o9PKcjNqPjUl98vYqKfkYKMR6y4wTGh
# rJ/qQtSucPoDXC707xOyX8+wKahAPfKvZ+OpyNk/3Q/jnZXXi6a64i+ayf+QWOBw
# DaCiZdI3pSx9MjFNH4q/YmqwJgr4oFvId3j2iljgHF+a2WSH8A4=
# SIG # End signature block
