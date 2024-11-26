@{
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_module_manifests

    RootModule           = 'WDACConfig.psm1'
    ModuleVersion        = '0.5.0'
    CompatiblePSEditions = @('Core')
    GUID                 = '79920947-efb5-48c1-a567-5b02ebe74793'
    Author               = 'HotCakeX'
    CompanyName          = 'SpyNetGirl'
    Copyright            = '(c) 2023-2024'
    PowerShellVersion    = '7.4.4'
    CmdletsToExport      = @()
    VariablesToExport    = '*'
    AliasesToExport      = @()
    HelpInfoURI          = 'https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig'
    Description          = @'


🟢This module is being transitioned to AppControl Manager application which is a modern GUI-based MSIX-packaged open-source Windows application. Check it out here: https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager

🩷 AppControl Manager is very high performance and offers a lot of new features and improvements.

Please see the GitHub page for Full details and everything about the module: https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig

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

✔️ Test-CiPolicy: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Test-CiPolicy

✔️ Get-CIPolicySetting: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Get-CIPolicySetting

'@

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
        'Core\Assert-WDACConfigIntegrity.psm1',
        'Core\Build-WDACCertificate.psm1',
        'Core\Test-CiPolicy.psm1',
        'Core\Get-CiFileHashes.psm1',
        'Core\Get-CIPolicySetting.psm1')

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
        'Assert-WDACConfigIntegrity',
        'Build-WDACCertificate',
        'Test-CiPolicy',
        'Get-CiFileHashes',
        'Get-CIPolicySetting',
        'Update-WDACConfigPSModule')

    PrivateData          = @{
        PSData = @{
            Tags         = @('WDAC', 'Windows-Defender-Application-Control', 'Windows', 'Security', 'Microsoft', 'Application-Control', 'App-Control-for-Business', 'Application-Whitelisting', 'BYOVD')
            LicenseUri   = 'https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig'
            IconUri      = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/WDACConfig/icon.png'
            ReleaseNotes = @'

Full Change log available in GitHub releases: https://github.com/HotCakeX/Harden-Windows-Security/releases

'@
            # Prerelease string of this module
            # Prerelease   = 'Beta1'
        }
    }
}