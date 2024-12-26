@{
    RootModule           = 'WDACConfig.psm1'
    ModuleVersion        = '0.5.1'
    CompatiblePSEditions = @('Core')
    GUID                 = '79920947-efb5-48c1-a567-5b02ebe74793'
    Author               = 'HotCakeX'
    CompanyName          = 'SpyNetGirl'
    Copyright            = '(c) 2023-2024'
    PowerShellVersion    = '7.4.4'
    CmdletsToExport      = @()
    VariablesToExport    = '*'
    AliasesToExport      = @()
    HelpInfoURI          = 'https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager'
    Description          = @'

🟢This module has been Evolved into the AppControl Manager application which is a modern GUI-based MSIX-packaged open-source Windows application. Check it out here: https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager

🩷 AppControl Manager is very high performance and offers a lot of new features and improvements. It includes every feature that WDACConfig module had plus so much more.

'@
    NestedModules        = @('Core\New-SupplementalWDACConfig.psm1', 'Core\New-DenyWDACConfig.psm1', 'Core\New-KernelModeWDACConfig.psm1', 'Core\Test-CiPolicy.psm1')

    FunctionsToExport    = @('New-SupplementalWDACConfig', 'New-DenyWDACConfig', 'New-KernelModeWDACConfig', 'Test-CiPolicy')

    PrivateData          = @{
        PSData = @{
            Tags         = @('WDAC', 'Windows-Defender-Application-Control', 'Windows', 'Security', 'Microsoft', 'Application-Control', 'App-Control-for-Business', 'Application-Whitelisting', 'BYOVD')
            LicenseUri   = 'https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager'
            IconUri      = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/WDACConfig/icon.png'
            ReleaseNotes = 'https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager'
        }
    }
}