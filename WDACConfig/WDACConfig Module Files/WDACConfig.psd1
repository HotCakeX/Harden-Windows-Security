@{

    # Script module or binary module file associated with this manifest.
    RootModule           = 'WDACConfig.psm1'

    # Version number of this module.
    ModuleVersion        = '0.4.1'

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

✔️ Build-WDACCertificate: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Build-WDACCertificate

✔️ Test-CiPolicy: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Test-CiPolicy

✔️ ConvertTo-WDACPolicy: https://github.com/HotCakeX/Harden-Windows-Security/wiki/ConvertTo-WDACPolicy

✔️ Get-CiFileHashes: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Get-CiFileHashes

✔️ Set-CiRuleOptions: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CiRuleOptions

✔️ Get-CIPolicySetting: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Get-CIPolicySetting

'@

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion    = '7.4.2'

    # Name of the PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules      = @()

    # Assemblies that must be loaded prior to importing this module
    # Required for File/Folder picker GUI
    # RequiredAssemblies   = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess     = @('Preloader.ps1')

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
        'Core\Assert-WDACConfigIntegrity.psm1',
        'Core\Build-WDACCertificate.psm1',
        'Core\Test-CiPolicy.psm1',
        'Core\ConvertTo-WDACPolicy.psm1',
        'Core\Get-CiFileHashes.psm1',
        'Core\Set-CiRuleOptions.psm1',
        'Core\Get-CIPolicySetting.psm1')

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
        'Assert-WDACConfigIntegrity',
        'Build-WDACCertificate',
        'Test-CiPolicy',
        'ConvertTo-WDACPolicy',
        'Get-CiFileHashes',
        'Set-CiRuleOptions',
        'Get-CIPolicySetting')

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
        'Assert-WDACConfigIntegrity',
        'Build-WDACCertificate',
        'Test-CiPolicy',
        'ConvertTo-WDACPolicy',
        'Get-CiFileHashes',
        'Set-CiRuleOptions',
        'Get-CIPolicySetting')

    # Variables to export from this module
    VariablesToExport    = '*'

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport      = @()

    # DSC resources to export from this module
    # DscResourcesToExport = @()

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    FileList             = @('WDACConfig.psd1',
        'WDACConfig.psm1',
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
        'Core\Build-WDACCertificate.psm1',
        'Core\Test-CiPolicy.psm1',
        'Core\ConvertTo-WDACPolicy.psm1',
        'Core\Get-CiFileHashes.psm1',
        'Core\Set-CiRuleOptions.psm1',
        'Core\Get-CIPolicySetting.psm1',
        'CoreExt\PSDefaultParameterValues.ps1',
        'CoreExt\ArgumentCompleters.ps1',
        'Resources\WDAC Policies\DefaultWindows_Enforced_Kernel.xml',
        'Resources\WDAC Policies\DefaultWindows_Enforced_Kernel_NoFlights.xml',
        'Resources\User Configurations\Schema.json',
        'Resources\WDAC Policies-Archived\DefaultWindows_Enforced_Kernel.xml',
        'Resources\WDAC Policies-Archived\DefaultWindows_Enforced_Kernel_NoFlights.xml',
        'Resources\WDAC Policies-Archived\Readme.md',
        'Resources\PolicyRuleOptions.Json',
        'Shared\Get-GlobalRootDrives.psm1',
        'Shared\Get-SignTool.psm1',
        'Shared\Move-UserModeToKernelMode.psm1',
        'Shared\Set-LogSize.psm1',
        'Shared\Update-Self.psm1',
        'Shared\Write-ColorfulText.psm1',
        'Shared\New-SnapBackGuarantee.psm1',
        'Shared\Get-KernelModeDriversAudit.psm1',
        'Shared\Remove-SupplementalSigners.psm1',
        'Shared\Receive-CodeIntegrityLogs.psm1',
        'Shared\Set-LogPropertiesVisibility.psm1',
        'Shared\Test-KernelProtectedFiles.psm1',
        'Shared\Select-LogProperties.psm1',
        'Shared\Get-KernelModeDrivers.psm1',
        'Shared\Invoke-CiSigning.psm1',
        'Shared\Show-DirectoryPathPicker.psm1',
        'Shared\Test-ECCSignedFiles.psm1',
        'WDACSimulation\Get-SignerInfo.psm1',
        'WDACSimulation\Get-FileRuleOutput.psm1',
        'WDACSimulation\Get-CertificateDetails.psm1',
        'WDACSimulation\Compare-SignerAndCertificate.psm1',
        'Help\ConvertTo-WDACPolicy.xml',
        'Help\ConvertTo-WDACPolicy.md',
        'XMLOps\Build-SignerAndHashObjects.psm1',
        'XMLOps\Clear-CiPolicy_Semantic.psm1',
        'XMLOps\Close-EmptyXmlNodes_Semantic.psm1',
        'XMLOps\Compare-CorrelatedData.psm1',
        'XMLOps\Merge-Signers_Semantic.psm1',
        'XMLOps\New-FilePublisherLevelRules.psm1',
        'XMLOps\New-HashLevelRules.psm1',
        'XMLOps\New-PublisherLevelRules.psm1',
        'XMLOps\Optimize-MDECSVData.psm1',
        'XMLOps\Remove-AllowElements_Semantic.psm1',
        'XMLOps\Remove-DuplicateAllowAndFileRuleRefElements_IDBased.psm1',
        'XMLOps\Remove-DuplicateAllowedSignersAndCiSigners_IDBased.psm1',
        'XMLOps\Remove-DuplicateFileAttrib_IDBased.psm1',
        'XMLOps\Remove-DuplicateFileAttrib_Semantic.psm1',
        'XMLOps\Remove-DuplicateFileAttribRef_IDBased.psm1',
        'XMLOps\Remove-OrphanAllowedSignersAndCiSigners_IDBased.psm1',
        'XMLOps\Remove-UnreferencedFileRuleRefs.psm1',
        'XMLOps\New-CertificateSignerRules.psm1',
        'XMLOps\New-PFNLevelRules.psm1',
        'XMLOps\New-Macros.psm1',
        'XMLOps\Checkpoint-Macros.psm1',
        'Public\Write-FinalOutput.psm1',
        'Public\MockConfigCIBootstrap.psm1',
        'C#\Custom Types\ChainElement.cs',
        'C#\Custom Types\PolicyHashObj.cs',
        'C#\Custom Types\Signer.cs',
        'C#\Custom Types\SimulationInput.cs',
        'C#\Custom Types\HashCreator.cs',
        'C#\Custom Types\CertificateDetailsCreator.cs',
        'C#\Custom Types\FilePublisherSignerCreator.cs',
        'C#\Custom Types\PublisherSignerCreator.cs',
        'C#\Custom Types\OpusSigner.cs',
        'C#\Custom Types\SimulationOutput.cs',
        'C#\Custom Types\AuthenticodePageHashes.cs',
        'C#\Custom Types\CertificateSignerCreator.cs',
        'C#\Custom Types\ChainPackage.cs',
        'C#\Functions\AllCertificatesGrabber.cs',
        'C#\Functions\AuthenticodeHashCalc.cs',
        'C#\Functions\CertificateHelper.cs',
        'C#\Functions\Crypt32CertCN.cs',
        'C#\Functions\Kernel32dll.cs',
        'C#\Functions\PageHashCalc.cs',
        'C#\Functions\WldpQuerySecurityPolicy.cs',
        'C#\Functions\GetOpusData.cs',
        'C#\Functions\VersionIncrementer.cs',
        'C#\Functions\CIPolicyVersion.cs',
        'C#\Functions\EditGUIDs.cs',
        'C#\Functions\SecureStringComparer.cs',
        'C#\Functions\GetFilesFast.cs',
        'C#\Functions\MeowOpener.cs',
        'C#\Functions\XmlFilePathExtractor.cs',
        'C#\Functions\FileDirectoryPathComparer.cs',
        'C#\Functions\CiPolicyUtility.cs',
        'C#\Functions\StagingArea.cs',
        'C#\Functions\GetExtendedFileAttrib.cs',
        'C#\Variables\ArgumentCompleters.cs',
        'C#\Variables\GlobalVariables.cs',
        'C#\ArgumentCompleters\BasePolicyNamez.cs',
        'C#\ArgumentCompleters\CertCNz.cs',
        'C#\ArgumentCompleters\RuleOptionsx.cs',
        'C#\ArgumentCompleters\ScanLevelz.cs')

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
            # Prerelease   = 'Beta1'

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
