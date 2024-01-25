@{

  # Script module or binary module file associated with this manifest.
  RootModule           = 'Harden-Windows-Security-Module.psm1'

  # Version number of this module.
  ModuleVersion        = '0.3.1'

  # Supported PSEditions
  CompatiblePSEditions = @('Core')

  # ID used to uniquely identify this module
  GUID                 = 'afae7a0a-5eff-4a4d-9139-e1702b7ac426'

  # Author of this module
  Author               = 'HotCakeX'

  # Company or vendor of this module
  CompanyName          = 'SpyNetGirl'

  # Copyright statement for this module
  Copyright            = '(c) HotCakeX. All rights reserved.'

  # Description of the functionality provided by this module
  Description          = @'

Harden Windows Safely, Securely, only with Official Microsoft methods

⭕ This module provides 3 main features: Hardening, Auditing/checking the system compliance, and undoing the Hardening

⭕ Please read the GitHub's readme before running this module: https://github.com/HotCakeX/Harden-Windows-Security

💠 Features of this module:

  ✅ Everything always stays up-to-date with the newest proactive security measures that are industry standards and scalable.
  ✅ Everything is in plain text, nothing hidden, no 3rd party executable or pre-compiled binary is involved.
  ✅ No Windows functionality is removed/disabled against Microsoft's recommendations.
  ✅ The module primarily uses Group policies, the Microsoft recommended way of configuring Windows. It also uses PowerShell cmdlets where Group Policies aren't available, and finally uses a few registry keys to configure security measures that can neither be configured using Group Policies nor PowerShell cmdlets. This is why the module doesn't break anything or cause unwanted behavior.
  ✅ When a hardening measure is no longer necessary because it's applied by default by Microsoft on new builds of Windows, it will also be removed from the module in order to prevent any problems and because it won't be necessary anymore.
  ✅ The module can be run infinite number of times, it's made in a way that it won't make any duplicate changes.
  ✅ The module prompts for confirmation before running each hardening category.
  ✅ Applying these hardening measures makes your PC compliant with Microsoft Security Baselines and Secured-core PC specifications (provided that you use modern hardware that supports the latest Windows security features)

💠 Hardening Categories from top to bottom: (🔻Detailed info about each of them at my Github🔻)

⏹ Commands that require Administrator Privileges
  ✅ Microsoft Security Baselines
  ✅ Microsoft 365 Apps Security Baselines
  ✅ Microsoft Defender
  ✅ Attack surface reduction rules
  ✅ Bitlocker Settings
  ✅ TLS Security
  ✅ Lock Screen
  ✅ UAC (User Account Control)
  ✅ Windows Firewall
  ✅ Optional Windows Features
  ✅ Windows Networking
  ✅ Miscellaneous Configurations
  ✅ Windows Update Configurations
  ✅ Edge Browser Configurations
  ✅ Certificate Checking Commands
  ✅ Country IP Blocking
  ✅ Downloads Defense Measures
⏹ Commands that don't require Administrator Privileges
  ✅ Non-Admin Commands that only affect the current user and do not make machine-wide changes.


💎 This module has hybrid mode of operation. It can run Interactively and non-interactively (Silent/unattended mode). More info in the document: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden%E2%80%90Windows%E2%80%90Security%E2%80%90Module

🏴 If you have any questions, requests, suggestions etc. about this script, please open a new Discussion or Issue on GitHub

🟡 The module generates a nice output on the screen as well as giving users an option to export the results in a CSV file.

'@

  # Minimum version of the PowerShell engine required by this module
  PowerShellVersion    = '7.4.1'

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
  NestedModules        = @('Core\Confirm-SystemCompliance.psm1', 'Core\Protect-WindowsSecurity.psm1', 'Core\Unprotect-WindowsSecurity.psm1')

  # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
  FunctionsToExport    = @('Confirm-SystemCompliance', 'Protect-WindowsSecurity', 'Unprotect-WindowsSecurity')

  # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
  CmdletsToExport      = @('Confirm-SystemCompliance', 'Protect-WindowsSecurity', 'Unprotect-WindowsSecurity')

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
    'Harden-Windows-Security-Module.psd1',
    'Harden-Windows-Security-Module.psm1',
    'Preloader.ps1',
    'Core\Confirm-SystemCompliance.psm1',
    'Core\Protect-WindowsSecurity.psm1',
    'Core\Unprotect-WindowsSecurity.psm1',
    'Resources\Default Security Policy.inf',
    'Resources\Registry resources.csv',
    'Resources\EventViewerCustomViews.zip',
    'Resources\Security-Baselines-X.zip',
    'Resources\Registry.csv',
    'Resources\ProcessMitigations.csv',
    'Shared\Update-self.psm1',
    'Shared\Test-IsAdmin.psm1'
  )

  # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
  PrivateData          = @{

    PSData = @{

      # Tags applied to this module. These help with module discovery in online galleries.
      Tags         = @('Harden-Windows-Security', 'Harden', 'Windows', 'Security', 'Compliance', 'Validation', 'Baseline', 'Security-Score', 'Benchmark', 'Group-Policy')

      # A URL to the license for this module.
      LicenseUri   = 'https://github.com/HotCakeX/.github/blob/main/LICENSE'

      # A URL to the main website for this project.
      ProjectUri   = 'https://github.com/HotCakeX/Harden-Windows-Security'

      # A URL to an icon representing this module.
      IconUri      = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/PowerShell%20Gallery%20Icon/Peach%20Small.png'

      # ReleaseNotes of this module
      ReleaseNotes = @'

Complete detailed release notes available on GitHub releases: https://github.com/HotCakeX/Harden-Windows-Security/releases/

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
  HelpInfoURI          = 'https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden%E2%80%90Windows%E2%80%90Security%E2%80%90Module'

  # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
  # DefaultCommandPrefix = ''

}