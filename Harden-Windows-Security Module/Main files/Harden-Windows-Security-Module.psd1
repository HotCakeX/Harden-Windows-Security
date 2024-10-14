@{
  # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_module_manifests

  RootModule           = 'Harden-Windows-Security-Module.psm1'
  ModuleVersion        = '0.6.7'
  CompatiblePSEditions = @('Core')
  GUID                 = 'afae7a0a-5eff-4a4d-9139-e1702b7ac426'
  Author               = 'Violet Hansen'
  CompanyName          = 'SpyNetGirl'
  Copyright            = '(c) Violet Hansen. All rights reserved.'
  HelpInfoURI          = 'https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden%E2%80%90Windows%E2%80%90Security%E2%80%90Module'
  PowerShellVersion    = '7.4.4'
  RequiredAssemblies   = @()
  NestedModules        = @('Core\Confirm-SystemCompliance.psm1', 'Core\Protect-WindowsSecurity.psm1', 'Core\Unprotect-WindowsSecurity.psm1')
  FunctionsToExport    = @('Confirm-SystemCompliance', 'Protect-WindowsSecurity', 'Unprotect-WindowsSecurity', 'Update-HardenWindowsSecurity')
  CmdletsToExport      = @()
  VariablesToExport    = '*'
  AliasesToExport      = @()
  Description          = @'

Harden Windows Safely, Securely, only with Official Microsoft methods - 🦄 Intune - 🧩 Group Policy - 🛡️ Local - ☁️ Cloud (All scenarios supported 💯)

⭕ This module provides 3 main features: Hardening, Auditing/checking the system compliance, and undoing the Hardening

⭕ Please read the GitHub's readme before running this module: https://github.com/HotCakeX/Harden-Windows-Security

💜 GUI (Graphical User Interface) is Available! Run (Protect-WindowsSecurity -GUI) to use the GUI instead of the CLI experience.

💠 Features of this module:

  ✅ Everything always stays up-to-date with the newest proactive security measures that are industry standards and scalable.
  ✅ Everything is in clear text, nothing hidden, no 3rd party executable or pre-compiled binary is involved.
  ✅ No Windows functionality is removed/disabled against Microsoft's recommendations.
  ✅ The module primarily uses Group policies, the Microsoft recommended way of configuring Windows. It also uses PowerShell cmdlets where Group Policies aren't available, and finally uses a few registry keys to configure security measures that can neither be configured using Group Policies nor PowerShell cmdlets. This is why the module doesn't break anything or cause unwanted behavior.
  ✅ When a hardening measure is no longer necessary because it's applied by default by Microsoft on new builds of Windows, it will also be removed from the module in order to prevent any problems and because it won't be necessary anymore.
  ✅ The module can be run infinite number of times, it's made in a way that it won't make any duplicate changes.
  ✅ The module prompts for confirmation before running each hardening category.
  ✅ Applying these hardening measures makes your PC compliant with Microsoft Security Baselines and Secured-core PC specifications (provided that you use modern hardware that supports the latest Windows security features)

💠 Hardening Categories from top to bottom: (⬇️Detailed info about each of them at my Github⬇️)

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

🏴 If you have any questions, requests, suggestions etc. about this module, please open a new Discussion or Issue on GitHub

🟡 The module generates a nice output on the screen as well as giving users an option to export the results in a CSV file.

'@

  PrivateData          = @{
    PSData = @{
      Tags         = @('Harden-Windows-Security', 'Harden', 'Windows', 'Security', 'Compliance', 'Validation', 'Baseline', 'Security-Score', 'Benchmark', 'Group-Policy')
      LicenseUri   = 'https://github.com/HotCakeX/.github/blob/main/LICENSE'
      ProjectUri   = 'https://github.com/HotCakeX/Harden-Windows-Security'
      IconUri      = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/refs/heads/main/Harden-Windows-Security%20Module/ICON-FULLSIZE.png'
      ReleaseNotes = @'

Complete detailed release notes available on GitHub releases: https://github.com/HotCakeX/Harden-Windows-Security/releases/

'@

      # Prerelease string of this module
      # Prerelease   = 'RC2'
    }
  }
}
