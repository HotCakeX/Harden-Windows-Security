@{
  RootModule           = 'Harden-Windows-Security-Module.psm1'
  ModuleVersion        = '0.7.6'
  CompatiblePSEditions = @('Core')
  GUID                 = 'afae7a0a-5eff-4a4d-9139-e1702b7ac426'
  Author               = 'Violet Hansen'
  CompanyName          = 'SpyNetGirl'
  Copyright            = '(c) Violet Hansen. All rights reserved.'
  HelpInfoURI          = 'https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security'
  PowerShellVersion    = '7.5.0'
  RequiredAssemblies   = @()
  NestedModules        = @('Core\Confirm-SystemCompliance.psm1', 'Core\Protect-WindowsSecurity.psm1', 'Core\Unprotect-WindowsSecurity.psm1')
  FunctionsToExport    = @('Confirm-SystemCompliance', 'Protect-WindowsSecurity', 'Unprotect-WindowsSecurity', 'LoadHardenWindowsSecurityNecessaryDLLsInternal', 'ReRunTheModuleAgain')
  CmdletsToExport      = @()
  VariablesToExport    = '*'
  AliasesToExport      = @()
  Description          = @'

🔔 THIS MODULE IS DEPRECATED.
💗 Please use the new Harden System Security app, available on Microsoft Store, that has 100% of the features of the module, plus so much more. It's open source as well.
➡️ https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security

💞 Microsoft Store link:
➡️ https://apps.microsoft.com/detail/9P7GGFL7DX57

💜 GitHub post regarding the transition from module to app: https://github.com/HotCakeX/Harden-Windows-Security/discussions/778

💚 Harden System Security app's First release: https://github.com/HotCakeX/Harden-Windows-Security/releases/tag/HardenSystemSecurity-v.1.0.1.0

❤️‍🔥 Additional Distinguished Features of the Harden System Security Application:

✅ Minimal Memory Footprint: The application is engineered for lightweight efficiency, ensuring negligible system resource consumption. Architecturally, no application pages maintain navigation cache, strictly adhering to the MVVM pattern.

✅ Native Performance: Compiled ahead-of-time for instantaneous launch responsiveness. This approach shifts computational workload to compile-time rather than runtime (user's system), delivering an exceptionally responsive user experience.

✅ Static Code Implementation: The application avoids dynamic code generation, enhancing security posture and reducing vulnerability exposure. This design ensures compatibility with advanced OS-level exploit mitigations including Control Flow Guard (CFG).

✅ Methodical Architecture: The application employs systematic, modular design principles, facilitating seamless extensibility and maintainability. Future security measures can be integrated while preserving established patterns and design philosophies.

✅ Modern User Interface: Utilizing cutting-edge WinUI 3 components, the application delivers a contemporary, responsive, accessible, and intuitive interface. Full touch input compatibility is comprehensively supported.

✅ Internationalization Support: The application accommodates localization, enabling users to operate in their preferred language. Currently available in English, Hebrew, Greek, Hindi, Malayalam, Polish, Spanish, and Arabic.

✅ Open Source Transparency: The application maintains open source availability, permitting code inspection, community contributions, and ensuring complete functional transparency.

✅ Native API Preference and Low-Level Programming: The application prioritizes native APIs and low-level programming methodologies, optimizing performance and security. This approach enables exploitation of latest Windows capabilities without third-party component dependencies.

✅ High-Performance Language Utilization: The application is primarily developed in C#, strategically incorporating C++ and Rust components for specialized tasks. Performance optimization and security enhancement constitute the primary objectives of this design strategy.

✅ Complete Reversibility: Every modification applied to your system through the new Harden System Security application can be undone with precision. The application provides surgical accuracy in applying, verifying, and removing security measures. Individual security measures can be targeted for verification, application, or removal without affecting other security measures.

✅ For the Microsoft Defender category where the module used to add all git executables to the ASLR exclusions list because some of them were incompatible and wouldn't allow Git or GitHub desktop to work when the mitigation was on, this no longer happens like this. The new app is capable of identifying which files are incompatible with the Mandatory ASLR exploit mitigation and only adds those to the exclusion list.

✅ A new Group Policy Editor page full of new features and capabilities such as loading POL files, viewing all of the applied policies on the system and generating a comprehensive security report of the system.

➡️➡️ https://apps.microsoft.com/detail/9P7GGFL7DX57 ⬅️⬅️
➡️➡️ https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security ⬅️⬅️

'@

  PrivateData          = @{
    PSData = @{
      Tags         = @('Harden-Windows-Security', 'Harden', 'Windows', 'Security', 'Compliance', 'Validation', 'Baseline', 'Security-Score', 'Benchmark', 'Group-Policy')
      LicenseUri   = 'https://github.com/HotCakeX/.github/blob/main/LICENSE'
      ProjectUri   = 'https://github.com/HotCakeX/Harden-Windows-Security'
      IconUri      = 'https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Harden%20System%20Security%20Icons/ICON-FULLSIZE.png'
      ReleaseNotes = 'https://github.com/HotCakeX/Harden-Windows-Security/releases'
    }
  }
}