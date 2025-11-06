# Harden System Security

Harden System Security is a modern secure lightweight application that can help you harden, secure and lock down your system. It is designed to be user-friendly and efficient, providing a range of features to enhance the security of your Windows operating system.

It always stays up to date with the latest security patches and provides constant and consistent maintenance and support.

## How To Install or Update The App<img src="https://raw.githubusercontent.com/HotCakeX/.github/995a58370317109287d14bc4465b00ff89872ddf/Pictures/Gifs/heart-purple.gif" width="35">

### Use The [Microsoft Store](https://apps.microsoft.com/detail/9p7ggfl7dx57)

<a href="https://apps.microsoft.com/detail/9p7ggfl7dx57?referrer=appbadge&mode=direct">
	<img src="https://get.microsoft.com/images/en-us%20dark.svg" width="270"/>
</a>

### Use Winget

You can utilize Winget to automate the installation of the Harden System Security.

```powershell
winget install --id 9p7ggfl7dx57 --exact --accept-package-agreements --accept-source-agreements --force --source msstore
```

<br>

Please feel free to open a discussion if you have any questions about the build process, security, how to use or have feedbacks. [**Source code on this repository**](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/Harden%20System%20Security)

<br>

### Supported Operating Systems

* Windows 11 25H2
* Windows 11 24H2
* Windows 11 23H2
* Windows 11 22H2
* Windows Server 2025

<br>

## Preview of the App

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/e98e3a322d2bd04b6a77e2cd4d2d8909d0eb6af0/Pictures/Gifs/HardenWindowsSecurityApp.gif" alt="Harden System Security preview"/>

</div>

<br>

## Technical Details of The App <img src="https://raw.githubusercontent.com/HotCakeX/.github/995a58370317109287d14bc4465b00ff89872ddf/Pictures/Gifs/pinkbow.gif" width="32">

* Secure and transparent development and build process.
* Built using [WinUI3](https://learn.microsoft.com/windows/apps/winui/winui3/) / [XAML](https://github.com/microsoft/microsoft-ui-xaml) / [C#](https://learn.microsoft.com/dotnet/csharp/).
* Built using the latest [.NET](https://dotnet.microsoft.com) SDK.
* Powered by the [WinAppSDK](https://github.com/microsoft/WindowsAppSDK) (formerly Project Reunion).
* Packaged with the modern [MSIX](https://learn.microsoft.com/windows/msix/overview) format.
* Incorporates the [Mica](https://learn.microsoft.com/windows/apps/design/style/mica) material design for backgrounds.
* Adopts the Windows 11 [Fluent design system](https://fluent2.microsoft.design/components/windows).
* Fast execution and startup time.
* 0 required dependency.
* 0 Third-party library or file used.
* 0 Telemetry or data collection.
* 100% clean uninstallation.
* 100% open-source and free to use.
* Natively supports X64 and ARM64 architectures.
* Full [Trimming](https://learn.microsoft.com/dotnet/core/deploying/trimming/trim-self-contained) and [Native AOT](https://learn.microsoft.com/dotnet/core/deploying/native-aot) support.
* Never uses runtime marshaling.

<br>

## Features <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Features.png">

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/Shiny.gif" width="27" alt="Features Item"> Everything always stays up-to-date with the newest proactive security measures that are industry standards and scalable.

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/Shiny.gif" width="27" alt="Features Item"> No Windows functionality is removed/disabled against Microsoft's recommendations.

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/Shiny.gif" width="27" alt="Features Item"> All of the links in the documentations and sources are from official Microsoft websites, straight from the source. No bias, No FUD, No misinformation and definitely No old obsolete methods. That's why there are no links to 3rd party news websites, forums, made up blogs/articles, and such.

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/Shiny.gif" width="27" alt="Features Item"> When a security measure is no longer necessary because it's applied by default by Microsoft on new builds of Windows, it will also be removed from the app in order to prevent any problems and because it won't be necessary anymore. **Community feedback will always be taken into account when doing so.**

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/Shiny.gif" width="27" alt="Features Item"> Applying the security measures can make your system compliant with Microsoft Security Baselines and Secured-core PC specifications (provided that you use modern hardware that supports the latest Windows security features) - [See what makes a Secured-core PC](https://learn.microsoft.com/windows-hardware/design/device-experiences/oem-highly-secure-11#what-makes-a-secured-core-pc) - <a href="https://github.com/HotCakeX/Harden-Windows-Security/wiki/Device-Guard">Check Device Guard category for more info</a>
> [Secured-core](https://learn.microsoft.com/windows-hardware/design/device-experiences/oem-highly-secure-11) – recommended for the most sensitive systems and industries like financial, healthcare, and government agencies. Builds on the previous layers and leverages advanced processor capabilities to provide protection from firmware attacks.

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/Shiny.gif" width="27" alt="Features Item"> Since I originally created this repository for myself and people I care about, I always maintain it to the highest possible standard.

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/Shiny.gif" width="27" alt="Features Item"> If you have multiple accounts on your device, you only need to apply the security measures 1 time with Admin privileges, that will make system-wide changes. Then you can ***optionally*** run the app, without Admin privileges, for each standard user to apply the [Non-Admin category](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Non-Admin-Measures).

<br>

## Security <img src="https://raw.githubusercontent.com/HotCakeX/.github/995a58370317109287d14bc4465b00ff89872ddf/Pictures/Gifs/pinkbutterflyholopastel.gif" width="35">

> [!IMPORTANT]\
> The Harden System Security application is built publicly using a [GitHub Workflow](https://github.com/HotCakeX/Harden-Windows-Security/actions/runs/17206622843/workflow) and uploaded to the Microsoft Partner Center for validation and signing. The action uses [SBOM (Software Bill of Materials)](https://github.com/HotCakeX/Harden-Windows-Security/network/dependencies) generation to comply with the highest [security standards](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds) such as [SLSA](https://slsa.dev/spec/v1.0/levels) level 3. [GitHub's CodeQL Advanced workflow](https://github.com/HotCakeX/Harden-Windows-Security/actions/workflows/codeql.yml) with extended security model scans the entire repository. All of the dependencies of any project in this repository are uploaded to GitHub and are available in the [Dependency Graph](https://github.com/HotCakeX/Harden-Windows-Security/network/dependencies).

<br>

Harden System Security is architected with a security-first philosophy from its inception. Every feature is designed and implemented with an offensive security mindset, ensuring that security is never an afterthought—and never will be. When selecting a solution tasked with defending critical systems, the last thing you want is a so‑called security tool that silently broadens your attack surface or neglects foundational safeguards. This application is built to be inherently trustworthy, defensible, and resilient.

### Dependencies

Harden System Security explicitly and unequivocally maintains zero third‑party dependencies. It relies solely on the .NET SDK, the Windows App SDK, and a minimal set of small trusted Microsoft platform components for the User Interface. This deliberate constraint sharply reduces the attack surface and virtually eliminates common software supply chain attack vectors. Rather than pulling transient packages to satisfy feature gaps, required capabilities are purpose‑built in-house—implemented correctly, auditable, and securely. While this increases development effort and time, the mission and deployment contexts of this application more than justify the investment.

Leveraging GitHub's native automation (including Dependabot) alongside Microsoft's patch cadence, security and platform updates can be integrated and released rapidly, preserving both stability and assurance.

### Exploit Protection

The application avoids dynamic code generation, enhancing security posture and reducing vulnerability exposure. This design ensures compatibility with advanced OS-level exploit mitigation. The Harden System Security supports [process mitigations / Exploit Protections](https://learn.microsoft.com/defender-endpoint/exploit-protection-reference) such as: `Blocking low integrity images`, `Blocking remote images`, `Blocking untrusted fonts`, `Strict Control Flow Guard`, `Disabling extension points`, `Export Address Filtering`, `Hardware enforced stack protection`, `Import Address Filtering`, `Validate handle usage`, `Validate stack integrity`, `Code integrity guard`.

This disciplined approach bolsters resistance against memory corruption, injection, and tampering techniques frequently leveraged by sophisticated adversaries.

### Code Review

The codebase is extensively and thoughtfully documented, enabling reviewers to trace logic, validate control flows, and assess security-relevant decisions with minimal friction. I remain fully available to clarify design rationale, threat assumptions, or implementation details whenever deeper scrutiny is desired.

<br>

## Documentation <img src="https://raw.githubusercontent.com/HotCakeX/.github/c26ab12b9bc18eb51041857c6244d6abe11a707a/Pictures/Gifs/peaheartbento.gif" width="40">

> [!NOTE]\
> Mixing 3rd party security solutions with advanced Microsoft Defender features or other features offered by the Harden System Security app is not recommended as it can create conflicts.

### Symbols Reference

The following chart explains various symbols you will see throughout the documentations for the Harden System Security app, helping you understand how they are each applied.

<div align="center">

| Indicator| Description                   |
|:--------:|:-----------------------------:|
| <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> | Security measure is applied via Registry/API/COM etc. |
| <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> | Security measure is applied via Group Policies |
| <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="25" alt="Rotating green checkmark denoting CSP"> | [CSP](https://learn.microsoft.com/windows/configuration/provisioning-packages/how-it-pros-can-use-configuration-service-providers) for the security measure |
| <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/discord-verify-gradient.gif" width="25" alt="Rotating green checkmark denoting Subcategory"> | Sub-category |

</div>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/be5b79427cba6546ece58984428841a4d1a31789/Pictures/Gifs/Harden%20System%20Security%20Menu/Protect.gif" alt="Harden System Security Menu Item" width="30"> [Protect](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Protect)

    - <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Microsoft-Security-Baseline.png" alt="Harden System Security Menu Item" width="30"> [Microsoft Security Baselines](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Microsoft-Security-Baselines)
    - <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/d32e4aced203262acc7eff373e888f22247a4212/images/MicrosoftBaseLinesOverrides.png" alt="Harden System Security Menu Item" width="30"> [Microsoft Security Baselines Overrides](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Overrides-for-Microsoft-Security-Baseline)
    - <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Microsoft-365-Apps-Security-Baselines.png" alt="Harden System Security Menu Item" width="30"> [Microsoft 365 Apps Security Baseline](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Microsoft-365-Apps-Security-Baseline)
    - <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/WindowsDefender.png" alt="Harden System Security Menu Item" width="30"> [Microsoft Defender](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Microsoft-Defender)
    - <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/ASRrules.png" alt="Harden System Security Menu Item" width="30"> [Attack Surface Reduction](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Attack-Surface-Reduction)
    - <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Bitlocker.png" alt="Harden System Security Menu Item" width="30"> [Bitlocker](https://github.com/HotCakeX/Harden-Windows-Security/wiki/BitLocker)
    - <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/DeviceGuard.png" alt="Harden System Security Menu Item" width="30"> [Device Guard](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Device-Guard)
    - <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/TLS.png" alt="Harden System Security Menu Item" width="30"> [TLS Security](https://github.com/HotCakeX/Harden-Windows-Security/wiki/TLS-Security)
    - <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/LockScreen.png" alt="Harden System Security Menu Item" width="30"> [Lock Screen](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Lock-Screen)
    - <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/UAC.png" alt="Harden System Security Menu Item" width="30"> [User Account Control](https://github.com/HotCakeX/Harden-Windows-Security/wiki/User-Account-Control)
    - <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Firewall.png" alt="Harden System Security Menu Item" width="30"> [Windows Firewall](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Windows-Firewall)
    - <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/OptionalFeatures.png" alt="Harden System Security Menu Item" width="30"> [Optional Windows Features](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Optional-Windows-Features)
    - <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Networking.png" alt="Harden System Security Menu Item" width="30"> [Windows Networking](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Windows-Networking)
    - <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/MiscellaneousCommands.png" alt="Harden System Security Menu Item" width="30"> [Miscellaneous Configurations](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Miscellaneous-Configurations)
    - <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/WindowsUpdate.png" alt="Harden System Security Menu Item" width="30"> [Windows Update](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Windows-Update)
    - <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/EdgeBrowser.png" alt="Harden System Security Menu Item" width="30"> [Edge Browser](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edge-Browser)
    - <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Certificate.png" alt="Harden System Security Menu Item" width="30"> [Certificate Checking](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Certificate-Checking)
    - <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/CountryIPBlocking.png" alt="Harden System Security Menu Item" width="30"> [Country IP Blocking](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Country-IP-Blocking)
    - <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/NonAdmin.png" alt="Harden System Security Menu Item" width="30"> [Non Admin Measures](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Non-Admin-Measures)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/649f2b7c8e8c381722d3a3d95af16407d5187d94/Pictures/Gifs/Harden%20System%20Security%20Menu/Star.gif" alt="Harden System Security Menu Item" width="30"> [Group Policy Editor](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Group-Policy-Editor)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/649f2b7c8e8c381722d3a3d95af16407d5187d94/Pictures/Gifs/Harden%20System%20Security%20Menu/Toolbox.gif" alt="Harden System Security Menu Item" width="30"> [Manage Installed Apps](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Manage-Installed-Apps)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/649f2b7c8e8c381722d3a3d95af16407d5187d94/Pictures/Gifs/Harden%20System%20Security%20Menu/kawaii.gif" alt="Harden System Security Menu Item" width="30"> [File Reputation](https://github.com/HotCakeX/Harden-Windows-Security/wiki/File-Reputation)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/be5b79427cba6546ece58984428841a4d1a31789/Pictures/Gifs/Harden%20System%20Security%20Menu/ChocolateBar.gif" alt="Harden System Security Menu Item" width="30"> [Audit Policies](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Audit-Policies)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/d186f4e5b83d5097099d6ce05573bf1844d7a7b3/Pictures/Gifs/Harden%20System%20Security%20Menu/CBOM.gif" alt="Harden System Security Menu Item" width="30"> [Cryptographic Bill of Materials](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Cryptographic-Bill-of-Materials)

<br>

## Supported Languages

The Harden System Security fully supports the following languages.

* <img src="https://raw.githubusercontent.com/HotCakeX/.github/ea13e9ebae5baa7343c9c1721f58cf4400cd88f6/Pictures/Country%20Flags/usa.svg" width="25" alt="Country flag"> English
* <img src="https://raw.githubusercontent.com/HotCakeX/.github/ea13e9ebae5baa7343c9c1721f58cf4400cd88f6/Pictures/Country%20Flags/israel.svg" width="25" alt="Country flag"> Hebrew
* <img src="https://raw.githubusercontent.com/HotCakeX/.github/ea13e9ebae5baa7343c9c1721f58cf4400cd88f6/Pictures/Country%20Flags/greece.svg" width="25" alt="Country flag"> Greek
* <img src="https://raw.githubusercontent.com/HotCakeX/.github/ea13e9ebae5baa7343c9c1721f58cf4400cd88f6/Pictures/Country%20Flags/india.svg" width="25" alt="Country flag"> Hindi
* <img src="https://raw.githubusercontent.com/HotCakeX/.github/ea13e9ebae5baa7343c9c1721f58cf4400cd88f6/Pictures/Country%20Flags/india.svg" width="25" alt="Country flag"> Malayalam
* <img src="https://raw.githubusercontent.com/HotCakeX/.github/ea13e9ebae5baa7343c9c1721f58cf4400cd88f6/Pictures/Country%20Flags/saudi-arabia.svg" width="25" alt="Country flag"> Arabic
* <img src="https://raw.githubusercontent.com/HotCakeX/.github/ea13e9ebae5baa7343c9c1721f58cf4400cd88f6/Pictures/Country%20Flags/mexico.svg" width="25" alt="Country flag"> Spanish
* <img src="https://raw.githubusercontent.com/HotCakeX/.github/ea13e9ebae5baa7343c9c1721f58cf4400cd88f6/Pictures/Country%20Flags/poland.svg" width="25" alt="Country flag"> Polish
* <img src="https://raw.githubusercontent.com/HotCakeX/.github/2f006adff77201f244cacdbe7c3ad8ac34f50199/Pictures/Country%20Flags/icons8-germany.svg" width="25" alt="Country flag"> German

<br>

## Windows Service

The Harden System Security app utilizes a Windows Service that is responsible for performing tasks that require SYSTEM privilege such as Intune configurations detection during verification jobs so that even when you applied the security measures via Intune, they will be detected and verifiable by the app. The service is very compact (2MBs only), highly optimized and runs only when needed. It does not consume any resources when idle. The service is designed to automatically shut itself down when idle for 120 seconds.

It can only be used by elevated Administrators and SYSTEM account. It is automatically installed when the Harden System Security app is installed and removed when the Harden System Security app is uninstalled, not leaving any leftovers on the system. It has 0 dependency other than the .NET SDK itself and its executable is inside the app's package.

The service source code [can be found here](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/AppControl%20Manager/eXclude/QuantumRelayHSS). The service name is `QuantumRelayHSS` and it is designed to write verbose logs in the Windows Event log if you add a System environment variable to your OS named `QUANTUMRELAYHSS_DEBUG` with a value of `1` or `true`.

The service supports Arbitrary Code Guard exploit protection as well as many others, all of which can be applied to it in the [Microsoft Defender category](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Microsoft-Defender).

<br>

## CommandLine Interface (CLI) Support

The Harden System Security app can be launched via command line for advanced users and automation scenarios. Below are the supported commands and their usage:

### Via Execution Alias

* #### Open a Group Policy (.POL) file in the Group Policy Editor

```
HSS.exe --file="C:\Path\Policy.pol"
```

<br>

### Via File Activation (Supported File Types Only)

* #### Opens a POL file in the Group Policy Editor, same as double-clicking/tapping on the file in File Explorer.

```powershell
Invoke-Item -Path "C:\Path\Policy.pol"
```

<br>

### Via AUMID (Application User Model ID) Activation

* #### Simply launches Harden System Security

```
explorer.exe shell:AppsFolder\VioletHansen.HardenSystemSecurity_ea7andspwdn10!App
```

<br>

### Headless CLI Mode

Use `--cli` to run headless (no GUI). All CLI arguments are case-insensitive.

- If an operation requires elevation, the app will relaunch itself elevated and preserve all CLI arguments.
- If elevation is denied when required, no changes are performed.

#### Preset-based Operations

Run a full preset across selected categories.

```
HSS.exe --cli --preset=0|1|2 --op=Apply|Remove|Verify
```

- Presets
  - 0 = Basic
  - 1 = Recommended
  - 2 = Complete

- Examples
  - Apply the Recommended preset:
    ```
    HSS.exe --cli --preset=1 --op=Apply
    ```
  - Verify the Complete preset:
    ```
    HSS.exe --cli --preset=2 --op=Verify
    ```
  - Remove the Basic preset:
    ```
    HSS.exe --cli --preset=0 --op=Remove
    ```

<br>

#### Device Usage Intent Operations

Apply protections tailored to a specific [device usage intent](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Protect#device-usage-intents). Only Apply is supported for intents at this time.

```
HSS.exe --cli --intent=<IntentName> --op=Apply
```

- Supported intents
  - Development
  - Gaming
  - School
  - Business
  - SpecializedAccessWorkstation
  - PrivilegedAccessWorkstation

- Example (Business intent):

```
HSS.exe --cli --intent=Business --op=Apply
```

<br>

#### Exit Codes

- 0: Success or no-op (including cases where elevation was required but not granted; no changes performed)
- 1: Unexpected failure during execution
- 2: Invalid arguments (e.g., unsupported `--preset`, invalid `--op`, invalid `--intent`)

<br>

## Under the Hood: Files and Directories Structures Explained

Here is the breakdown of some of the directories and files used by the Harden System Security app.

* [Animated Icon Sources](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/Harden%20System%20Security/Animated%20Icon%20Sources) is the location hosting JSON content of the Lottie animations used for the animated buttons.

* [Animated Icons](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/Harden%20System%20Security/Animated%20Icons) contain source generated files used for animated icons in various parts of the app.

* [Resources](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/Harden%20System%20Security/Resources) directory contains JSON data used by the app to apply Security Measures for the following sources: `Group Policies`, `Registry Keys`, `Security Policies Registry Keys`.

* [CountryIPsData](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/Harden%20System%20Security/Resources/CountryIPsData) contains the JSON files used by the app in the [Country IP Blocking](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Country-IP-Blocking) page.

* [Mitigations](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/Harden%20System%20Security/Resources/Mitigations) contains files used by the app to apply, verify or remove Exploit Protection for different processes defined in it.

* [DISMService.exe](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Harden%20System%20Security/DISMService.exe) is one of the components of the Harden System Security app that provides DISM functionalities via named pipe.

* [CppInterop](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/Harden%20System%20Security/CppInterop) directory contains parts of the Harden System Security app written in C++.

<br>

If you'd like to know more about a specific file or directory please feel free to reach out.

<br>

## How To Build The Harden System Security Locally?

You can build the Harden System Security application directly from the source code locally on your device without using any 3rd party tools in a completely automated way. It will create the MSIXBundle file containing the X64 and ARM64 MSIX packages.

The build process will generate complete log files and you can use the [MSBuild Structured Log Viewer](https://learn.microsoft.com/shows/visual-studio-toolbox/msbuild-structured-log-viewer) to inspect them.

<details>

<summary>
✨ Click/Tap here to see the PowerShell code ✨
</summary>

<br>

```powershell
# Requires -Version 7.5
# Requires -RunAsAdministrator
function Build_HSS {
    param(
        [bool]$DownloadRepo,
        [bool]$InstallDeps,
        [bool]$Workflow,
        [bool]$UpdateWorkLoads,
        [bool]$Upload
    )

    $ErrorActionPreference = 'Stop'
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'LongPathsEnabled' -Value 1 -Force

    [System.String]$script:AppControlManagerDirectory

    if ($DownloadRepo) {

        [System.String]$BranchName = 'main'
        [System.String]$RepoName = 'Harden-Windows-Security'
        [System.String]$RepoUrl = "https://github.com/HotCakeX/$RepoName/archive/refs/heads/$BranchName.zip"
        [System.String]$ZipPath = [System.IO.Path]::Combine($env:TEMP, "$RepoName.zip")
        [System.String]$InitialWorkingDirectory = $PWD.Path
        $script:AppControlManagerDirectory = [System.IO.Path]::Combine($InitialWorkingDirectory, "$RepoName-$BranchName", 'Harden System Security')

        if (Test-Path -Path $script:AppControlManagerDirectory -PathType Container) {
            Remove-Item -Path $script:AppControlManagerDirectory -Recurse -Force
        }

        Invoke-WebRequest -Uri $RepoUrl -OutFile $ZipPath
        Expand-Archive -Path $ZipPath -DestinationPath $InitialWorkingDirectory -Force
        Remove-Item -Path $ZipPath -Force
        Set-Location -Path $script:AppControlManagerDirectory
    }
    else {
        $script:AppControlManagerDirectory = $PWD.Path
    }

    if ($InstallDeps) {

        # Install Winget if it doesn't exist
        if (!(Get-Command -Name 'winget.exe' -ErrorAction Ignore)) {

            # Retrieve the latest Winget release information
            $WingetReleases = Invoke-RestMethod -Uri 'https://api.github.com/repos/microsoft/winget-cli/releases'
            $LatestRelease = $WingetReleases | Select-Object -First 1
            # Direct links to the latest Winget release assets
            [string]$WingetURL = $LatestRelease.assets.browser_download_url | Where-Object -FilterScript { $_.EndsWith('.msixbundle') } | Select-Object -First 1
            [string]$WingetLicense = $LatestRelease.assets.browser_download_url | Where-Object -FilterScript { $_.EndsWith('License1.xml') } | Select-Object -First 1
            [string]$LatestWingetReleaseDependenciesZipURL = $LatestRelease.assets.browser_download_url | Where-Object -FilterScript { $_.EndsWith('DesktopAppInstaller_Dependencies.zip') } | Select-Object -First 1
            [hashtable]$Downloads = @{
                # 'Winget.msixbundle'                 = 'https://aka.ms/getwinget' This is updated slower than the GitHub release
                'DesktopAppInstaller_Dependencies.zip' = $LatestWingetReleaseDependenciesZipURL
                'Winget.msixbundle'                    = $WingetURL
                'License1.xml'                         = $WingetLicense
            }
            $Downloads.GetEnumerator() | ForEach-Object -Parallel {
                Invoke-RestMethod -Uri $_.Value -OutFile $_.Key
            }

            Expand-Archive -Path 'DesktopAppInstaller_Dependencies.zip' -DestinationPath .\ -Force

            # Required to update the Winget
            Stop-Process -Name 'WindowsTerminal' -Force -ErrorAction Ignore

            # Get the paths to all of the dependencies
            [string[]]$DependencyPaths = (Get-ChildItem -Path .\x64 -Filter '*.appx' -File -Force).FullName
            Add-AppxProvisionedPackage -Online -PackagePath 'Winget.msixbundle' -DependencyPackagePath $DependencyPaths -LicensePath 'License1.xml'

            Add-AppPackage -Path 'Winget.msixbundle' -DependencyPath "$($DependencyPaths[0])", "$($DependencyPaths[1])" -ForceTargetApplicationShutdown -ForceUpdateFromAnyVersion

        }

        Write-Host -Object 'The version of the Winget currently in use:'
        Write-Host -Object (winget --version)

        winget source update

        Write-Host -Object "`nInstalling Rust toolchain" -ForegroundColor Magenta
        $null = winget install --id Rustlang.Rustup --exact --accept-package-agreements --accept-source-agreements --uninstall-previous --force --source winget
        if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed to install the Rust toolchain: $LASTEXITCODE") }

        Write-Host -Object "`nInstalling .NET SDK" -ForegroundColor Magenta
        $null = winget install --id Microsoft.DotNet.SDK.Preview --exact --accept-package-agreements --accept-source-agreements --uninstall-previous --force --source winget
        if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed to install .NET SDK: $LASTEXITCODE") }

        Write-Host -Object "`nInstalling Visual Studio Build Tools" -ForegroundColor Magenta
        # Downloads the online installer and automatically runs it and installs the build tools
        # https://learn.microsoft.com/windows/apps/windows-app-sdk/set-up-your-development-environment
        # https://learn.microsoft.com/visualstudio/install/workload-component-id-vs-build-tools
        # https://learn.microsoft.com/visualstudio/install/use-command-line-parameters-to-install-visual-studio
        # https://learn.microsoft.com/visualstudio/install/workload-component-id-vs-community
        # winget install --id Microsoft.VisualStudio.2022.BuildTools --exact --accept-package-agreements --accept-source-agreements --uninstall-previous --force --source winget --override '--force --wait --passive --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Workload.MSBuildTools --add Microsoft.VisualStudio.Workload.UniversalBuildTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.26100 --includeRecommended --add Microsoft.VisualStudio.Component.VC.Tools.ARM64'

        # Using this until version 18 build tools are added to Winget
        Invoke-RestMethod -Uri "https://aka.ms/vs/18/insiders/vs_BuildTools.exe" -OutFile "vs_BuildTools.exe"
        Start-Process -Wait -FilePath .\vs_BuildTools.exe -ArgumentList '--force --wait --passive --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Workload.MSBuildTools --add Microsoft.VisualStudio.Workload.UniversalBuildTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.26100 --includeRecommended --add Microsoft.VisualStudio.Component.VC.Tools.ARM64'

        if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New('Failed to install Visual Studio Build Tools') }

        # winget install --id Microsoft.VCRedist.2015+.x64 --exact --accept-package-agreements --accept-source-agreements --uninstall-previous --force --source winget
    }

    # Refresh the environment variables so the current session detects the new dotnet installation
    $Env:Path = [System.Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine) + ';' +
    [System.Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::User)

    # https://github.com/Microsoft/vswhere/wiki/Start-Developer-Command-Prompt#using-powershell
    $installationPath = . 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe' -prerelease -latest -property installationPath
    if ($installationPath -and (Test-Path -Path "$installationPath\Common7\Tools\vsdevcmd.bat" -PathType Leaf)) {
        & "${env:COMSPEC}" /s /c "`"$installationPath\Common7\Tools\vsdevcmd.bat`" -no_logo && set" | ForEach-Object -Process {
            $name, $value = $_ -split '=', 2
            Set-Content -Path env:\"$name" -Value $value -Force
            Write-Host -Object "Setting environment variable: $name=$value"
        }
    }

    # Remove any possible existing directories
    Remove-Item -Path .\MSIXOutputX64 -Recurse -Force -ErrorAction Ignore
    Remove-Item -Path .\MSIXOutputARM64 -Recurse -Force -ErrorAction Ignore
    Remove-Item -Path .\MSIXBundleOutput -Recurse -Force -ErrorAction Ignore
    Remove-Item -Path .\bin -Recurse -Force -ErrorAction Ignore
    Remove-Item -Path .\obj -Recurse -Force -ErrorAction Ignore

    if ($UpdateWorkLoads) {
        # Update the workloads
        dotnet workload update
        dotnet workload config --update-mode workload-set
        dotnet workload update
        if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed updating the workloads. Exit Code: $LASTEXITCODE") }
    }

    Write-Host -Object "`nChecking .NET info`n`n" -ForegroundColor Magenta
    dotnet --info
    Write-Host -Object "`nListing installed .NET SDKs`n`n" -ForegroundColor Magenta
    dotnet --list-sdks

    function Find-mspdbcmf {
        # "-products *" is necessary to detect BuildTools too
        [string]$VisualStudioPath = . 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe' -prerelease -latest -property resolvedInstallationPath -products *

        [string]$BasePath = [System.IO.Path]::Combine($VisualStudioPath, 'VC', 'Tools', 'MSVC')

        # Get all subdirectories under the base path
        [System.String[]]$VersionDirs = [System.IO.Directory]::GetDirectories($BasePath)

        # Initialize the highest version with a minimal version value.
        [System.Version]$HighestVersion = [System.Version]::New('0.0.0.0')
        [System.String]$HighestVersionFolder = $null

        # Loop through each directory to find the highest version folder.
        foreach ($Dir in $VersionDirs) {
            # Extract the folder name
            [System.String]$FolderName = [System.IO.Path]::GetFileName($Dir)
            [System.Version]$CurrentVersion = $null
            # Try parsing the folder name as a Version.
            if ([System.Version]::TryParse($FolderName, [ref] $CurrentVersion)) {
                # Compare versions
                if ($CurrentVersion.CompareTo($HighestVersion) -gt 0) {
                    $HighestVersion = $CurrentVersion
                    $HighestVersionFolder = $FolderName
                }
            }
        }

        # If no valid version folder is found
        if (!$HighestVersionFolder) {
            throw [System.IO.DirectoryNotFoundException]::New("No valid version directories found in $BasePath")
        }

        # Combine the base path, the highest version folder, the architecture folder, and the file name.
        [System.String]$mspdbcmfPath = [System.IO.Path]::Combine($BasePath, $HighestVersionFolder, 'bin', 'Hostx64', 'x64', 'mspdbcmf.exe')

        if (![System.IO.File]::Exists($mspdbcmfPath)) {
            throw [System.IO.FileNotFoundException]::New("mspdbcmf.exe not found at $mspdbcmfPath")
        }

        return $mspdbcmfPath
    }

    [string]$mspdbcmfPath = Find-mspdbcmf

    function Find-MSBuild {
        # "-products *" is necessary to detect BuildTools too
        [string]$VisualStudioPath = . 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe' -prerelease -latest -property resolvedInstallationPath -products *

        [string]$MSBuildPath = [System.IO.Path]::Combine($VisualStudioPath, 'MSBuild', 'Current', 'Bin', 'MSBuild.exe')

        if (![System.IO.File]::Exists($MSBuildPath)) {
            throw [System.IO.FileNotFoundException]::New("MSBuild.exe not found at $MSBuildPath")
        }

        return $MSBuildPath
    }

    [string]$MSBuildPath = Find-MSBuild

    #region --- Compile C++ projects ---

    ### ComManager

    . $MSBuildPath '..\AppControl Manager\eXclude\ComManager\ComManager.slnx' /p:Configuration=Release /p:Platform=x64 /target:"clean;Rebuild"

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building ComManager solution for X64. Exit Code: $LASTEXITCODE") }

    . $MSBuildPath '..\AppControl Manager\eXclude\ComManager\ComManager.slnx' /p:Configuration=Release /p:Platform=arm64 /target:"clean;Rebuild"

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building ComManager solution for ARM64. Exit Code: $LASTEXITCODE") }

    #region --- RUST projects ---

    # Uncomment this once stable toolchain supports ehcont security feature, till then we use nightly only
    # rustup default stable
    rustup default nightly

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed setting Rust toolchain to Stable. Exit Code: $LASTEXITCODE") }

    rustup target add aarch64-pc-windows-msvc

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed adding aarch64-pc-windows-msvc target to Rust toolchain. Exit Code: $LASTEXITCODE") }

    rustup target add x86_64-pc-windows-msvc

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed adding x86_64-pc-windows-msvc target to Rust toolchain. Exit Code: $LASTEXITCODE") }

    rustup update

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed updating Rust. Exit Code: $LASTEXITCODE") }

    cargo version

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed checking for Rust version. Exit Code: $LASTEXITCODE") }

    [string]$Current_Location = (Get-Location).Path

    Set-Location -Path '..\AppControl Manager\eXclude\Rust Interop Library'

    if (Test-Path -PathType Leaf -LiteralPath 'Cargo.lock') {
        Remove-Item -Force -LiteralPath 'Cargo.lock'
    }

    rustup toolchain install nightly

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed installing nightly Rust toolchain. Exit Code: $LASTEXITCODE") }

    rustup default nightly

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed setting Rust toolchain to Nightly. Exit Code: $LASTEXITCODE") }

    rustup component add rust-src --toolchain nightly-x86_64-pc-windows-msvc

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed adding rust-src component to Nightly toolchain. Exit Code: $LASTEXITCODE") }

    rustup update

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed updating Rust. Exit Code: $LASTEXITCODE") }

    cargo version

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed checking for Rust version. Exit Code: $LASTEXITCODE") }

    cargo clean

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed cleaning the Rust project. Exit Code: $LASTEXITCODE") }

    cargo update --verbose

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed updating Rust. Exit Code: $LASTEXITCODE") }

    cargo tree

    rustup show active-toolchain

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed showing active Rust toolchain. Exit Code: $LASTEXITCODE") }

    cargo build_x64

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building x64 Rust Interop project. Exit Code: $LASTEXITCODE") }

    cargo build_arm64

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building ARM64 Rust Interop project. Exit Code: $LASTEXITCODE") }

    Set-Location -Path $Current_Location

    #endregion

    #region --- C# projects ---

    # DISM Service

    dotnet restore '..\AppControl Manager\eXclude\DISMService\DISMService.csproj' -r win-x64
    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed restoring DISMService for x64. Exit Code: $LASTEXITCODE") }

    dotnet restore '..\AppControl Manager\eXclude\DISMService\DISMService.csproj' -r win-arm64
    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed restoring DISMService for ARM64. Exit Code: $LASTEXITCODE") }

    dotnet clean '..\AppControl Manager\eXclude\DISMService\DISMService.csproj' --configuration Release
    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed cleaning DISMService (first pass). Exit Code: $LASTEXITCODE") }

    dotnet build '..\AppControl Manager\eXclude\DISMService\DISMService.csproj' --configuration Release --verbosity minimal /p:Platform=x64 /p:RuntimeIdentifier=win-x64
    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building DISMService (first pass). Exit Code: $LASTEXITCODE") }

    dotnet msbuild '..\AppControl Manager\eXclude\DISMService\DISMService.csproj' /p:Configuration=Release /restore /p:Platform=x64 /p:RuntimeIdentifier=win-x64 /p:PublishProfile="..\AppControl Manager\eXclude\DISMService\Properties\PublishProfiles\win-x64.pubxml" /t:Publish -v:minimal
    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed publishing DISMService for x64. Exit Code: $LASTEXITCODE") }

    dotnet clean '..\AppControl Manager\eXclude\DISMService\DISMService.csproj' --configuration Release
    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed cleaning DISMService (second pass). Exit Code: $LASTEXITCODE") }

    dotnet build '..\AppControl Manager\eXclude\DISMService\DISMService.csproj' --configuration Release --verbosity minimal /p:Platform=ARM64 /p:RuntimeIdentifier=win-arm64
    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building DISMService (second pass). Exit Code: $LASTEXITCODE") }

    dotnet msbuild '..\AppControl Manager\eXclude\DISMService\DISMService.csproj' /p:Configuration=Release /restore /p:Platform=arm64 /p:RuntimeIdentifier=win-arm64 /p:PublishProfile="..\AppControl Manager\eXclude\DISMService\Properties\PublishProfiles\win-arm64.pubxml" /t:Publish -v:minimal
    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed publishing DISMService for ARM64. Exit Code: $LASTEXITCODE") }


    # Windows Service

    dotnet restore '..\AppControl Manager\eXclude\QuantumRelayHSS\QuantumRelayHSS.csproj' -r win-x64
    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed restoring QuantumRelayHSS for x64. Exit Code: $LASTEXITCODE") }

    dotnet restore '..\AppControl Manager\eXclude\QuantumRelayHSS\QuantumRelayHSS.csproj' -r win-arm64
    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed restoring QuantumRelayHSS for ARM64. Exit Code: $LASTEXITCODE") }

    dotnet clean '..\AppControl Manager\eXclude\QuantumRelayHSS\QuantumRelayHSS.csproj' --configuration Release
    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed cleaning QuantumRelayHSS (first pass). Exit Code: $LASTEXITCODE") }

    dotnet build '..\AppControl Manager\eXclude\QuantumRelayHSS\QuantumRelayHSS.csproj' --configuration Release --verbosity minimal /p:Platform=x64 /p:RuntimeIdentifier=win-x64
    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building QuantumRelayHSS (first pass). Exit Code: $LASTEXITCODE") }

    dotnet msbuild '..\AppControl Manager\eXclude\QuantumRelayHSS\QuantumRelayHSS.csproj' /p:Configuration=Release /restore /p:Platform=x64 /p:RuntimeIdentifier=win-x64 /p:PublishProfile="..\AppControl Manager\eXclude\QuantumRelayHSS\Properties\PublishProfiles\win-x64.pubxml" /t:Publish -v:minimal
    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed publishing QuantumRelayHSS for x64. Exit Code: $LASTEXITCODE") }

    dotnet clean '..\AppControl Manager\eXclude\QuantumRelayHSS\QuantumRelayHSS.csproj' --configuration Release
    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed cleaning QuantumRelayHSS (second pass). Exit Code: $LASTEXITCODE") }

    dotnet build '..\AppControl Manager\eXclude\QuantumRelayHSS\QuantumRelayHSS.csproj' --configuration Release --verbosity minimal /p:Platform=ARM64 /p:RuntimeIdentifier=win-arm64
    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building QuantumRelayHSS (second pass). Exit Code: $LASTEXITCODE") }

    dotnet msbuild '..\AppControl Manager\eXclude\QuantumRelayHSS\QuantumRelayHSS.csproj' /p:Configuration=Release /restore /p:Platform=arm64 /p:RuntimeIdentifier=win-arm64 /p:PublishProfile="..\AppControl Manager\eXclude\QuantumRelayHSS\Properties\PublishProfiles\win-arm64.pubxml" /t:Publish -v:minimal
    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed publishing QuantumRelayHSS for ARM64. Exit Code: $LASTEXITCODE") }


    #endregion

    [string]$CsProjFilePath = (Resolve-Path -Path '.\Harden System Security.csproj').Path

    # https://learn.microsoft.com/dotnet/core/tools/dotnet-build
    # https://learn.microsoft.com/visualstudio/msbuild/msbuild-command-line-reference
    # https://learn.microsoft.com/visualstudio/msbuild/common-msbuild-project-properties

    # Copy the X64 components to the directory before the build starts

    Copy-Item -Path '..\AppControl Manager\eXclude\ComManager\x64\Release\ComManager.exe' -Destination '.\CppInterop\ComManager.exe' -Force

    Copy-Item -Path '..\AppControl Manager\eXclude\DISMService\OutputX64\DISMService.exe' -Destination '.\DISMService.exe' -Force

    Copy-Item -Path '..\AppControl Manager\eXclude\QuantumRelayHSS\OutputX64\QuantumRelayHSS.exe' -Destination '.\QuantumRelayHSS.exe' -Force

    # Generate for X64 architecture
    dotnet clean 'Harden System Security.csproj' --configuration Release
    dotnet build 'Harden System Security.csproj' --configuration Release --verbosity minimal /p:Platform=x64 /p:RuntimeIdentifier=win-x64

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building x64 Harden System Security project. Exit Code: $LASTEXITCODE") }

    dotnet msbuild 'Harden System Security.csproj' /t:Publish /p:Configuration=Release /p:RuntimeIdentifier=win-x64 /p:AppxPackageDir="MSIXOutputX64\" /p:GenerateAppxPackageOnBuild=true /p:Platform=x64 -v:minimal /p:MsPdbCmfExeFullpath=$mspdbcmfPath -bl:X64MSBuildLog.binlog

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed packaging x64 Harden System Security project. Exit Code: $LASTEXITCODE") }

    # Copy the ARM64 components to the directory before the build starts

    Copy-Item -Path '..\AppControl Manager\eXclude\ComManager\ARM64\Release\ComManager.exe' -Destination '.\CppInterop\ComManager.exe' -Force

    Copy-Item -Path '..\AppControl Manager\eXclude\DISMService\OutputARM64\DISMService.exe' -Destination '.\DISMService.exe' -Force

    Copy-Item -Path '..\AppControl Manager\eXclude\QuantumRelayHSS\OutputARM64\QuantumRelayHSS.exe' -Destination '.\QuantumRelayHSS.exe' -Force

    # Generate for ARM64 architecture
    dotnet clean 'Harden System Security.csproj' --configuration Release
    dotnet build 'Harden System Security.csproj' --configuration Release --verbosity minimal /p:Platform=ARM64 /p:RuntimeIdentifier=win-arm64

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building ARM64 Harden System Security project. Exit Code: $LASTEXITCODE") }

    dotnet msbuild 'Harden System Security.csproj' /t:Publish /p:Configuration=Release /p:RuntimeIdentifier=win-arm64 /p:AppxPackageDir="MSIXOutputARM64\" /p:GenerateAppxPackageOnBuild=true /p:Platform=ARM64 -v:minimal /p:MsPdbCmfExeFullpath=$mspdbcmfPath -bl:ARM64MSBuildLog.binlog

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed packaging ARM64 Harden System Security project. Exit Code: $LASTEXITCODE") }

    function Get-MSIXFile {
        param(
            [System.String]$BasePath,
            [System.String]$FolderPattern,
            [System.String]$FileNamePattern,
            [System.String]$ErrorMessageFolder,
            [System.String]$ErrorMessageFile
        )
        # Get all subdirectories in the base path matching the folder pattern
        [System.String[]]$Folders = [System.IO.Directory]::GetDirectories($BasePath)
        [System.String]$DetectedFolder = $null
        foreach ($Folder in $Folders) {
            if ([System.Text.RegularExpressions.Regex]::IsMatch($Folder, $FolderPattern)) {
                $DetectedFolder = $Folder
                break
            }
        }

        if (!$DetectedFolder) {
            throw [System.InvalidOperationException]::New($ErrorMessageFolder)
        }

        # Get the full path of the first file matching the file name pattern inside the found folder
        [System.String[]]$Files = [System.IO.Directory]::GetFiles($DetectedFolder)
        [System.String]$DetectedFile = $null
        foreach ($File in $Files) {
            if ([System.Text.RegularExpressions.Regex]::IsMatch($File, $FileNamePattern)) {
                $DetectedFile = $File
                break
            }
        }

        if (!$DetectedFile) {
            throw [System.InvalidOperationException]::New($ErrorMessageFile)
        }
        return $DetectedFile
    }

    #region Finding X64 outputs
    [System.String]$FinalMSIXX64Path = Get-MSIXFile -BasePath ([System.IO.Path]::Combine($PWD.Path, 'MSIXOutputX64')) -FolderPattern 'Harden System Security_\d+\.\d+\.\d+\.\d+_x64_Test' -FileNamePattern 'Harden System Security_\d+\.\d+\.\d+\.\d+_x64\.msix' -ErrorMessageFolder 'Could not find the directory for X64 MSIX file' -ErrorMessageFile 'Could not find the X64 MSIX file'
    [System.String]$FinalMSIXX64Name = [System.IO.Path]::GetFileName($FinalMSIXX64Path)
    [System.String]$FinalMSIXX64SymbolPath = Get-MSIXFile -BasePath ([System.IO.Path]::Combine($PWD.Path, 'MSIXOutputX64')) -FolderPattern 'Harden System Security_\d+\.\d+\.\d+\.\d+_x64_Test' -FileNamePattern 'Harden System Security_\d+\.\d+\.\d+\.\d+_x64\.appxsym' -ErrorMessageFolder 'Could not find the directory for X64 symbol file' -ErrorMessageFile 'Could not find the X64 symbol file'
    [System.String]$FinalMSIXX64SymbolName = [System.IO.Path]::GetFileName($FinalMSIXX64SymbolPath)
    #endregion

    #region Finding ARM64 outputs
    [System.String]$FinalMSIXARM64Path = Get-MSIXFile -BasePath ([System.IO.Path]::Combine($PWD.Path, 'MSIXOutputARM64')) -FolderPattern 'Harden System Security_\d+\.\d+\.\d+\.\d+_arm64_Test' -FileNamePattern 'Harden System Security_\d+\.\d+\.\d+\.\d+_arm64\.msix' -ErrorMessageFolder 'Could not find the directory for ARM64 MSIX file' -ErrorMessageFile 'Could not find the ARM64 MSIX file'
    [System.String]$FinalMSIXARM64Name = [System.IO.Path]::GetFileName($FinalMSIXARM64Path)
    [System.String]$FinalMSIXARM64SymbolPath = Get-MSIXFile -BasePath ([System.IO.Path]::Combine($PWD.Path, 'MSIXOutputARM64')) -FolderPattern 'Harden System Security_\d+\.\d+\.\d+\.\d+_arm64_Test' -FileNamePattern 'Harden System Security_\d+\.\d+\.\d+\.\d+_arm64\.appxsym' -ErrorMessageFolder 'Could not find the directory for ARM64 symbol file' -ErrorMessageFile 'Could not find the ARM64 symbol file'
    [System.String]$FinalMSIXARM64SymbolName = [System.IO.Path]::GetFileName($FinalMSIXARM64SymbolPath)
    #endregion

    #region Detect and Validate File Versions
    [System.Text.RegularExpressions.Regex]$versionRegexX64 = [System.Text.RegularExpressions.Regex]::New('Harden System Security_(\d+\.\d+\.\d+\.\d+)_x64\.msix')

    [System.Text.RegularExpressions.Regex]$versionRegexARM64 = [System.Text.RegularExpressions.Regex]::New('Harden System Security_(\d+\.\d+\.\d+\.\d+)_arm64\.msix')
    [System.Text.RegularExpressions.Match]$MatchX64 = $versionRegexX64.Match($FinalMSIXX64Name)

    [System.Text.RegularExpressions.Match]$MatchARM64 = $versionRegexARM64.Match($FinalMSIXARM64Name)

    if (!$MatchX64.Success) {
        throw [System.InvalidOperationException]::New('Could not detect version from X64 file name')
    }

    if (!$MatchARM64.Success) {
        throw [System.InvalidOperationException]::New('Could not detect version from ARM64 file name')
    }

    [System.String]$versionX64 = $MatchX64.Groups[1].Value

    [System.String]$versionARM64 = $MatchARM64.Groups[1].Value


    if ($versionX64 -ne $versionARM64) {
        throw [System.InvalidOperationException]::New('The versions in X64 and ARM64 files do not match')
    }

    # Craft the file name for the MSIX Bundle file
    [System.String]$FinalBundleFileName = "Harden System Security_$versionX64.msixbundle"
    #endregion

    # Creating the directory where the MSIX packages will be copied to
    [System.String]$MSIXBundleOutput = [System.IO.Directory]::CreateDirectory([System.IO.Path]::Combine($script:AppControlManagerDirectory, 'MSIXBundleOutput')).FullName

    [System.IO.File]::Copy($FinalMSIXX64Path, [System.IO.Path]::Combine($MSIXBundleOutput, $FinalMSIXX64Name), $true)

    [System.IO.File]::Copy($FinalMSIXARM64Path, [System.IO.Path]::Combine($MSIXBundleOutput, $FinalMSIXARM64Name), $true)

    # The path to the final MSIX Bundle file
    [System.String]$MSIXBundle = [System.IO.Path]::Combine($MSIXBundleOutput, $FinalBundleFileName)

    function Get-MakeAppxPath {
        [System.String]$BasePath = 'C:\Program Files (x86)\Windows Kits\10\bin'

        # Get all subdirectories under the base path
        [System.String[]]$VersionDirs = [System.IO.Directory]::GetDirectories($BasePath)

        # Initialize the highest version with a minimal version value.
        [System.Version]$HighestVersion = [System.Version]::New('0.0.0.0')
        [System.String]$HighestVersionFolder = $null

        # Loop through each directory to find the highest version folder.
        foreach ($Dir in $VersionDirs) {
            # Extract the folder name
            [System.String]$FolderName = [System.IO.Path]::GetFileName($Dir)
            [System.Version]$CurrentVersion = $null
            # Try parsing the folder name as a Version.
            if ([System.Version]::TryParse($FolderName, [ref] $CurrentVersion)) {
                # Compare versions
                if ($CurrentVersion.CompareTo($HighestVersion) -gt 0) {
                    $HighestVersion = $CurrentVersion
                    $HighestVersionFolder = $FolderName
                }
            }
        }

        # If no valid version folder is found
        if (!$HighestVersionFolder) {
            throw [System.IO.DirectoryNotFoundException]::New("No valid version directories found in $BasePath")
        }

        [string]$CPUArch = @{AMD64 = 'x64'; ARM64 = 'arm64' }[$Env:PROCESSOR_ARCHITECTURE]
        if ([System.String]::IsNullOrWhiteSpace($CPUArch)) { throw [System.PlatformNotSupportedException]::New('Only AMD64 and ARM64 architectures are supported.') }

        # Combine the base path, the highest version folder, the architecture folder, and the file name.
        [System.String]$MakeAppxPath = [System.IO.Path]::Combine($BasePath, $HighestVersionFolder, $CPUArch, 'makeappx.exe')

        return $MakeAppxPath
    }

    [System.String]$MakeAppxPath = Get-MakeAppxPath

    if ([System.string]::IsNullOrWhiteSpace($MakeAppxPath)) {
        throw [System.IO.FileNotFoundException]::New('Could not find the makeappx.exe')
    }

    # https://learn.microsoft.com/windows/win32/appxpkg/make-appx-package--makeappx-exe-#to-create-a-package-bundle-using-a-directory-structure
    . $MakeAppxPath bundle /d $MSIXBundleOutput /p $MSIXBundle /o /v

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("MakeAppx failed creating the MSIXBundle. Exit Code: $LASTEXITCODE") }

    #Endregion

    Write-Host -Object "X64 MSIX File Path: $FinalMSIXX64Path" -ForegroundColor Green
    Write-Host -Object "X64 MSIX File Name: $FinalMSIXX64Name" -ForegroundColor Green
    Write-Host -Object "X64 Symbols: $FinalMSIXX64SymbolPath" -ForegroundColor Green

    Write-Host -Object "ARM64 MSIX File Path: $FinalMSIXARM64Path" -ForegroundColor Cyan
    Write-Host -Object "ARM64 MSIX File Name: $FinalMSIXARM64Name" -ForegroundColor Cyan
    Write-Host -Object "ARM64 Symbols: $FinalMSIXARM64SymbolPath" -ForegroundColor Cyan

    Write-Host -Object "MSIX Bundle File Path: $MSIXBundle" -ForegroundColor Yellow
    Write-Host -Object "MSIX Bundle File Name: $FinalBundleFileName" -ForegroundColor Yellow

    if ($Workflow) {

        [XML]$CSProjXMLContent = Get-Content -Path $CsProjFilePath -Force
        [string]$MSIXVersion = $CSProjXMLContent.Project.PropertyGroup.FileVersion
        [string]$MSIXVersion = $MSIXVersion.Trim() # It would have trailing whitespaces
        if ([string]::IsNullOrWhiteSpace($FinalMSIXX64Path) -or [string]::IsNullOrWhiteSpace($FinalMSIXX64Name) -or [string]::IsNullOrWhiteSpace($MSIXVersion)) { throw 'Necessary info could not be found' }

        # Write the MSIXVersion to GITHUB_ENV to set it as an environment variable for the entire workflow
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "PACKAGE_VERSION=$MSIXVersion"

        # Saving the details for the MSIX Bundle file
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "MSIXBundle_PATH=$MSIXBundle"
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "MSIXBundle_NAME=$FinalBundleFileName"

        # Saving the details of the log files
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "X64MSBuildLog_PATH=$((Resolve-Path -Path .\X64MSBuildLog.binlog).Path)"
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "ARM64MSBuildLog_PATH=$((Resolve-Path -Path .\ARM64MSBuildLog.binlog).Path)"

        # Saving the details of the X64 symbol file
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "X64Symbol_PATH=$FinalMSIXX64SymbolPath"
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "X64Symbol_NAME=$FinalMSIXX64SymbolName"

        # Saving the details of the ARM64 symbol file
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "ARM64Symbol_PATH=$FinalMSIXARM64SymbolPath"
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "ARM64Symbol_NAME=$FinalMSIXARM64SymbolName"

        # https://github.com/microsoft/sbom-tool
        # Generating SBOM
        Invoke-WebRequest -Uri 'https://github.com/microsoft/sbom-tool/releases/latest/download/sbom-tool-win-x64.exe' -OutFile "${Env:RUNNER_TEMP}\sbom-tool.exe"

        # https://github.com/microsoft/sbom-tool/blob/main/docs/sbom-tool-arguments.md
        . "${Env:RUNNER_TEMP}\sbom-tool.exe" generate -b $MSIXBundleOutput -bc .\ -pn 'Harden System Security' -ps 'Violet Hansen' -pv $MSIXVersion -nsb 'https://github.com/HotCakeX/Harden-Windows-Security' -V Verbose -gt true -li true -pm true -D true -lto 80

        # Saving the details of the SBOM file
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "SBOM_PATH=$MSIXBundleOutput/_manifest/spdx_2.2/manifest.spdx.json"
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value 'SBOM_NAME=manifest.spdx.json'
    }

    if ($Upload) {
        dotnet clean '..\AppControl Manager\eXclude\PartnerCenter\PartnerCenter.slnx' --configuration Release
        dotnet build '..\AppControl Manager\eXclude\PartnerCenter\PartnerCenter.slnx' --configuration Release --verbosity minimal
        dotnet msbuild '..\AppControl Manager\eXclude\PartnerCenter\PartnerCenter.slnx' /p:Configuration=Release /p:Platform=x64 /p:PublishProfile=win-x64 /t:Publish -v:minimal

        [System.String]$TokenEndpoint = $env:PARTNERCENTER_TOKENENDPOINT
        [System.String]$ClientId = $env:PARTNERCENTER_CLIENTID
        [System.String]$ClientSecret = $env:PARTNERCENTER_CLIENTSECRET
        [System.String]$ApplicationId = $env:PARTNERCENTER_APPLICATIONID_HSS

        [System.String]$PackageFilePath = $MSIXBundle
        [System.String]$ReleaseNotesFilePath = (Resolve-Path -Path ReleaseNotes.txt).Path

        . '..\AppControl Manager\eXclude\PartnerCenter\X64Output\PartnerCenter.exe' $TokenEndpoint $ClientId $ClientSecret $ApplicationId $PackageFilePath $ReleaseNotesFilePath
    }

    if ($null -ne $Stopwatch) {

        $Stopwatch.Stop()

        $Elapsed = $Stopwatch.Elapsed
        [string]$Result = @"
                  Execution Time:
                  ----------------------------
                  Total Time   : $($Elapsed.ToString('g'))
                  Hours        : $($Elapsed.Hours)
                  Minutes      : $($Elapsed.Minutes)
                  Seconds      : $($Elapsed.Seconds)
                  Milliseconds : $($Elapsed.Milliseconds)
                  ----------------------------
"@

        Write-Host -Object $Result -ForegroundColor Cyan
    }
}

# For GitHub workflow
# Build_HSS -DownloadRepo $false -InstallDeps $true -Workflow $true -UpdateWorkLoads $false -Upload $true
# Local - ARM64 + X64
Build_HSS -DownloadRepo $true -InstallDeps $true -Workflow $false -UpdateWorkLoads $false -Upload $false

```

<br>

</details>

<br>
