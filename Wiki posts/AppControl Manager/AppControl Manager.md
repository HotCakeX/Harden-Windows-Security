# AppControl Manager

AppControl Manager is a modern secure app that provides easy to use graphical user interface to manage App Control and Code Integrity on your local or remote devices.

It always stays up to date with the latest security patches and provides constant and consistent maintenance and support.

**⚡What is App Control? [Check Out This Article ⚡](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction)**

<br>

## How To Install or Update The App<img src="https://raw.githubusercontent.com/HotCakeX/.github/995a58370317109287d14bc4465b00ff89872ddf/Pictures/Gifs/heart-purple.gif" width="40">

### Use The Microsoft Store

<a href="https://apps.microsoft.com/detail/9png1jddtgp8?mode=direct">
	<img src="https://get.microsoft.com/images/en-us%20dark.svg" width="230" alt="install AppControl Manager from Microsoft Store"/>
</a>

AppControl Manager is available on [**the Microsoft Store**](https://apps.microsoft.com/detail/9PNG1JDDTGP8). **This is the easiest and recommended way to install it.** You will use the Microsoft Store to receive future updates.

<br>

### Use GitHub Packages

Use the following PowerShell [command](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Harden-Windows-Security.ps1) as Admin, it will automatically download the latest MSIXBundle file from this repository's release page and install it for you.

```powershell
(irm 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security.ps1')+'AppControl'|iex
```

> [!TIP]\
> [AppControl Manager supports auto-update and has built-in updater.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Update)

<br>

### Use Winget

You can utilize Winget to automate the installation of the AppControl Manager. It will use the Microsoft Store source.

```powershell
winget install --id 9PNG1JDDTGP8 --exact --accept-package-agreements --accept-source-agreements --force --source msstore
```

<br>

Please feel free to open a discussion if you have any questions about the build process, security, how to use or have feedbacks. [**Source code on this repository**](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/AppControl%20Manager)

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

<a href="https://www.youtube.com/watch?v=SzMs13n7elE"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControlManager.gif" alt="AppControl Manager preview"/> </a>

<br>

<a href="https://www.youtube.com/watch?v=SzMs13n7elE"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20video%20Demo%20Thumbnail.png" alt="AppControl Manager YouTube Video demo thumbnail" width="700"> </a>

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
* 0 Windows Registry changes.
* 100% clean uninstallation.
* 100% open-source and free to use.
* Natively supports X64 and ARM64 architectures.
* Full [Trimming](https://learn.microsoft.com/dotnet/core/deploying/trimming/trim-self-contained) and [Native AOT](https://learn.microsoft.com/dotnet/core/deploying/native-aot) support.
* Never uses runtime marshaling.

<br>

## Features Implemented So Far <img src="https://raw.githubusercontent.com/HotCakeX/.github/995a58370317109287d14bc4465b00ff89872ddf/Pictures/Gifs/pinklollipoppurplebow.gif" width="35">

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControl%20Manager%20Menu/Create%20Policy.gif" alt="AppControl Manager Menu Item" width="20"> [Create AppControl Policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-App-Control-Policy)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControl%20Manager%20Menu/Create%20Supplemental%20Policy.gif" alt="AppControl Manager Menu Item" width="20"> [Create Supplemental Policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Supplemental-App-Control-Policy)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControl%20Manager%20Menu/System%20Information.gif" alt="AppControl Manager Menu Item" width="20"> [System Information](https://github.com/HotCakeX/Harden-Windows-Security/wiki/System-Information)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControl%20Manager%20Menu/Configure%20Policy%20Rule%20Options.gif" alt="AppControl Manager Menu Item" width="20"> [Configure Policy Rule Options](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Configure-Policy-Rule-Options)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/2a7cfc538ca70d855b567c77084f063f03119e14/Pictures/Gifs/AppControl%20Manager%20Menu/Policy%20Editor.gif" alt="AppControl Manager Menu Item" width="21"> [Policy Editor](https://github.com/HotCakeX/Harden-Windows-Security/wiki/PolicyEditor)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControl%20Manager%20Menu/Simulation.gif" alt="AppControl Manager Menu Item" width="20"> [Simulation](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Simulation)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControl%20Manager%20Menu/Allow%20New%20Apps.gif" alt="AppControl Manager Menu Item" width="20"> [Allow New Apps](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Allow-New-Apps)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControl%20Manager%20Menu/Build%20new%20certificate.gif" alt="AppControl Manager Menu Item" width="20"> [Build New Certificate](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Build-New-Certificate)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControl%20Manager%20Menu/Create%20policy%20from%20Event%20Logs.gif" alt="AppControl Manager Menu Item" width="20"> [Create Policy From Event Logs](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Policy-From-Event-Logs)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControl%20Manager%20Menu/Create%20policy%20from%20MDE%20Advanced%20Hunting.gif" alt="AppControl Manager Menu Item" width="20"> [Create Policy From MDE Advanced Hunting](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Policy-From-MDE-Advanced-Hunting)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControl%20Manager%20Menu/Create%20Deny%20Policy.gif" alt="AppControl Manager Menu Item" width="20"> [Create Deny Policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Deny-App-Control-Policy)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControl%20Manager%20Menu/Merge%20App%20Control%20Policies.gif" width="20" alt="AppControl Manager Menu Item"> [Merge App Control Policies](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Merge-App-Control-Policies)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControl%20Manager%20Menu/Deployment.gif" alt="AppControl Manager Menu Item" width="20"> [Deploy App Control Policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-App-Control-Policy)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControl%20Manager%20Menu/Get%20CI%20Hahses.gif" alt="AppControl Manager Menu Item" width="20"> [Get Code Integrity Hashes](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Get-Code-Integrity-Hashes)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControl%20Manager%20Menu/Get%20Secure%20policy%20settings.gif" alt="AppControl Manager Menu Item" width="20"> [Get Secure Policy Settings](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Get-Secure-Policy-Settings)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControl%20Manager%20Menu/Update.gif" alt="AppControl Manager Menu Item" width="20"> [Update](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Update)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControl%20Manager%20Menu/Sidebar.gif" alt="AppControl Manager Menu Item" width="20"> [Sidebar](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Sidebar)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControl%20Manager%20Menu/View%20File%20Certificates.gif" alt="AppControl Manager Menu Item" width="20"> [Validate Policies](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Validate-Policies)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControl%20Manager%20Menu/Validate%20Policies.gif" alt="AppControl Manager Menu Item" width="20"> [View File Certificates](https://github.com/HotCakeX/Harden-Windows-Security/wiki/View-File-Certificates)
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/7ac3898730bc82a790f56a61e301b6663dfc9d5a/Pictures/Gifs/AppControl%20Manager%20Menu/Microsoft%20Graph.gif" alt="AppControl Manager Menu Item" width="20"> [Microsoft Graph](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Microsoft-Graph)

*More features will come very quickly in the near future.*

<br>

## Supported Languages

The AppControl Manager fully supports the following languages. You can request for more languages to be supported.

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

## Security <img src="https://raw.githubusercontent.com/HotCakeX/.github/995a58370317109287d14bc4465b00ff89872ddf/Pictures/Gifs/pinkbutterflyholopastel.gif" width="35">

> [!IMPORTANT]\
> The AppControl Manager application is built publicly using a [GitHub Workflow](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/.github/workflows/Build%20AppControl%20Manager%20MSIX%20Package.yml) and uploaded to the GitHub release. The action uses [Artifact Attestation](https://github.com/HotCakeX/Harden-Windows-Security/attestations) and [SBOM (Software Bill of Materials)](https://github.com/HotCakeX/Harden-Windows-Security/network/dependencies) generation to comply with the highest [security standards](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds) such as [SLSA](https://slsa.dev/spec/v1.0/levels) level 3. The source code as well as the package is [uploaded to VirusTotal](https://github.com/HotCakeX/Harden-Windows-Security/actions/workflows/VirusTotal.yml) automatically. Also [GitHub's CodeQL Advanced workflow](https://github.com/HotCakeX/Harden-Windows-Security/actions/workflows/codeql.yml) with extended security model scans the entire repository. All of the dependencies of any project in this repository are uploaded to GitHub and are available in the [Dependency Graph](https://github.com/HotCakeX/Harden-Windows-Security/network/dependencies).

> [!NOTE]\
> [United States Veteran Affairs (VA) Technical Reference Model regarding AppControl Manager.](https://www.oit.va.gov/Services/TRM/ToolPage.aspx?tid=16938)

Security is paramount when selecting any application designed to safeguard your systems. The last thing you want is a security-focused tool that inadvertently expands your attack surface or one that doesn't prioritize security at its core.

AppControl Manager is engineered with a security-first approach from the ground up. It's crafted specifically for defense teams, yet its design has been rigorously shaped with a keen awareness of potential offensive strategies, ensuring resilience against emerging threats.

* The AppControl Manager does not rely on any 3rd party component or dependency. All the logics are built securely and specifically for the app.

* Any file(s) the AppControl Manager ever produces, uses or expects is only from an Administrator-protected location in `C:\Program Files\AppControl Manager`.

* The AppControl Manager supports [process mitigations / Exploit Protections](https://learn.microsoft.com/defender-endpoint/exploit-protection-reference) such as: `Blocking low integrity images`, `Blocking remote images`, `Blocking untrusted fonts`, `Strict Control Flow Guard`, `Disabling extension points`, `Export Address Filtering`, `Hardware enforced stack protection`, `Import Address Filtering`, `Validate handle usage`, `Validate stack integrity`, `Code integrity guard`.

* The AppControl Manager always uses the latest .NET SDK and NuGet package versions, ensuring all the security patches released by Microsoft will be included.

* AppControl Manager leverages [MSAL from Microsoft](https://learn.microsoft.com/entra/identity-platform/msal-overview) to manage Microsoft 365 authentications. This industry-standard library adheres to best practices for secure authentication token management.

### Code Review

The codebase is extensively and thoughtfully documented, enabling reviewers to trace logic, validate control flows, and assess security-relevant decisions with minimal friction. I remain fully available to clarify design rationale, threat assumptions, or implementation details whenever deeper scrutiny is desired.

<br>

### Why Do Certain Features of The AppControl Manager Require Administrator Privileges?

* AppControl Manager operates exclusively within the "AppControl Manager" directory located in the `Program Files` directory for all read and write operations. No data is accessed or modified outside this directory. This design ensures that non-elevated processes, unauthorized software, or unprivileged malware on the system cannot alter the policies you create, the certificates you generate, or the CIP binary files you deploy.

* AppControl Manager employs MediumIL (Medium Integrity Level) when running as an Administrator, ensuring that non-elevated processes cannot access its memory or attach debuggers. Given that the app handles sensitive information—such as Microsoft 365 authentication tokens stored in private variables—this design decision safeguards these tokens from unauthorized, unelevated access or tampering.

* Administrator privileges are required for scanning Code Integrity and AppLocker logs. These scans are integral to several application functions, providing enhanced insights and enabling the generation of precise supplemental policies tailored to your needs.

* Deploying, removing, modifying, or checking the status of policies also necessitates Administrator privileges to ensure secure and reliable execution of these operations.

* Creating scheduled tasks that run as SYSTEM account requires Administrator privilege. This feature is used in places such as [Creating auto-update task for Microsoft Recommended driver block rules](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-App-Control-Policy) or when [Allowing new apps](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Allow-New-Apps).

<br>

### Where Are The Temporary Files Saved To?

Every new instance of the app that is launched creates a new `StagingArea` directory in the location below (if needed) with the Date and Time of that moment appended to it:

```
C:\Program Files\AppControl Manager\StagingArea[+ current Date Time]
```

Additionally, each applicable feature of the AppControl Manager that you start using will generate a uniquely named subdirectory within the `StagingArea` to store its temporary files (if needed). Upon closing the application, the entire StagingArea directory, along with its contents, will be automatically deleted. These files are utilized by the application for tasks such as creating policies, storing temporary scan results, and other related functions.

<br>

## Where Is The User Configurations Directory?

The User Configurations directory is located in the following location:

```
C:\Program Files\AppControl Manager
```

Everything the AppControl Manager creates/generates will be saved in that directory ***or one of its sub-directories***, such as:

* XML policy files
* CIP files
* Generated certificates
* Logs
* User Configurations JSON file
* Temporary files (Staging Areas)

<br>

## Which URLs does the AppControl Manager Connect To?

Here is the complete list of all of the URLs the AppControl Manager application connects to ***(or is mentioned in the User Interface)*** with proper justification for each of them.

* **[Privacy Policy for the AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Privacy-Policy-for-the-AppControl-Manager)**

<br>

<div align="center">

| URL | Justification                   |
|:--------:|:-----------------------------:|
| https://aka.ms/VulnerableDriverBlockList | To download the Microsoft Recommended Drivers Block List |
| https://api.github.com/repos/MicrosoftDocs/windows-itpro-docs/commits | To check the latest commit details of the Microsoft Recommended Drivers Block List and display them to the user on the UI |
| https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/refs/heads/public/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol.md | Source for the Microsoft Recommended User-Mode Block Rules |
| https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/refs/heads/public/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules.md | Source for the Microsoft Recommended Drivers Block Rules |
| https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/refs/heads/main/AppControl%20Manager/MSIXBundleDownloadURL.txt | The file on this repository that contains the download link to the latest version of the AppControl Manager. That text file is updated via automated GitHub action workflow that securely builds and uploads the MSIXBundle package to the GitHub releases. |
| https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/refs/heads/main/AppControl%20Manager/version.txt | The latest available version of the AppControl Manager application. That text file is updated via automated GitHub action workflow that securely builds and uploads the MSIXBundle package to the GitHub releases. |
| https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction | The link that opens in the GitHub documentations page in the app via the built-in WebView 2 |
| https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/appcontrol | The link that opens in the Microsoft documentations page in the app via the built-in WebView 2 |
| https://github.com/HotCakeX/Harden-Windows-Security/releases | During the update process, this link that is for the GitHub releases will be displayed on the update page as a quick way to read the release notes |
| https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager | Will be displayed on the Update page when a new version is available and being downloaded |
| https://github.com/HotCakeX/Harden-Windows-Security/issues/new/choose | Link for the "Send Feedback" button at the bottom of the about section in settings |
| https://github.com/HotCakeX/Harden-Windows-Security | Mentioned in the Links section at the bottom of the About section in Settings |
| https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager | Mentioned in the Links section at the bottom of the About section in Settings |
| https://spynetgirl.github.io/ | Mentioned in the Links section at the bottom of the About section in Settings |
| https://www.youtube.com/@hotcakex | Mentioned in the Links section at the bottom of the About section in Settings |
| https://x.com/CyberCakeX | Mentioned in the Links section at the bottom of the About section in Settings |
| https://icons8.com | Mentioned in the Links section at the bottom of the About section in Settings as credit |
| https://graph.microsoft.com | Used when signing into your Azure tenant for uploading policies to Intune |

</div>

<br>

## CommandLine Interface (CLI) Support

The AppControl Manager can be launched via command line for advanced users and automation scenarios. Below are the supported commands and their usage:

### Via Execution Alias

* #### Open an App Control policy in the Policy Editor

```
AppControl.exe --action=PolicyEditor --file="C:\Path\Policy.xml"
```
```
AppControl.exe --action=PolicyEditor --file="C:\Path\Policy.cip"
```

* #### View File Signature

```
AppControl.exe --action=FileSignature --file="C:\Path\SomeFile.exe"
```

* #### Get Code Integrity Hashes

```
AppControl.exe --action=FileHashes --file="C:\Path\SomeFile.exe"
```

* #### Deploy the RMM (Remote Monitoring and Management) Software Blocking Policy In Audit Mode

```
AppControl.exe --action=DeployRMMAuditPolicy
```

* #### Deploy the RMM (Remote Monitoring and Management) Software Blocking Policy In Enforced Mode

```
AppControl.exe --action=DeployRMMBlockPolicy
```

<br>

### Via Protocol Activation (URI scheme)

* #### Open an App Control policy in the Policy Editor

```powershell
Start-Process 'appcontrol-manager: --action=PolicyEditor --file="C:\Program Files\AppControl Manager\AllowMicrosoft.CIP"'
```
```powershell
Start-Process 'appcontrol-manager: --action=PolicyEditor --file="C:\Program Files\AppControl Manager\AllowMicrosoft.xml"'
```

* #### View File Signature

```powershell
Start-Process "appcontrol-manager: --action=FileSignature --file=C:\Path\SomeFile.exe"
```

* #### Get Code Integrity Hashes

```powershell
Start-Process "appcontrol-manager: --action=FileHashes --file=C:\Path\SomeFile.exe"
```

* #### Deploy the RMM (Remote Monitoring and Management) Software Blocking Policy In Audit Mode

```powershell
Start-Process "appcontrol-manager: --action=DeployRMMAuditPolicy"
```

* #### Deploy the RMM (Remote Monitoring and Management) Software Blocking Policy In Enforced Mode

```powershell
Start-Process "appcontrol-manager: --action=DeployRMMBlockPolicy"
```

<br>

### Via File Activation (Supported File Types Only)

* #### Opens a CIP file in the Policy Editor, same as double-clicking/tapping on the file in File Explorer.

```powershell
Invoke-Item -Path "C:\Program Files\AppControl Manager\AllowMicrosoft.CIP"
```

<br>

### Via AUMID (Application User Model ID) Activation

* #### Simply launches the AppControl Manager

```
explorer.exe shell:AppsFolder\VioletHansen.AppControlManager_ea7andspwdn10!App
```

<br>

## How To Install AppControl Manager Completely Offline?

1. Download [this PowerShell script](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Harden-Windows-Security.ps1).

2. Have `SignTool.exe`. You can find it in [here](https://www.nuget.org/packages/Microsoft.Windows.SDK.BuildTools/) if you don't already have it.

3. Download the latest MSIXBundle package of the AppControl Manager from the [GitHub releases](https://github.com/HotCakeX/Harden-Windows-Security/releases) or build it from [the source code](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/AppControl%20Manager) yourself.

4. Start an elevated PowerShell and import the script file via `Import-Module "Path to script file"`.

5. Use the following syntax to Install the AppControl Manager

```powershell
AppControl -MSIXBundlePath "Path To the MSIXBundle" -SignTool "Path to signtool.exe" -Verbose
```

<br>

## About the GitHub Packages Installation Process

> [!Warning]\
> The following only happens during GitHub installation method, when you run the one-liner script to install the AppControl Manager then the steps described below will automatically run. **However, if you choose to install the AppControl Manager from the [Microsoft Store](https://apps.microsoft.com/detail/9PNG1JDDTGP8) then the following steps are not necessary and will not be used.**

The installation process for AppControl Manager is uniquely streamlined. When you execute the PowerShell one-liner command mentioned above, it initiates [a file](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Harden-Windows-Security.ps1) containing the `AppControl` function, which serves as the bootstrapper script. This script is thoroughly documented, with detailed explanations and justifications for each step, as outlined below:

* The latest version of the AppControl Manager MSIXBundle package is securely downloaded from the GitHub release page, where it is built publicly with full artifact attestation and SBOMs.

* The `SignTool.exe` utility is sourced directly from Microsoft by retrieving the associated [NuGet package](https://www.nuget.org/packages/Microsoft.Windows.SDK.BuildTools/), ensuring a trusted origin.

* A secure, on-device code-signing certificate is then generated. This certificate, managed by the Microsoft-signed `SignTool.exe`, is used to sign the [MSIXBundle package](https://learn.microsoft.com/windows/msix/packaging-tool/bundle-msix-packages) obtained from GitHub.

* The private key of the certificate is non-exportable, never written on the disk and is securely discarded once signing is complete, leaving only the public key on the device to allow AppControl Manager to function properly on the system and prevent the certificate from being able to sign anything else.

* The entire process is designed to leave no residual files. Each time the script runs, any certificates from previous executions are detected and removed, ensuring a clean system.

<br>

## How To Build The AppControl Manager Locally?

You can build the AppControl Manager application directly from the source code locally on your device without using any 3rd party tools in a completely automated way.

It will create the MSIXBundle file containing the X64 and ARM64 MSIX packages. You can even optionally chain it with the [Bootstrapper script](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Harden-Windows-Security.ps1) to sign and install the application on your system at the end.

The build process will generate complete log files and you can use the [MSBuild Structured Log Viewer](https://learn.microsoft.com/shows/visual-studio-toolbox/msbuild-structured-log-viewer) to inspect them.

<details>

<summary>
✨ Click/Tap here to see the PowerShell code ✨
</summary>

<br>

```powershell
# Requires -Version 5.1
# Requires -RunAsAdministrator
function Build_ACM {
    param(
        [ValidateSet('Store', 'Self')]
        [string]$Type,
        [bool]$DownloadRepo,
        [bool]$InstallDeps,
        [bool]$Workflow,
        [bool]$UpdateWorkLoads,
        [bool]$Install,
        [bool]$Upload,
        [bool]$X64ONLY
    )

    [string]$PackageFamilyName = ''
    [string]$PackageHashAlgo = ''
    [string]$PackagePublisher = ''
    [string]$PackageName = ''
    [string]$PackagePhoneProductId = ''
    [string]$PackagePhonePublisherId = ''
    [string]$PackagePublisherDisplayName = ''

    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'LongPathsEnabled' -Value 1 -Force

    if ($Type -eq 'Store') {
        $PackageFamilyName = 'VioletHansen.AppControlManager_ea7andspwdn10'
        $PackageHashAlgo = 'SHA256'
        $PackagePublisher = 'CN=C62E63B6-6EF1-4F86-B80F-41A725BD0189'
        $PackageName = 'VioletHansen.AppControlManager'
        $PackagePhoneProductId = '4157a676-f4c2-4a8c-a511-b7fb2255c6f5'
        $PackagePhonePublisherId = '387464d6-cb95-4e5f-9c8f-f153a4855fb2'
        $PackagePublisherDisplayName = 'Violet Hansen'
    }
    else {
        $PackageFamilyName = 'AppControlManager_sadt7br7jpt02'
        $PackageHashAlgo = 'SHA512'
        $PackagePublisher = 'CN=SelfSignedCertForAppControlManager'
        $PackageName = 'AppControlManager'
        $PackagePhoneProductId = '199a23ec-7cb6-4ab5-ab50-8baca348bc79'
        $PackagePhonePublisherId = '00000000-0000-0000-0000-000000000000'
        $PackagePublisherDisplayName = 'SelfSignedCertForAppControlManager'
    }

    $ErrorActionPreference = 'Stop'
    # Start the stopwatch
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    [System.String]$script:AppControlManagerDirectory

    if ($DownloadRepo) {

        [System.String]$BranchName = 'main'
        [System.String]$RepoName = 'Harden-Windows-Security'
        [System.String]$RepoUrl = "https://github.com/HotCakeX/$RepoName/archive/refs/heads/$BranchName.zip"
        [System.String]$ZipPath = [System.IO.Path]::Combine($env:TEMP, "$RepoName.zip")
        [System.String]$InitialWorkingDirectory = $PWD.Path
        $script:AppControlManagerDirectory = [System.IO.Path]::Combine($InitialWorkingDirectory, "$RepoName-$BranchName", 'AppControl Manager')

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
        $null = winget install --id Microsoft.DotNet.SDK.10 --exact --accept-package-agreements --accept-source-agreements --uninstall-previous --force --source winget
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

    . $MSBuildPath 'eXclude\ComManager\ComManager.slnx' /p:Configuration=Release /p:Platform=x64 /target:"clean;Rebuild"

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building ComManager solution for X64. Exit Code: $LASTEXITCODE") }

    if (!$X64ONLY) {

        . $MSBuildPath 'eXclude\ComManager\ComManager.slnx' /p:Configuration=Release /p:Platform=arm64 /target:"clean;Rebuild"

        if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building ComManager solution for ARM64. Exit Code: $LASTEXITCODE") }
    }

    ### Shell

    [string]$newPFN = "$PackageFamilyName!App"
    [string]$content = Get-Content 'eXclude\Shell\Shell.cpp' -Raw
    [string]$content = $content -replace 'static constexpr LPCWSTR APP_CONTROL_MANAGER_PFN = L"[^"]*";', "static constexpr LPCWSTR APP_CONTROL_MANAGER_PFN = L`"$newPFN`";"
    $content | Set-Content 'eXclude\Shell\Shell.cpp' -NoNewline -Force

    . $MSBuildPath 'eXclude\Shell\Shell.slnx' /p:Configuration=Release /p:Platform=x64 /target:"clean;Rebuild"

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building the Shell solution for X64. Exit Code: $LASTEXITCODE") }

    if (!$X64ONLY) {

        . $MSBuildPath 'eXclude\Shell\Shell.slnx' /p:Configuration=Release /p:Platform=arm64 /target:"clean;Rebuild"

        if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building the Shell solution for ARM64. Exit Code: $LASTEXITCODE") }
    }

    #endregion


    #region --- RUST projects ---

    # Uncomment this once stable toolchain supports ehcont security feature, till then we use nightly only
    # rustup default stable
    rustup default nightly

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed setting Rust toolchain to Stable. Exit Code: $LASTEXITCODE") }

    if (!$X64ONLY) {

        rustup target add aarch64-pc-windows-msvc

        if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed adding aarch64-pc-windows-msvc target to Rust toolchain. Exit Code: $LASTEXITCODE") }

    }

    rustup target add x86_64-pc-windows-msvc

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed adding x86_64-pc-windows-msvc target to Rust toolchain. Exit Code: $LASTEXITCODE") }

    rustup update

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed updating Rust. Exit Code: $LASTEXITCODE") }

    cargo version

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed checking for Rust version. Exit Code: $LASTEXITCODE") }

    [string]$Current_Location = (Get-Location).Path

    Set-Location -Path '.\eXclude\Rust Interop Library'

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

    if (!$X64ONLY) {

        cargo build_arm64

        if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building ARM64 Rust Interop project. Exit Code: $LASTEXITCODE") }

    }

    Set-Location -Path $Current_Location

    #endregion

    #region XML Modifications

    [string]$CsProjFilePath = (Resolve-Path -Path '.\AppControl Manager.csproj').Path
    [string]$AppxManifestFilePath = (Resolve-Path -Path '.\Package.appxmanifest').Path

    # Adjust the Digest Algorithm based on the package source
    [xml]$ProjXMLContent = Get-Content -Path $CsProjFilePath -Force

    # Grab ALL existing nodes, wherever they are
    $nodes = $ProjXMLContent.SelectNodes('//AppxPackageSigningTimestampDigestAlgorithm')

    foreach ($node in $nodes) {
        $node.InnerText = $PackageHashAlgo
    }

    $ProjXMLContent.Save($CsProjFilePath)

    # Configure the Package Manifest Dits
    [xml]$AppxManifestContent = Get-Content -Path $AppxManifestFilePath -Force

    $ns = New-Object System.Xml.XmlNamespaceManager($AppxManifestContent.NameTable)
    $ns.AddNamespace('ns', 'http://schemas.microsoft.com/appx/manifest/foundation/windows10')
    $ns.AddNamespace('mp', 'http://schemas.microsoft.com/appx/2014/phone/manifest')

    # Update the <Identity> attributes
    $identity = $AppxManifestContent.SelectSingleNode('/ns:Package/ns:Identity', $ns)
    $identity.SetAttribute('Name', $PackageName)
    $identity.SetAttribute('Publisher', $PackagePublisher)

    # Update the <mp:PhoneIdentity> attributes
    $phoneId = $AppxManifestContent.SelectSingleNode('/ns:Package/mp:PhoneIdentity', $ns)
    $phoneId.SetAttribute('PhoneProductId', $PackagePhoneProductId)
    $phoneId.SetAttribute('PhonePublisherId', $PackagePhonePublisherId)

    # Update the <PublisherDisplayName> element
    $pubDisplay = $AppxManifestContent.SelectSingleNode('/ns:Package/ns:Properties/ns:PublisherDisplayName', $ns)
    $pubDisplay.InnerText = $PackagePublisherDisplayName

    $AppxManifestContent.Save($AppxManifestFilePath)

    #endregion XML Modifications

    # https://learn.microsoft.com/dotnet/core/tools/dotnet-build
    # https://learn.microsoft.com/visualstudio/msbuild/msbuild-command-line-reference
    # https://learn.microsoft.com/visualstudio/msbuild/common-msbuild-project-properties

    # Copy the X64 components to the directory before the build starts
    Copy-Item -Path '.\eXclude\Shell\x64\Release\Shell.dll' -Destination 'Shell' -Force

    Copy-Item -Path '.\eXclude\ComManager\x64\Release\ComManager.exe' -Destination '.\CppInterop\ComManager.exe' -Force

    # Generate for X64 architecture
    dotnet clean 'AppControl Manager.csproj' --configuration Release
    dotnet build 'AppControl Manager.csproj' --configuration Release --verbosity minimal /p:Platform=x64 /p:RuntimeIdentifier=win-x64

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building x64 AppControl Manager project. Exit Code: $LASTEXITCODE") }

    dotnet msbuild 'AppControl Manager.csproj' /t:Publish /p:Configuration=Release /p:RuntimeIdentifier=win-x64 /p:AppxPackageDir="MSIXOutputX64\" /p:GenerateAppxPackageOnBuild=true /p:Platform=x64 -v:minimal /p:MsPdbCmfExeFullpath=$mspdbcmfPath -bl:X64MSBuildLog.binlog

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed packaging x64 AppControl Manager project. Exit Code: $LASTEXITCODE") }

    if (!$X64ONLY) {

        # Copy the ARM64 components to the directory before the build starts
        Copy-Item -Path '.\eXclude\Shell\ARM64\Release\Shell.dll' -Destination 'Shell' -Force

        Copy-Item -Path '.\eXclude\ComManager\ARM64\Release\ComManager.exe' -Destination '.\CppInterop\ComManager.exe' -Force

        # Generate for ARM64 architecture
        dotnet clean 'AppControl Manager.csproj' --configuration Release
        dotnet build 'AppControl Manager.csproj' --configuration Release --verbosity minimal /p:Platform=ARM64 /p:RuntimeIdentifier=win-arm64

        if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building ARM64 AppControl Manager project. Exit Code: $LASTEXITCODE") }

        dotnet msbuild 'AppControl Manager.csproj' /t:Publish /p:Configuration=Release /p:RuntimeIdentifier=win-arm64 /p:AppxPackageDir="MSIXOutputARM64\" /p:GenerateAppxPackageOnBuild=true /p:Platform=ARM64 -v:minimal /p:MsPdbCmfExeFullpath=$mspdbcmfPath -bl:ARM64MSBuildLog.binlog

        if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed packaging ARM64 AppControl Manager project. Exit Code: $LASTEXITCODE") }
    }

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
    [System.String]$FinalMSIXX64Path = Get-MSIXFile -BasePath ([System.IO.Path]::Combine($PWD.Path, 'MSIXOutputX64')) -FolderPattern 'AppControl Manager_\d+\.\d+\.\d+\.\d+_x64_Test' -FileNamePattern 'AppControl Manager_\d+\.\d+\.\d+\.\d+_x64\.msix' -ErrorMessageFolder 'Could not find the directory for X64 MSIX file' -ErrorMessageFile 'Could not find the X64 MSIX file'
    [System.String]$FinalMSIXX64Name = [System.IO.Path]::GetFileName($FinalMSIXX64Path)
    [System.String]$FinalMSIXX64SymbolPath = Get-MSIXFile -BasePath ([System.IO.Path]::Combine($PWD.Path, 'MSIXOutputX64')) -FolderPattern 'AppControl Manager_\d+\.\d+\.\d+\.\d+_x64_Test' -FileNamePattern 'AppControl Manager_\d+\.\d+\.\d+\.\d+_x64\.appxsym' -ErrorMessageFolder 'Could not find the directory for X64 symbol file' -ErrorMessageFile 'Could not find the X64 symbol file'
    [System.String]$FinalMSIXX64SymbolName = [System.IO.Path]::GetFileName($FinalMSIXX64SymbolPath)
    #endregion

    if (!$X64ONLY) {

        #region Finding ARM64 outputs
        [System.String]$FinalMSIXARM64Path = Get-MSIXFile -BasePath ([System.IO.Path]::Combine($PWD.Path, 'MSIXOutputARM64')) -FolderPattern 'AppControl Manager_\d+\.\d+\.\d+\.\d+_arm64_Test' -FileNamePattern 'AppControl Manager_\d+\.\d+\.\d+\.\d+_arm64\.msix' -ErrorMessageFolder 'Could not find the directory for ARM64 MSIX file' -ErrorMessageFile 'Could not find the ARM64 MSIX file'
        [System.String]$FinalMSIXARM64Name = [System.IO.Path]::GetFileName($FinalMSIXARM64Path)
        [System.String]$FinalMSIXARM64SymbolPath = Get-MSIXFile -BasePath ([System.IO.Path]::Combine($PWD.Path, 'MSIXOutputARM64')) -FolderPattern 'AppControl Manager_\d+\.\d+\.\d+\.\d+_arm64_Test' -FileNamePattern 'AppControl Manager_\d+\.\d+\.\d+\.\d+_arm64\.appxsym' -ErrorMessageFolder 'Could not find the directory for ARM64 symbol file' -ErrorMessageFile 'Could not find the ARM64 symbol file'
        [System.String]$FinalMSIXARM64SymbolName = [System.IO.Path]::GetFileName($FinalMSIXARM64SymbolPath)
        #endregion

    }

    #region Detect and Validate File Versions
    [System.Text.RegularExpressions.Regex]$versionRegexX64 = [System.Text.RegularExpressions.Regex]::New('AppControl Manager_(\d+\.\d+\.\d+\.\d+)_x64\.msix')

    if (!$X64ONLY) {

        [System.Text.RegularExpressions.Regex]$versionRegexARM64 = [System.Text.RegularExpressions.Regex]::New('AppControl Manager_(\d+\.\d+\.\d+\.\d+)_arm64\.msix')
    }

    [System.Text.RegularExpressions.Match]$MatchX64 = $versionRegexX64.Match($FinalMSIXX64Name)

    if (!$X64ONLY) {

        [System.Text.RegularExpressions.Match]$MatchARM64 = $versionRegexARM64.Match($FinalMSIXARM64Name)

    }

    if (!$MatchX64.Success) {
        throw [System.InvalidOperationException]::New('Could not detect version from X64 file name')
    }

    if (!$X64ONLY) {

        if (!$MatchARM64.Success) {
            throw [System.InvalidOperationException]::New('Could not detect version from ARM64 file name')
        }
    }

    [System.String]$versionX64 = $MatchX64.Groups[1].Value

    if (!$X64ONLY) {

        [System.String]$versionARM64 = $MatchARM64.Groups[1].Value


        if ($versionX64 -ne $versionARM64) {
            throw [System.InvalidOperationException]::New('The versions in X64 and ARM64 files do not match')
        }

    }

    # Craft the file name for the MSIX Bundle file
    [System.String]$FinalBundleFileName = "AppControl Manager_$versionX64.msixbundle"
    #endregion

    # Creating the directory where the MSIX packages will be copied to
    [System.String]$MSIXBundleOutput = [System.IO.Directory]::CreateDirectory([System.IO.Path]::Combine($script:AppControlManagerDirectory, 'MSIXBundleOutput')).FullName

    [System.IO.File]::Copy($FinalMSIXX64Path, [System.IO.Path]::Combine($MSIXBundleOutput, $FinalMSIXX64Name), $true)

    if (!$X64ONLY) {

        [System.IO.File]::Copy($FinalMSIXARM64Path, [System.IO.Path]::Combine($MSIXBundleOutput, $FinalMSIXARM64Name), $true)

    }

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

    if (!$X64ONLY) {

        Write-Host -Object "ARM64 MSIX File Path: $FinalMSIXARM64Path" -ForegroundColor Cyan
        Write-Host -Object "ARM64 MSIX File Name: $FinalMSIXARM64Name" -ForegroundColor Cyan
        Write-Host -Object "ARM64 Symbols: $FinalMSIXARM64SymbolPath" -ForegroundColor Cyan

    }

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
        . "${Env:RUNNER_TEMP}\sbom-tool.exe" generate -b $MSIXBundleOutput -bc .\ -pn 'AppControl Manager' -ps 'Violet Hansen' -pv $MSIXVersion -nsb 'https://github.com/HotCakeX/Harden-Windows-Security' -V Verbose -gt true -li true -pm true -D true -lto 80

        # Saving the details of the SBOM file
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "SBOM_PATH=$MSIXBundleOutput/_manifest/spdx_2.2/manifest.spdx.json"
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value 'SBOM_NAME=manifest.spdx.json'
    }

    if ($Install -and $PackageFamilyName -eq 'AppControlManager_sadt7br7jpt02') {
        (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security.ps1') + "AppControl -Verbose -MSIXBundlePath '$MSIXBundle'" | Invoke-Expression
    }

    if ($Upload) {
        dotnet clean '.\eXclude\PartnerCenter\PartnerCenter.slnx' --configuration Release
        dotnet build '.\eXclude\PartnerCenter\PartnerCenter.slnx' --configuration Release --verbosity minimal
        dotnet msbuild '.\eXclude\PartnerCenter\PartnerCenter.slnx' /p:Configuration=Release /p:Platform=x64 /p:PublishProfile=win-x64 /t:Publish -v:minimal

        [System.String]$TokenEndpoint = $env:PARTNERCENTER_TOKENENDPOINT
        [System.String]$ClientId = $env:PARTNERCENTER_CLIENTID
        [System.String]$ClientSecret = $env:PARTNERCENTER_CLIENTSECRET
        [System.String]$ApplicationId = $env:PARTNERCENTER_APPLICATIONID

        [System.String]$PackageFilePath = $MSIXBundle
        [System.String]$ReleaseNotesFilePath = (Resolve-Path -Path ReleaseNotes.txt).Path

        . '.\eXclude\PartnerCenter\X64Output\PartnerCenter.exe' $TokenEndpoint $ClientId $ClientSecret $ApplicationId $PackageFilePath $ReleaseNotesFilePath
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

# For GitHub workflow 1
# Build_ACM -Type Self -DownloadRepo $false -InstallDeps $true -Workflow $true -UpdateWorkLoads $false -Install $false -Upload $false -X64ONLY $false
# For GitHub workflow 2
# Build_ACM -Type Store -DownloadRepo $false -InstallDeps $true -Workflow $true -UpdateWorkLoads $false -Install $false -Upload $true -X64ONLY $false
# Example of building the app from the source code and installing it on a clean system with self-signed certificate
# Build_ACM -Type Self -DownloadRepo $true -InstallDeps $true -Workflow $false -UpdateWorkLoads $false -Install $true -Upload $false -X64ONLY $false
# Example of building the app from the source code on a clean system and uploading it to the Partner Center
# Build_ACM -Type Store -DownloadRepo $true -InstallDeps $true -Workflow $false -UpdateWorkLoads $false -Install $false -Upload $true -X64ONLY $false
# Local Test - X64 only
# Build_ACM -Type Self -DownloadRepo $false -InstallDeps $false -Workflow $false -UpdateWorkLoads $false -Install $false -Upload $false -X64ONLY $true
# Local Test - ARM64 + X64
# Build_ACM -Type Self -DownloadRepo $false -InstallDeps $false -Workflow $false -UpdateWorkLoads $false -Install $false -Upload $false -X64ONLY $false

```

<br>

</details>

<br>
