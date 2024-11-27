# AppControl Manager

AppControl Manager is a modern secure app that provides easy to use graphical user interface to manage App Control and Code Integrity on your device.

The short-term goal is for the AppControl manager to reach feature parity with the [WDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) Powershell module, as fast as possible, and then to surpass it with new unique features and improvements.

> [!IMPORTANT]\
> The AppControl Manager application is built publicly using a [GitHub action](https://github.com/HotCakeX/Harden-Windows-Security/actions/workflows/Build%20AppControl%20Manager%20MSIX%20Package.yml) and uploaded to the GitHub release. The action uses [Artifact Attestation](https://github.com/HotCakeX/Harden-Windows-Security/attestations) and [SBOM (Software Bill of Materials)](https://github.com/HotCakeX/Harden-Windows-Security/network/dependencies) generation to comply with [SLSA](https://slsa.dev/spec/v1.0/levels) level 2 and [security standards](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds). The source code as well as the package is [uploaded to Virus Total](https://github.com/HotCakeX/Harden-Windows-Security/actions/workflows/VirusTotal.yml) automatically. Also [GitHub's CodeQL Advanced workflow](https://github.com/HotCakeX/Harden-Windows-Security/actions/workflows/codeql.yml) with extended security model scans the entire repository.

<br>

## How To Install or Update The App

Use the following PowerShell [command](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Harden-Windows-Security.ps1) as Admin, it will automatically download the latest MSIX file from this repository's release page and install it for you.

> [!TIP]\
> The app includes an update section that allows you to check for update and install the new version securely with just a press of a button. It is a very convenient and non-intrusive update experience because when the app is updated, it won't restart itself, instead it will wait for you to close it and the next time you open it you will be automatically using the new version.

<br>

```powershell
(irm 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security.ps1')+'AppControl'|iex
```

<br>

Please feel free to open a discussion if you have any questions about the build process, security, how to use or have feedbacks.

<br>

## Preview of the App

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControlManager.gif" alt="AppControl Manager preview"/>

<br>

## Technical Details of The App

* Secure and transparent development and build process.
* Built using [WinUI3](https://learn.microsoft.com/en-us/windows/apps/winui/winui3/) / [XAML](https://github.com/microsoft/microsoft-ui-xaml) / [C#](https://learn.microsoft.com/en-us/dotnet/csharp/).
* Built using the latest [.NET](https://dotnet.microsoft.com).
* Powered by the [WinAppSDK](https://github.com/microsoft/WindowsAppSDK) (formerly Project Reunion).
* Packaged with the modern [MSIX](https://learn.microsoft.com/en-us/windows/msix/overview) format.
* Incorporates the [Mica](https://learn.microsoft.com/en-us/windows/apps/design/style/mica) material design for backgrounds.
* Adopts the Windows 11 [Fluent design system](https://fluent2.microsoft.design/components/windows).
* Fast execution and startup time.
* 0 required dependency.
* 0 Third-party library or file used.
* 0 Telemetry or data collection.
* 0 Windows Registry changes.
* 100% clean uninstallation.
* 100% open-source and free to use.

<br>

## Features Implemented So Far

* Creating, configuring and deploying AllowMicrosoft policy
* Creating, configuring and deploying SignedAndReputable policy (based on ISG)
* Creating and deploying Microsoft recommended driver block rules
* Creating and deploying Microsoft recommended user-mode block rules
* Checking for secure policy settings on the system
* Getting the Code Integrity hashes of the files (Authenticode hash and Page hash)
* Adding/Changing/Removing User Configurations
* Configure policy rule options
* View deployed policies on the system (with filtering search)
* Remove unsigned Base policies and signed/unsigned Supplemental policies from the system
* Quick access to App Control resources and documentations right within the app
* Self-updating the app
* Displaying advanced Code Integrity information about the system
* Complete App Control Simulation feature
* Create policy from Microsoft Defender for Endpoint Advanced Hunting
* Create policy from Local event logs
* Create policy from EVTX files
* Create policy by scanning local files
* Change application appearance in multiple ways
* Creating Supplemental Policy by scanning files and folders.
* Creating Supplemental policy by scanning certificate `.cer` files.
* Deploying XML and CIP files on the system.
* Build App Control compatible Code Signing Certificate.

More features will come very quickly in the near future.

<br>

## Security

Security is paramount when selecting any application designed to safeguard your systems. The last thing you want is a security-focused tool that inadvertently expands your attack surface or one that doesn't prioritize security at its core.

AppControl Manager is engineered with a security-first approach from the ground up. It's crafted specifically for defense teams, yet its design has been rigorously shaped with a keen awareness of potential offensive strategies, ensuring resilience against emerging threats.

* The AppControl Manager does not rely on any 3rd party component or dependency. All the logics are built securely and specifically for the app.

* Any file(s) the AppControl Manager ever produces, uses or expects is only from an Administrator-protected location in `C:\Program Files\WDACConfig`.

* The AppControl Manager supports [process mitigations / Exploit Protections](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference) such as: `Blocking low integrity images`, `Blocking remote images`, `Blocking untrusted fonts`, `Disabling extension points`, `Export Address Filtering`, `Hardware enforced stack protection`, `Import Address Filtering`, `Validate handle usage`, `Validate stack integrity` and so on.

* The AppControl Manager always uses the latest .NET and SDK versions, ensuring all the security patches released by Microsoft will be included.

<br>

## About the Installation Process

The installation process for AppControl Manager is uniquely streamlined. When you execute the PowerShell one-liner command mentioned above, it initiates [a file]((https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Harden-Windows-Security.ps1)) containing the `AppControl` function, which serves as the bootstrapper script. This script is thoroughly documented, with detailed explanations and justifications for each step, as outlined below:

* The latest version of the AppControl Manager MSIX package is securely downloaded from the GitHub release page, where it is built publicly with full artifact attestation and SBOMs.

* The `SignTool.exe` utility is sourced directly from Microsoft by retrieving the associated [Nuget package](https://www.nuget.org/packages/Microsoft.Windows.SDK.BuildTools/), ensuring a trusted origin.

* A secure, on-device code-signing certificate is then generated. This certificate, managed by the Microsoft-signed `SignTool.exe`, is used to sign the MSIX package obtained from GitHub.

* The private keys of the certificate are encrypted with a randomly generated, 100-character password during the signing process, which lasts only a few seconds. Once signing is complete, the private keys are securely discarded, leaving only the public keys on the device to allow AppControl Manager to function properly on the system and prevent the certificate from being able to sign anything else.

* The entire process is designed to leave no residual files. Each time the script runs, any certificates from previous executions are detected and removed, ensuring a clean system.

* Finally, the `AppControlManager.dll` and `AppControlManager.exe` files are added to the Attack Surface Reduction (ASR) exclusions to prevent ASR rules from blocking these newly released binaries. Previous version exclusions are also removed from the ASRs exclusions list to maintain a clean, streamlined setup for the user.

<br>

## Which URLs does the AppControl Manager Connect To?

Here is the complete list of all of the URLs the AppControl Manager application connects to ***(or is mentioned in the User Interface)*** with proper justification for each of them.

<br>

<div align="center">

| URL | Justification                   |
|:--------:|:-----------------------------:|
| https://api.nuget.org/v3-flatcontainer/ | To access Microsoft NuGet repository to download SignTool.exe |
| https://aka.ms/VulnerableDriverBlockList | To download the Microsoft Recommended Drivers Block List |
| https://api.github.com/repos/MicrosoftDocs/windows-itpro-docs/commits | To check the latest commit details of the Microsoft Recommended Drivers Block List and display them to the user on the UI |
| https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/refs/heads/public/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol.md | Source for the Microsoft Recommended USer-Mode Block Rules |
| https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/refs/heads/public/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules.md | Source for the Microsoft Recommended Drivers Block Rules |
| https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/refs/heads/main/AppControl%20Manager/DownloadURL.txt | The file on this repository that contains the download link to the latest version of the AppControl Manager. That text file is updated via automated GitHub action workflow that securely builds and uploads the MSIX package to the GitHub releases. |
| https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/refs/heads/main/AppControl%20Manager/version.txt | The latest available version of the AppControl Manager application. That text file is updated via automated GitHub action workflow that securely builds and uploads the MSIX package to the GitHub releases. |
| https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction | The link that opens in the GitHub documentations page in the app via the built-in WebView 2 |
| https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol | The link that opens in the Microsoft documentations page in the app via the built-in WebView 2 |
| https://github.com/HotCakeX/Harden-Windows-Security/issues/415 | A link to one of the GitHub issues |
| https://github.com/HotCakeX/Harden-Windows-Security/releases | During the update process, this link that is for the GitHub releases will be displayed on the update page as a quick way to read the release notes |
| https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager | Will be displayed on the Update page when a new version is available and being downloaded |
| https://github.com/HotCakeX/Harden-Windows-Security/issues/new/choose | Link for the "Send Feedback" button at the bottom of the about section in settings |
| https://github.com/HotCakeX/Harden-Windows-Security | Mentioned in the Links section at the bottom of the About section in Settings |
| https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager | Mentioned in the Links section at the bottom of the About section in Settings |
| https://spynetgirl.github.io/ | Mentioned in the Links section at the bottom of the About section in Settings |
| https://www.youtube.com/@hotcakex | Mentioned in the Links section at the bottom of the About section in Settings |
| https://x.com/CyberCakeX | Mentioned in the Links section at the bottom of the About section in Settings |

</div>

<br>
