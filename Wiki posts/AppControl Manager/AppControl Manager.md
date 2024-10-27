# AppControl Manager

AppControl Manager is a modern secure app that provides easy to use graphical user interface to mange App Control and Code Integrity on your device.

The goal is for AppControl manager to reach feature parity with the [WDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) Powershell module as fast as possible and then to surpass it with additional features and improvements.

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

More features will come very quickly in the near future.

<br>
