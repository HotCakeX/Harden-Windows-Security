# WDACConfig (Windows Defender Application Control) Module

[**WDACConfig**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) is an advanced PowerShell module designed with the aim of automating [Application and File whitelisting in Windows](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol) using App Control for Business. [You can always find its source code on GitHub](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/WDACConfig) and Install it from [**PowerShell Gallery**](https://www.powershellgallery.com/packages/WDACConfig/).

This page is also available [on my website.](https://spynetgirl.github.io/WDACConfig%20Module/WDACConfig/)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Requirements

* PowerShell Core latest version

    * Install from [GitHub](https://github.com/PowerShell/PowerShell/releases/latest) or [Microsoft Store](https://www.microsoft.com/store/productid/9MZ1SNWT0N5D)

* Windows 11 latest version
* Administrator Privileges
* Internet Connection (for periodic update checks that happen every 30 minutes)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Features

* Uses the [official documented methods of the ConfigCI module](https://learn.microsoft.com/en-us/powershell/module/configci/).

* Checks for new version periodically and updates itself automatically when necessary.

    - Update check can be skipped with `-SkipVersionCheck`.

* Actively trying to design it with [Microsoft Security Development Lifecycle (SDL)](https://www.microsoft.com/en-us/securityengineering/sdl/) guidelines in mind.

* The module goes through Extended Validation before each update is released to make sure everything works perfectly.

* The module can be used for managing local systems, remote systems and Azure VMs.

* Use `-Verbose` common parameter with each cmdlet of the WDACConfig module to see extra details and what's happening under the hood.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Install The Module

```powershell
Install-Module -Name 'WDACConfig' -Scope 'AllUsers' -Force
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Video Guides

| Video Link  | Description |
| :---: | :---: |
| <a href="https://youtu.be/oyz0jFzOOGA?si=tJbFbzRJNy79lUo7"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/MDE%20Advanced%20Hunting%20YouTube%20Thumbnail.png" alt="MDE AH Demo"></a> | [Microsoft Defender For Endpoint Advanced Hunting With WDACConfig Module](https://youtu.be/oyz0jFzOOGA?si=tJbFbzRJNy79lUo7) |
| <a href="https://www.youtube.com/watch?v=cp7TaTNPZE0"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/YouTube%20Thumbnail%20-%20Sandboxing-like%20capabilities%20of%20WDAC%20Policies.png" alt="Sandboxing-like capabilities in the App Control Policies"></a> | [Sandboxing-like capabilities in the App Control Policies](https://www.youtube.com/watch?v=cp7TaTNPZE0) |
| <a href="https://www.youtube.com/watch?v=JSwrfe9zYY4"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/YouTube%20Thumbnail%20-%20create%2C%20audit%20and%20deploy%20WDAC%20policies.png" alt="Create, Deploy & Audit App Control Policies"></a> | [Create, Deploy & Audit App Control Policies](https://www.youtube.com/watch?v=JSwrfe9zYY4) |
| <a href="https://www.youtube.com/watch?v=hNpzYlOMCys"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/YouTube%20Thumbnail%20-%20secure%20settings%20in%20WDAC%20Policies.png" alt="How To Set And Query Secure Settings in App Control Policies"></a> | [How To Set And Query Secure Settings in App Control Policies](https://www.youtube.com/watch?v=hNpzYlOMCys) |
| <a href="https://www.youtube.com/watch?v=nZ5c9ceaEwA"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/YouTube%20Thumbnal%20-%20deploy%20Signed%20WDAC%20policies.png" alt="How To Create And Deploy Signed App Control Policies"></a> | [How To Create And Deploy Signed App Control Policies](https://www.youtube.com/watch?v=nZ5c9ceaEwA) |
| <a href="https://www.youtube.com/watch?v=A0bKDaeYomg"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Simulating%20Application%20Control%20(WDAC)%20Policies%20Using%20The%20WDACConfig%20Module%20-%20low%20res.png" alt="Simulating App Control Deployment in Windows"></a> | [Simulating App Control Deployment in Windows](https://www.youtube.com/watch?v=A0bKDaeYomg) |
| <a href="https://youtu.be/RSYJ64BlS9Y?si=t6TlcYzsMwteG1M9"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/YouTube%20Video%20Thumbnails/With%20YouTube%20play%20button/How%20to%20Create%20and%20Deploy%20a%20Signed%20WDAC%20Policy.png" alt="Create and Deploy Signed WDAC Windows Defender Policy YouTube Guide"></a> | [Create Code Signing Certificate Using Windows Server](https://youtu.be/RSYJ64BlS9Y?si=t6TlcYzsMwteG1M9) |

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## WDACConfig Module's Table of Content

|  Cmdlet Guide  |     Usage      | PowerShell Console Help |
|    :---:       |     :---:      |          :---:          |
| [New-WDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig) | Mainly for creating and deploying App Control policies | `Get-Help New-WDACConfig` |
| [New-SupplementalWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-SupplementalWDACConfig) | To create and deploy Supplemental policies | `Get-Help New-SupplementalWDACConfig` |
| [Remove-WDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Remove-WDACConfig) | To remove deployed App Control policies | `Get-Help Remove-WDACConfig` |
| [Edit-WDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-WDACConfig) | To edit deployed unsigned App Control policies | `Get-Help Edit-WDACConfig` |
| [Edit-SignedWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-SignedWDACConfig) | To edit deployed signed App Control policies | `Get-Help Edit-SignedWDACConfig` |
| [Deploy-SignedWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-SignedWDACConfig) | To sign and deploy App Control policies | `Get-Help Deploy-SignedWDACConfig` |
| [Confirm-WDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Confirm-WDACConfig) | To confirm deployment and check the status of App Control policies | `Get-Help Confirm-WDACConfig` |
| [New-DenyWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-DenyWDACConfig) | To create a deny mode App Control policy | `Get-Help New-DenyWDACConfig` |
| [Set-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig) | To add or edit user configurations for common WDACConfig parameters | `Get-Help Set-CommonWDACConfig` |
| [New-KernelModeWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New%E2%80%90KernelModeWDACConfig)  | To create a Strict Kernel mode App Control policy for [total BYOVD protection](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection) | `Get-Help New-KernelModeWDACConfig` |
| [Get-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Get-CommonWDACConfig) | To display or fetch user configurations for common WDACConfig parameters | `Get-Help Get-CommonWDACConfig` |
| [Invoke-WDACSimulation](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Invoke-WDACSimulation) | To simulate an App Control policy deployment quickly | `Get-Help Invoke-WDACSimulation` |
| [Remove-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Remove-CommonWDACConfig) | To remove user configurations for common WDACConfig parameters | `Get-Help Remove-CommonWDACConfig` |
| [Assert-WDACConfigIntegrity](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Assert-WDACConfigIntegrity) | To ascertain that the files in your local WDACConfig folder are identical to the ones in the cloud | `Get-Help Assert-WDACConfigIntegrity` |
| [Build-WDACCertificate](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Build-WDACCertificate) | To create proper code signing certificates for App Control policy signing | `Get-Help Build-WDACCertificate` |
| [Test-CiPolicy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Test-CiPolicy) | Tests a Code Integrity (App Control) Policy XML file against the Schema and shows the signers in a signed `.CIP` files | `Get-Help Test-CiPolicy` |
| [Get-CiFileHashes](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Get-CiFileHashes) | Calculates the Authenticode hash and first page hash of the PEs with SHA1 and SHA256 algorithms | `Get-Help Get-CiFileHashes` |
| [ConvertTo-WDACPolicy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/ConvertTo-WDACPolicy) | Multi-Purpose & Powerful functionalities such as converting local and MDE logs to App Control Policies | `Get-Help ConvertTo-WDACPolicy` |
| [Get-CIPolicySetting](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Get-CIPolicySetting) | Queries the Secure Settings among the deployed policies on the system | `Get-Help Get-CIPolicySetting` |

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## User Configurations Directory

The module stores user configurations and all of the outputs only in the following directory:

```
C:\Program Files\WDACConfig
```

It's an Admin-protected path that provides security against non-elevated users and processes.

<br>

### The Temporary Files Are Stored in the Following Directory

```
C:\Program Files\WDACConfig\StagingArea
```

Each cmdlet of the module creates a subdirectory in the StagingArea to store its temporary files. The subdirectory is named after the cmdlet's name. At the end of the cmdlet's execution, the temporary subdirectory is deleted, unless the `-Debug` parameter is used.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## About Automatic Parameters

A parameter with an **Automatic** value of True in the description means that the module will use its default value set by the [Set-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig) cmdlet. This simplifies the process and avoids redundancy. However, if an Automatic parameter has no value in User Configurations and you do not specify one in the command line, you will encounter an error requesting a value. Specifying a value for an Automatic parameter in the command line supersedes its default value in User Configurations, so the module will disregard the value of that parameter in the User Configurations file.

<br>

### The Logic Behind The -SignToolPath Parameter in the Module

1. If [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/) Signing Tools for Desktop Apps components is installed in the default location `C:\Program Files (x86)\Windows Kits`, then specifying `-SignToolPath` parameter isn't necessary as the SignTool.exe will be detected automatically.

2. If Windows SDK Signing Tools for Desktop Apps components is not installed in the default location or you want to manually browse for the signtool.exe, then make sure you either specify its path using `Set-CommonWDACConfig -SignToolPath` or use the `-SignToolPath` parameter.

3. If SignTool.exe path is available in user configurations then it will be automatically used.

4. Specifying `-SignToolPath` parameter explicitly on the command line takes priority over auto detection and value in the user configurations.

5. If SignTool.exe cannot be auto-detected and the user didn't specify it on the command line, you will receive a prompt to authorize the automatic download of the most recent SignTool.exe version from the official Microsoft servers. Upon confirmation, it will be saved in your user configurations and utilized by the cmdlet.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Feedback and Feature Request

If there are any feedback or feature requests regarding this module, please [open a new discussion/issue on GitHub.](https://github.com/HotCakeX/Harden-Windows-Security)

<br>
