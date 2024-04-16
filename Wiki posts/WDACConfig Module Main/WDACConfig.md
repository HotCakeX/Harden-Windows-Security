# WDACConfig (Windows Defender Application Control) Module

[**WDACConfig**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) is an advanced PowerShell module designed with the aim of automating [Application and File whitelisting in Windows](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/wdac) using Windows Defender Application Control (App Control for Business Policies). [You can always find its source code on GitHub](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/WDACConfig) and Install it from [**PowerShell Gallery**](https://www.powershellgallery.com/packages/WDACConfig/).

This page is also available [on my website.](https://spynetgirl.github.io/WDACConfig%20Module/WDACConfig/)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Requirements

* PowerShell Core latest version

    * Install from [GitHub](https://github.com/PowerShell/PowerShell/releases/latest) or [Microsoft Store](https://www.microsoft.com/store/productid/9MZ1SNWT0N5D)

* Windows 11 latest version
* Administrator Privileges
* Internet Connection (for periodic update checks)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Features

* Uses the [official documented methods of the ConfigCI module](https://learn.microsoft.com/en-us/powershell/module/configci/).

* Checks for new version periodically and updates itself automatically when necessary.

    - Update check can be skipped with `-SkipVersionCheck`.

* Actively trying to design it with [Microsoft Security Development Lifecycle (SDL)](https://www.microsoft.com/en-us/securityengineering/sdl/) guidelines in mind.

* The module goes through Extended Validation before each update is released to make sure everything works perfectly.

* The module can be used for managing both local systems and systems in Azure VMs.

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

## WDACConfig Module's Table of Content

|  Cmdlet Guide  |     Usage      | PowerShell Console Help |
|    :---:       |     :---:      |          :---:          |
| [New-WDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig) | Mainly for creating and deploying WDAC policies | `Get-Help New-WDACConfig` |
| [New-SupplementalWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-SupplementalWDACConfig) | To create and deploy Supplemental policies | `Get-Help New-SupplementalWDACConfig` |
| [Remove-WDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Remove-WDACConfig) | To remove deployed WDAC policies | `Get-Help Remove-WDACConfig` |
| [Edit-WDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-WDACConfig) | To edit deployed unsigned WDAC policies | `Get-Help Edit-WDACConfig` |
| [Edit-SignedWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-SignedWDACConfig) | To edit deployed signed WDAC policies | `Get-Help Edit-SignedWDACConfig` |
| [Deploy-SignedWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-SignedWDACConfig) | To sign and deploy WDAC policies | `Get-Help Deploy-SignedWDACConfig` |
| [Confirm-WDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Confirm-WDACConfig) | To confirm deployment and check the status of WDAC policies | `Get-Help Confirm-WDACConfig` |
| [New-DenyWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-DenyWDACConfig) | To create a deny mode WDAC policy | `Get-Help New-DenyWDACConfig` |
| [Set-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig) | To add or edit user configurations for common WDACConfig parameters | `Get-Help Set-CommonWDACConfig` |
| [New-KernelModeWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New%E2%80%90KernelModeWDACConfig)  | To create a Strict Kernel mode WDAC policy for [total BYOVD protection](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection) | `Get-Help New-KernelModeWDACConfig` |
| [Get-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Get-CommonWDACConfig) | To display or fetch user configurations for common WDACConfig parameters | `Get-Help Get-CommonWDACConfig` |
| [Invoke-WDACSimulation](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Invoke-WDACSimulation) | To simulate a WDAC policy deployment quickly | `Get-Help Invoke-WDACSimulation` |
| [Remove-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Remove-CommonWDACConfig) | To remove user configurations for common WDACConfig parameters | `Get-Help Remove-CommonWDACConfig` |
| [Assert-WDACConfigIntegrity](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Assert-WDACConfigIntegrity) | To ascertain that the files in your local WDACConfig folder are identical to the ones in the cloud | `Get-Help Assert-WDACConfigIntegrity` |
| [Build-WDACCertificate](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Build-WDACCertificate) | To create proper code signing certificates for WDAC policy signing | `Get-Help Build-WDACCertificate` |
| [Test-CiPolicy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Test-CiPolicy) | Tests a Code Integrity (WDAC) Policy XML file against the Schema and shows the signers in a signed `.CIP` files | `Get-Help Test-CiPolicy` |


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

## Video Guides

<br>

<a href="https://youtu.be/oyz0jFzOOGA?si=tJbFbzRJNy79lUo7"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/MDE%20Advanced%20Hunting%20YouTube%20Thumbnail.png" alt="MDE AH Demo"></a>

<a href="https://youtu.be/RSYJ64BlS9Y?si=t6TlcYzsMwteG1M9"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/YouTube%20Video%20Thumbnails/With%20YouTube%20play%20button/How%20to%20Create%20and%20Deploy%20a%20Signed%20WDAC%20Policy.png" alt="Create and Deploy Signed WDAC Windows Defender Policy YouTube Guide"></a>

<br>

<a href="https://youtu.be/KD0zUb2GCyk?si=_g09D0yF5lTN1NLO"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/YouTube%20Video%20Thumbnails/With%20YouTube%20play%20button/WDAC%20policy%20for%20Fully%20Managed%20device%20-%20Variant%201.png" alt="WDAC policy for Fully Managed device - Variant 1 YouTube Guide"></a>

<br>

<a href="https://youtu.be/QpJt255pHDE?si=eLSRkAQXrkHK8SSh"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/YouTube%20Video%20Thumbnails/With%20YouTube%20play%20button/WDAC%20for%20Fully%20Managed%20Devices%20(2nd%20variant).png" alt="WDAC policy for Fully managed device - Variant 2 YouTube Guide"></a>

<br>

<a href="https://youtu.be/41_5ntFYghM?si=2PcCXI7gis6UAJh7"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/YouTube%20Video%20Thumbnails/With%20YouTube%20play%20button/WDAC%20policy%20for%20Fully%20managed%20device%20Variant%203.png" alt="WDAC policy for Fully managed device - Variant 3 YouTube Guide"></a>

<br>

<a href="https://youtu.be/AgqhcPV9aPY?si=l_2QPbEAKKVhb9z6"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/YouTube%20Video%20Thumbnails/With%20YouTube%20play%20button/WDAC%20policy%20for%20Fully%20managed%20device%20Variant%204.png" alt="WDAC policy for Fully managed device - Variant 4 YouTube Guide"></a>

<br>

<a href="https://youtu.be/RgVf4p9ct90?si=mGdVCnqVlUN_FBWR"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/YouTube%20Video%20Thumbnails/With%20YouTube%20play%20button/WDAC%20policy%20for%20Lightly%20managed%20device.png" alt="WDAC policy for Lightly managed device YouTube Guide"></a>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Feedback and Feature Request

If there are any feedback or feature requests regarding this module, please [open a new discussion/issue on GitHub.](https://github.com/HotCakeX/Harden-Windows-Security)

<br>
