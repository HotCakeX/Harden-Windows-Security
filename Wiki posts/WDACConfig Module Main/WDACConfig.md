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
Install-Module -Name 'WDACConfig' -Force
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

<br>

## Video Guides

<br>

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
