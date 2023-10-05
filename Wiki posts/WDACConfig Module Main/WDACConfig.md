# WDACConfig (Windows Defender Application Control) Module

[**WDACConfig**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) is an advanced PowerShell module designed with the aim of automating [Application and File whitelisting in Windows](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/wdac) using Windows Defender Application Control. [**You can always find its source code on GitHub**](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/WDACConfig) and Install it from [**PowerShell Gallery**](https://www.powershellgallery.com/packages/WDACConfig/).

This page is also available [on my website.](https://spynetgirl.github.io/WDACConfig%20Module/WDACConfig/)

## Requirements

* [PowerShell 7.3.6 and above](https://github.com/PowerShell/PowerShell/releases)
* Windows 11 version 22H2 and above
* Administrator Privileges
* Internet Connection

## Features

* Uses the [official documented methods on Microsoft websites](https://learn.microsoft.com/en-us/powershell/module/configci/) only.
* Checks for new version when you run it and will update itself automatically if necessary.
  - (This can be bypassed if `-SkipVersionCheck` is used, but **not recommended**).
* Actively trying to design it with [Microsoft Security Development Lifesycle (SDL)](https://www.microsoft.com/en-us/securityengineering/sdl/) guidelines in mind.
* The module goes through Extended Validation before each update is released to make sure everything works perfectly.

<br>

## How To Use It

### Install the module

```powershell
Install-Module -Name WDACConfig -Force
```

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
| [New-KernelModeWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New%E2%80%90KernelModeWDACConfig)  | To create a Strict Kernel mode WDAC policy for total BYOVD protection | `Get-Help New-KernelModeWDACConfig` |
| [Get-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Get-CommonWDACConfig) | To display or fetch user configurations for common WDACConfig parameters | `Get-Help Get-CommonWDACConfig` |
| [Invoke-WDACSimulation](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Invoke-WDACSimulation) | To simulate a WDAC policy deployment quickly | `Get-Help Invoke-WDACSimulation` |
| [Remove-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Remove-CommonWDACConfig) | To remove user configurations for common WDACConfig parameters | `Get-Help Remove-CommonWDACConfig` |

<br>

## Video Guides

<br>

<a href="https://youtu.be/RSYJ64BlS9Y?si=t6TlcYzsMwteG1M9"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/YouTube%20Video%20Thumbnails/With%20YouTube%20play%20button/How%20to%20Create%20and%20Deploy%20a%20Signed%20WDAC%20Policy.png"></a>

<br>

<a href="https://youtu.be/KD0zUb2GCyk?si=_g09D0yF5lTN1NLO"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/YouTube%20Video%20Thumbnails/With%20YouTube%20play%20button/WDAC%20policy%20for%20Fully%20Managed%20device%20-%20Variant%201.png"></a>
<br>

<br>

<a href="https://youtu.be/QpJt255pHDE?si=eLSRkAQXrkHK8SSh"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/YouTube%20Video%20Thumbnails/With%20YouTube%20play%20button/WDAC%20for%20Fully%20Managed%20Devices%20(2nd%20variant).png"></a>

<br>

<a href="https://youtu.be/41_5ntFYghM?si=2PcCXI7gis6UAJh7"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/YouTube%20Video%20Thumbnails/With%20YouTube%20play%20button/WDAC%20policy%20for%20Fully%20managed%20device%20Variant%203.png"></a>

<br>

<a href="https://youtu.be/AgqhcPV9aPY?si=l_2QPbEAKKVhb9z6"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/YouTube%20Video%20Thumbnails/With%20YouTube%20play%20button/WDAC%20policy%20for%20Fully%20managed%20device%20Variant%204.png"></a>

<br>

<a href="https://youtu.be/RgVf4p9ct90?si=mGdVCnqVlUN_FBWR"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/YouTube%20Video%20Thumbnails/With%20YouTube%20play%20button/WDAC%20policy%20for%20Lightly%20managed%20device.png"></a>

<br>

## Feedback and Feature Request

If there are any feedback or feature requests regarding this module, please [open a new discussion/issue on GitHub.](https://github.com/HotCakeX/Harden-Windows-Security)
