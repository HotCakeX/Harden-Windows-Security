# WDACConfig (Windows Defender Application Control) Module

[**WDACConfig**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) is an advanced PowerShell module designed with the aim of automating [Application and File whitelisting in Windows](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/wdac) using Windows Defender Application Control. [**You can always find its source code on GitHub**](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/WDACConfig) and Install it from [**PowerShell Gallery**](https://www.powershellgallery.com/packages/WDACConfig/).

This page is also available [on my website.](https://spynetgirl.github.io/WDACConfig%20Module/WDACConfig/)

## Requirements

* [PowerShell 7.3.4 and above](https://github.com/PowerShell/PowerShell/releases)
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

### VIDEO: How to Configure, Use and Setup **Unsigned** WDAC (Windows Defender Application Control) Automatically using WDACConfig PowerShell module

<br>

<p align="center">
  <a href="https://youtu.be/Wj3EEiMCqF0">
    <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/YouTubeLogoWDACUnsignedDemo.png" width="700"
         alt="YouTube Video showcase Unsigned WDAC Policies">
  </a>
  </p>

<br>

***

<br>

### VIDEO: How to Configure, Use and Setup **Signed** WDAC (Windows Defender Application Control) Automatically using WDACConfig PowerShell module

<br>

<p align="center">
  <a href="https://youtu.be/wAByFp-X-iM">
    <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/YouTubeLogoWDACSignedDemo.png" width="700"
         alt="YouTube Video showcase Signed WDAC Policies">
  </a>
  </p>

<br>

## How to use it

### Install the module

```powershell
Install-Module -Name WDACConfig -Force
```

<br>

**To get help and syntax on PowerShell console, type:**

```powershell
"Get-Command -Module WDACConfig"
"Get-Help New-WDACConfig"
"Get-Help New-SupplementalWDACConfig"
"Get-Help Remove-WDACConfig"
"Get-Help Edit-WDACConfig"
"Get-Help Edit-SignedWDACConfig"
"Get-Help Deploy-SignedWDACConfig"
"Get-Help Confirm-WDACConfig"
"Get-Help New-DenyWDACConfig"
"Get-Help Set-CommonWDACConfig"
"Get-help New-KernelModeWDACConfig"
"Get-help Get-CommonWDACConfig"
"Get-help Invoke-WDACSimulation"
```

<br>

## Cmdlets and Guides

* ### [New-WDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig)

* ### [New-SupplementalWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-SupplementalWDACConfig)

* ### [Remove-WDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Remove-WDACConfig)

* ### [Edit-WDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-WDACConfig)

* ### [Edit-SignedWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-SignedWDACConfig)

* ### [Deploy-SignedWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-SignedWDACConfig)

* ### [Confirm-WDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Confirm-WDACConfig)

* ### [New-DenyWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-DenyWDACConfig)

* ### [Set-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig)

* ### [New-KernelModeWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New%E2%80%90KernelModeWDACConfig)

* ### [Get-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Get-CommonWDACConfig)

* ### [Invoke-WDACSimulation](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Invoke-WDACSimulation)

<br>

## Feedback and Feature request

If there are any feedbacks or feature requests regarding this module, please [open a new discussion/issue on GitHub.](https://github.com/HotCakeX/Harden-Windows-Security)
