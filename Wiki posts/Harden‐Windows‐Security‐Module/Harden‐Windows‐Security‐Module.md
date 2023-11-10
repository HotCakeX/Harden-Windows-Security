# Harden Windows Security Module

This module offers rigorous compliance verification and security assessment. It enables you to evaluate the conformity of your system based on the security standards and recommendations of this repository. The module employs various techniques such as Security Policy, PowerShell cmdlet and Registry keys to conduct the checks.

Compliance checking strictly follows the guidelines and security measures of this GitHub repository. Any minor deviation from them will result in a `false` value for the corresponding check.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How It Works

This module verifies and validates all of the security measures applied by the Harden Windows Security script. It checks registry keys if the script uses Group Policy or registry, PowerShell cmdlets if the script invokes them and Security Group Policy if the script applies them.

The module is compatible with any system locale and language.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Quick Demo

https://github.com/HotCakeX/Harden-Windows-Security/assets/118815227/0fdbd34b-6bf6-4eae-b081-83b43d60bd0d

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Requirements

[Same requirements as described on the Readme](https://github.com/HotCakeX/Harden-Windows-Security#requirements-), plus:

* Administrator privileges for `Confirm-SystemCompliance` and `Unprotect-WindowsSecurity`
* Administrator OR Standard user privileges for `Protect-WindowsSecurity`
* PowerShell Core latest version
     * Get it from the [official GitHub repository](https://github.com/PowerShell/PowerShell/releases)
     * Or Install it from [Microsoft Store](https://apps.microsoft.com/store/detail/powershell/9MZ1SNWT0N5D)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Automatic Updates
The module checks for updates every time you run it and updates itself if there is a new version available, so you don't have to manually do anything.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How to Install and Use

### You can install this module from [PowerShell gallery](https://www.powershellgallery.com/packages/Harden-Windows-Security-Module/)

```powershell
Install-Module -Name 'Harden-Windows-Security-Module' -Force
```

### Perform Compliance Check

```powershell
Confirm-SystemCompliance
```

### Apply the Hardening measures described in the [Readme](https://github.com/HotCakeX/Harden-Windows-Security)

```powershell
Protect-WindowsSecurity
```

### Remove the Hardening Measures Described in The [Readme](https://github.com/HotCakeX/Harden-Windows-Security)

```powershell
Unprotect-WindowsSecurity
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Available Parameters for Confirm-SystemCompliance Cmdlet

```powershell
Confirm-SystemCompliance [-ExportToCSV] [-ShowAsObjectsOnly] [-DetailedDisplay]
```

### 3 Optional Parameters, They Can Be Used Together or Individually.

* `[-ExportToCSV]`: In addition to displaying the results on the screen, also exports them in a nicely formatted CSV for easier viewing. The CSV is fully compatible with GitHub too so you can upload it to GitHub and view it.

* `[-ShowAsObjectsOnly]`: Instead of displaying strings on the console, outputs actionable objects and properties. You can use this parameter for when you need to store the output of the function in a variable and use it that way. This provides a very detailed nested object and suppresses the normal string output on the console.

* `[-DetailedDisplay]`: Shows the output on the PowerShell console with more details and in the list format instead of table format

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Available Parameters for Unprotect-WindowsSecurity Cmdlet

```powershell
Unprotect-WindowsSecurity [-OnlyProcessMitigations]
```

### 1 Optional Parameter

* `[-OnlyProcessMitigations]`: Indicates that the cmdlet will only remove Process Mitigations (Exploit Protection) settings and doesn't change anything else.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Notes for Unprotect-WindowsSecurity Cmdlet

1. Bitlocker Encrypted drives are not decrypted when you invoke this cmdlet.

2. Security features related to [Device Guard](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Device-Guard-and-Virtualization-Based-Security-in-Windows) that are activated by UEFI Lock remain enabled even after you execute this cmdlet. [Learn more here](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Device-Guard-and-Virtualization-Based-Security-in-Windows#about-uefi-lock)

3. Windows optional features that are enabled or disabled by `Protect-WindowsSecurity` cmdlet are not affected.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Security Scoring System

Based on the score that you get you will see a different ASCII art!

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

<br>

Any feedback or suggestions? Please use GitHub [issues](https://github.com/HotCakeX/Harden-Windows-Security/issues) or [discussions](https://github.com/HotCakeX/Harden-Windows-Security/discussions)

<br>
