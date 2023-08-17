# Harden-Windows-Security-Module

This module offers rigorous compliance verification and security assessment. It enables you to evaluate the conformity of your system based on the security standards and recommendations of this repository. The module employs various techniques such as Security Policy, PowerShell cmdlet and Registry keys to conduct the checks.

Compliance checking strictly follows the guidelines and security measures of this GitHub repository. Any minor deviation from them will result in a `$false` value for the corresponding check.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How it works

This module verifies and validates all of the security measures applied by the Harden Windows Security script. It checks registry keys if the script uses Group Policy or registry, PowerShell cmdlets if the script invokes them and Security Group Policy if the script applies them.

The module is compatible with any system locale and language.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Quick demo

https://github.com/HotCakeX/Harden-Windows-Security/assets/118815227/0fdbd34b-6bf6-4eae-b081-83b43d60bd0d

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Requirements

* **Administrator privileges for compliance checking and Removing Hardening measures**
* **Administrator OR Standard user privileges for the Hardening mode, just like the Harden Windows Security script**
* [PowerShell core version 7.3 and above](https://github.com/PowerShell/PowerShell/releases)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Automatic updates
The module checks for updates every time you run it and updates itself if there is a new version available, so you don't have to manually do anything.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How to install and use

### You can install this module from [PowerShell gallery](https://www.powershellgallery.com/packages/Harden-Windows-Security-Module/)

```powershell
Install-Module -Name Harden-Windows-Security-Module -Force
```

### Perform Compliance check

```powershell
Confirm-SystemCompliance
```

### Apply the Hardening measures described in the [Readme](https://github.com/HotCakeX/Harden-Windows-Security)

```powershell
Protect-WindowsSecurity
```

### Remove the Hardening measures described in the [Readme](https://github.com/HotCakeX/Harden-Windows-Security)

```powershell
Unprotect-WindowsSecurity
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Available parameters for Confirm-SystemCompliance cmdlet

```powershell
Confirm-SystemCompliance [-ExportToCSV] [-ShowAsObjectsOnly] [-DetailedDisplay]
```

### 3 optional parameters, they can be used together or individually.

* `[-ExportToCSV]`: In addition to displaying the results on the screen, also exports them in a nicely formatted CSV for easier viewing. The CSV is fully compatible with GitHub too so you can upload it to GitHub and view it.

* `[-ShowAsObjectsOnly]`: Instead of displaying strings on the console, outputs actionable objects and properties. You can use this parameter for when you need to store the output of the function in a variable and use it that way. This provides a very detailed nested object and suppresses the normal string output on the console.

* `[-DetailedDisplay]`: Shows the output on the PowerShell console with more details and in the list format instead of table format

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
