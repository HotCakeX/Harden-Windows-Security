# Harden Windows Security Module

This module can apply all of the hardening measures described in the readme. It also offers rigorous compliance verification and security assessment. It enables you to evaluate the conformity of your system based on the security standards and recommendations of this repository. The module employs various techniques such as Security Policy, PowerShell cmdlet and Registry keys to conduct the checks.

Compliance checking strictly follows the guidelines and security measures of this GitHub repository. Any minor deviation from them will result in a `false` value for the corresponding check.

The module is compatible with any system locale and language.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How the Compliance Checking Works

This module verifies and validates all of the security measures applied by the Harden Windows Security script. It checks registry keys if the script uses Group Policy or registry, PowerShell cmdlets if the script invokes them and Security Group Policy if the script applies them.

### Security Scoring System

Based on the score that you get you will see a different ASCII art!

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How the Protection Works

The `Protect-WindowsSecurity` cmdlet's hybrid design allows it to operate as a standalone script and as a module component. It allows it to operate with and without administrator privileges. You can use this cmdlet in both interactive and non-interactive modes.

In Interactive mode, the cmdlet will ask you to confirm the changes before applying them. In non-interactive mode, you can pre-configure the hardening categories you want to apply and the cmdlet will apply them without asking for confirmation.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How the Protections Removal Works

You can use the `Unprotect-WindowsSecurity` cmdlet to remove all of the hardening measures applied by the `Protect-WindowsSecurity` cmdlet.

* Bitlocker Encrypted drives are not decrypted when you invoke this cmdlet.

* Security features related to [Device Guard](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Device-Guard-and-Virtualization-Based-Security-in-Windows) that are activated by UEFI Lock remain enabled even after you execute this cmdlet. [Learn more here](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Device-Guard-and-Virtualization-Based-Security-in-Windows#about-uefi-lock)

* Windows optional features that are enabled or disabled by `Protect-WindowsSecurity` cmdlet are not affected.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Quick Demo

https://github.com/HotCakeX/Harden-Windows-Security/assets/118815227/0fdbd34b-6bf6-4eae-b081-83b43d60bd0d

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Automatic Updates
The module checks for updates every time you run it and updates itself if there is a new version available, so you don't have to manually do anything.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How to Install and Use

### Install the Harden Windows Security Module from [PowerShell Gallery](https://www.powershellgallery.com/packages/Harden-Windows-Security-Module/)

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

### Uninstall the Harden Windows Security Module

```powershell
Uninstall-Module -Name 'Harden-Windows-Security-Module' -Force -AllVersions
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Available Parameters for Protect-WindowsSecurity Cmdlet

```powershell
Protect-WindowsSecurity [[-Categories] <String[]>] [<CommonParameters>]
```

### 1 Optional Parameter

* `-Categories`: Specify the hardening categories that you want to apply. This will tell the module to operate in non-interactive or headless/silent mode which won't ask for confirmation before running each selected categories. You can specify multiple categories by separating them with a comma. If you don't specify any category, the cmdlet will run in interactive mode. **Use this parameter for deployments at a large scale.** If a selected category requires Administrator privileges and the module is running with Standard privileges, that category is skipped.

### 10 Dynamic Parameters

When running in headless/unattended mode, you can control the sub-categories of each category by using the following switch parameters:

* `MicrosoftSecurityBaselines_NoOverrides`: Applies the Microsoft Security Baselines without the optional overrides

* `MicrosoftDefender_SmartAppControl`: Enables Smart App Control

* `MicrosoftDefender_NoOptionalDiagnosticData`: Will not enable optional diagnostics data required for Smart App Control (Does not have any effect if Smart App Control is already turned on)

* `MicrosoftDefender_NoScheduledTask`: Will not create scheduled task for fast MSFT driver block rules 

* `MicrosoftDefender_DefenderBetaChannels`: Set Defender Engine and Intelligence update channels to beta

* `LockScreen_RequireCtrlAltDel`: Require CTRL + ALT + Delete at lock screen

* `LockScreen_DontDisplayLastSignedIn`: Will not display the last signed in user at the lock screen

* `UserAccountControl_NoFastUserSwitching`: Hide entry points for fast user switching

* `UserAccountControl_OnlyElevateSignedExe`: Only elevate signed and validated executables

* `CountryIPBlocking_BlockOFACSanctionedCountries`: Include the IP ranges of OFAC Sanctioned Countries in the firewall block rules

Each of the switch parameters above will be dynamically generated based on the categories you choose. For example, if you choose to run the Microsoft Security Baselines category, the `MicrosoftSecurityBaselines_NoOverrides` switch parameter will be generated and you can use it to apply the Microsoft Security Baselines without the optional overrides.

<br>

### Available Categories in Headless Mode

The following is the exact enumeration of the items that will be executed based on the user chosen categories when operating in headless/silent mode. You can control the sub-categories of each category by using the dynamic switch parameters described above.

<br>

<div align="center">

| Indicator| Description                   |
|:--------:|:-----------------------------:|
| <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> | Indicates the item runs |
| <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> | Indicates the item is skipped |

</div>

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Windows Boot Manager Revocations
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Microsoft Security Baselines
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Yes, With the Optional Overrides (Recommended)
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Yes
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Microsoft 365 Apps Security Baselines
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Microsoft Defender
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Smart App Control enablement
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Enable advanced diagnostic data if Smart App Control is on
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Scheduled task creation for fast weekly MSFT driver block list update
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Set engine and intelligence update channels to beta
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Attack Surface Reduction Rules
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> BitLocker Settings
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Normal: TPM + Startup PIN + Recovery Password
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Enhanced: TPM + Startup PIN + Startup Key + Recovery Password
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Skip encryptions altogether
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> TLS Security
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Lock Screen
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Don't display last signed-in
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Require CTRL + ALT + DEL on lock screen
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> User Account Control
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Only elevate signed and validated executables
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Hide the entry points for Fast User Switching
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Windows Firewall
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Optional Windows Features
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Windows Networking
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Miscellaneous Configurations
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Windows Update Configurations
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Edge Browser Configurations
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Certificate Checking Commands
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Country IP Blocking
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Block State Sponsors of Terrorism IP blocks
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Block OFAC Sanctioned Countries IP blocks
- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Non-Admin Commands

<br>

> [!IMPORTANT]\
> It is highly recommended to always include the Microsoft Security Baselines category and place it first as it forms the foundation of all subsequent categories.

<br>

### Example 1

If you run the module like this, the 2 categories will be executed automatically without requiring any user input. The results will be displayed on the console.

```powershell
Protect-WindowsSecurity -Categories MicrosoftDefender, AttackSurfaceReductionRules
```

### Example 2

If you run the module like this without specifying any categories, the module will run in interactive mode and the usual beautiful prompts will be displayed to the user.

```powershell
Protect-WindowsSecurity
```

### Example 3

This example will apply the Microsoft Defender category with the Smart App Control sub-category, without the need for user interaction, and will show verbose messages.

```powershell
Protect-WindowsSecurity -Categories MicrosoftDefender -MicrosoftDefender_SmartAppControl -Verbose
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

<br>

Any feedback or suggestions? Please use GitHub [issues](https://github.com/HotCakeX/Harden-Windows-Security/issues) or [discussions](https://github.com/HotCakeX/Harden-Windows-Security/discussions)

<br>
