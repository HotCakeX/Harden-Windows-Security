# Harden Windows Security Module

It is a PowerShell module that can apply all of the hardening measures described in the readme. It also offers rigorous compliance verification and security assessment. It enables you to evaluate the conformity of your system based on the security standards and recommendations of this repository. The module employs various techniques such as Security Policy, PowerShell cmdlet and Registry keys to conduct the checks.

It is also useful for security researchers and penetration testers who want to assess their system security posture. The module works with any system locale and language.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How the Protection Works

The `Protect-WindowsSecurity` cmdlet's hybrid design allows it to operate as a standalone script and as a module component. It allows it to operate with and without administrator privileges. You can use this cmdlet in both interactive and non-interactive modes.

In Interactive mode, the cmdlet will ask you to confirm the changes before applying them. In non-interactive mode, you can pre-configure the hardening categories you want to apply and the cmdlet will apply them without asking for confirmation.

It possesses the ability to operate entirely in isolation, useful for systems or servers that are disconnected from the Internet.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How the Compliance Checking Works

This module verifies and validates all of the security measures applied by the `Protect-windowsSecurity` cmdlet. It checks registry keys if the script uses Group Policy or registry, PowerShell cmdlets if the script invokes them and Security Group Policy if the script applies them.

Compliance checking strictly follows the guidelines and security measures of this GitHub repository. Any minor deviation from them will result in a `false` value for the corresponding check.

### Security Scoring System

Based on the score that you get you will see a different ASCII art!

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How the Protections Removal Works

You can use the `Unprotect-WindowsSecurity` cmdlet to remove all of the hardening measures applied by the `Protect-WindowsSecurity` cmdlet, with the following exceptions:

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

### Apply the Hardening measures described in the [Readme](https://github.com/HotCakeX/Harden-Windows-Security)

```powershell
Protect-WindowsSecurity
```

### Perform Compliance Check

```powershell
Confirm-SystemCompliance
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
Protect-WindowsSecurity [-Categories <String[]>] [-Log] [-Offline] [<CommonParameters>]
```

<br>

### 8 Optional Parameters

* `-Categories`: Specify the hardening categories that you want to apply. This will tell the module to operate in non-interactive or headless/silent mode which won't ask for confirmation before running each selected categories. You can specify multiple categories by separating them with a comma. If you don't specify any category, the cmdlet will run in interactive mode. **Use this parameter for deployments at a large scale.** If a selected category requires Administrator privileges and the module is running with Standard privileges, that category is skipped.
    * This parameter has automatic tab completion. You can press the `Tab` key to see the available categories.

* `-Verbose`: Shows verbose messages on the console about what the cmdlet is doing.

* `-Log`: Activates comprehensive logging by recording all the information shown on the screen and some additional data to a text file. It is strongly advised to use the -Verbose parameter when you want to enable logging.

     * `-LogPath`: The path to save the log file to. If not specified, the log file will be saved in the current working directory.

* `-Offline`: Indicates that the module is being run in offline mode. Will not download any files from the internet. Will not check for updates. Using this parameter will make the following 3 parameters available and mandatory: `PathToLGPO`, `PathToMSFTSecurityBaselines` and `PathToMSFT365AppsSecurityBaselines`.

     * `-PathToLGPO`: The path to the 'LGPO.zip'. Make sure it's in the zip format just like it's downloaded from the Microsoft servers. File name can be anything. The parameter has argument completer so you can press tab and use the file picker GUI to select the zip file.

     * `-PathToMSFTSecurityBaselines`: The path to the 'Windows Security Baseline.zip'. Make sure it's in the zip format just like it's downloaded from the Microsoft servers. File name can be anything. The parameter has argument completer so you can press tab and use the file picker GUI to select the zip file.

     * `-PathToMSFT365AppsSecurityBaselines`: The path to the 'Microsoft 365 Apps for Enterprise zip'. Make sure it's in the zip format just like it's downloaded from the Microsoft servers. File name can be anything. The parameter has argument completer so you can press tab and use the file picker GUI to select the zip file.

<br>

> [!NOTE]\
> You can further control the sub-categories of each category by using the following switch parameters. Pay attention to the naming convention of them. They are named after the category they belong to. For example, the switch parameter `-MSFTDefender_SAC` belongs to the `MicrosoftDefender` category. The switch parameters are dynamic and will only appear if you specify the corresponding category in the `-Categories` parameter. For example, if you don't specify the `MicrosoftDefender` category in the `-Categories` parameter, the switch parameters related to it won't appear. The following table shows the available switch parameters and their corresponding categories.

<br>

|         Parameter Name                  |          Description                        | Required Category |
|:---------------------------------------:|:-------------------------------------------:|:-----------------:|
|-SecBaselines_NoOverrides | Applies the Microsoft Security Baselines without the optional overrides   | MicrosoftSecurityBaselines |
|-MSFTDefender_SAC | Enables Smart App Control | MicrosoftDefender |
|-MSFTDefender_NoDiagData | Will not enable optional diagnostics data required for Smart App Control (Does not have any effect if Smart App Control is already turned on) | MicrosoftDefender |
|-MSFTDefender_NoScheduledTask | Will not create scheduled task for fast MSFT driver block rules  | MicrosoftDefender |
|-MSFTDefender_BetaChannels | Set Defender Engine and Intelligence update channels to beta | MicrosoftDefender |
|-LockScreen_CtrlAltDel | Require CTRL + ALT + Delete at lock screen | LockScreen |
|-LockScreen_NoLastSignedIn | Will not display the last signed in user at the lock screen | LockScreen |
|-UAC_NoFastSwitching | Hide entry points for fast user switching | UserAccountControl |
|-UAC_OnlyElevateSigned | Only elevate signed and validated executables | UserAccountControl |
|-CountryIPBlocking_OFAC | Include the IP ranges of OFAC Sanctioned Countries in the firewall block rules | CountryIPBlocking |

<br>

### What if You Don’t Configure the Sub-Categories?

If you do not specify any sub-categories using the switch parameters above, the following sub-category configuration will be applied when the corresponding category exists in the `-Categories` parameter.

<br>

<div align="center">

| Indicator| Sub-Category Status                   |
|:--------:|:-----------------------------:|
| <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> | Is Applied |
| <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> | Is Not Applied |

</div>

<br>

- Windows Boot Manager Revocations
- Microsoft Security Baselines
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Yes, With the Optional Overrides (Recommended)
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Yes
- Microsoft 365 Apps Security Baselines
- Microsoft Defender
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Smart App Control enablement
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Enable advanced diagnostic data if Smart App Control is on
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Scheduled task creation for fast weekly MSFT driver block list update
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Set engine and intelligence update channels to beta
- Attack Surface Reduction Rules
- BitLocker Settings
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Normal: TPM + Startup PIN + Recovery Password
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Enhanced: TPM + Startup PIN + Startup Key + Recovery Password
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Skip encryptions altogether
- TLS Security
- Lock Screen
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Don't display last signed-in
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Require CTRL + ALT + DEL on lock screen
- User Account Control
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Only elevate signed and validated executables
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Hide the entry points for Fast User Switching
- Windows Firewall
- Optional Windows Features
- Windows Networking
- Miscellaneous Configurations
- Windows Update Configurations
- Edge Browser Configurations
- Certificate Checking Commands
- Country IP Blocking
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow-planet-heart.gif" alt="planet rainbow heart indicating item that runs in Windows Hardening module" width="30"> Block State Sponsors of Terrorism IP blocks
    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/orange-point.gif" alt="spinning random dots indicating the sub-category won't run in headless mode in Windows Hardening module" width="30"> Block OFAC Sanctioned Countries IP blocks
- Downloads Defense Measures
- Non-Admin Commands

<br>

> [!IMPORTANT]\
> It is highly recommended to always include the Microsoft Security Baselines category and place it first as it forms the foundation of all subsequent categories.

<br>

### Example 1

If you run the module like this without specifying any categories, the module will run in interactive mode and the usual beautiful prompts will be displayed to the user.

```powershell
Protect-WindowsSecurity
```

### Example 2

If you run the module like this, the 2 categories will be executed automatically without requiring any user input. The results will be displayed on the console.

```powershell
Protect-WindowsSecurity -Categories MicrosoftDefender, AttackSurfaceReductionRules
```

### Example 3

This example will apply the Microsoft Defender category with the Smart App Control sub-category, without the need for user interaction, and will show verbose messages.

```powershell
Protect-WindowsSecurity -Categories MicrosoftDefender -MSFTDefender_SAC -Verbose
```

### Example 4

This example will apply the Microsoft Security Baselines, BitLocker, User Account Control, Lock Screen and Downloads Defense Measures categories. It will also apply the "Only Elevate Signed and Validated Executables" sub-category of the User Account Control category, and the "Require CTRL + ALT + DEL on Lock Screen" sub-category of the Lock Screen category.

```powershell
Protect-WindowsSecurity -Categories MicrosoftSecurityBaselines,BitLockerSettings,UserAccountControl,LockScreen,DownloadsDefenseMeasures -UAC_OnlyElevateSigned -LockScreen_CtrlAltDel
```

### Example 5

This example instructs the cmdlet to run in offline mode and will not download any files from the internet. It also runs it in headless/silent mode by specifying which categories to automatically run. `-MSFTDefender_SAC` switch is used so the Smart App Control sub-category is also applied in the headless/silent mode. `-Log` switch is mentioned which will save the output of the cmdlet to a text file in the current working directory.

```powershell
Protect-WindowsSecurity -Verbose -Offline -PathToLGPO 'C:\Users\Admin\Desktop\LGPO.zip' -PathToMSFTSecurityBaselines 'C:\Users\Admin\Desktop\Baselines.zip' -PathToMSFT365AppsSecurityBaselines 'C:\Users\Admin\Desktop\M365Baselines.zip' -Log -Categories MicrosoftSecurityBaselines,MicrosoftDefender -MSFTDefender_SAC
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
