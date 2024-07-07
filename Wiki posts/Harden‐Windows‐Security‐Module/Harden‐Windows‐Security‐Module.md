# Harden Windows Security Module

<div align="center">
<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/APNGs/harden%20windows%20security%20Module.apng" alt="Harden Windows Security by Violet Hansen aka HotCakeX">
</div>

<br>

It is a PowerShell module that can apply all of the hardening measures described in the readme. It also offers rigorous compliance verification and security assessment. It enables you to evaluate the conformity of your system based on the security standards and recommendations of this repository. The module employs various techniques such as Security Policy, PowerShell cmdlet and Registry keys to conduct the checks.

It is also useful for security researchers and penetration testers who want to assess their system security posture. The module works with any system locale and language.

### Automatic Updates

The module checks for updates every time you run it and updates itself if there is a new version available, so you don't have to manually do anything.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How to Install and Use

### <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/pinkhellokittydonut.gif" width="35" alt="milky donut"> Install the Harden Windows Security Module from [PowerShell Gallery](https://www.powershellgallery.com/packages/Harden-Windows-Security-Module/)

```powershell
Install-Module -Name 'Harden-Windows-Security-Module' -Force
```

### <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/rainbow.gif" width="35" alt="rainbow"> Use the GUI (Graphical User Interface)

```powershell
Protect-WindowsSecurity -GUI
```

### <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/sailormoonheart.gif" width="35" alt="sailor moon heart"> Apply the Hardening measures described in the [Readme](https://github.com/HotCakeX/Harden-Windows-Security)

```powershell
Protect-WindowsSecurity
```

### <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/strawberrymilk.gif" width="35" alt="Strawberry milk"> Perform Compliance Check

```powershell
Confirm-SystemCompliance
```

### <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/stileto.gif" width="35" alt="stileto"> Remove the Hardening Measures Described in The [Readme](https://github.com/HotCakeX/Harden-Windows-Security)

```powershell
Unprotect-WindowsSecurity
```

### <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/glowstick.gif" width="35" alt="glowing sticks"> Uninstall the Harden Windows Security Module

```powershell
Uninstall-Module -Name 'Harden-Windows-Security-Module' -Force -AllVersions
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Quick Demo

<div align="center">

https://github.com/HotCakeX/Harden-Windows-Security/assets/118815227/51259ec0-aba3-45c4-9e4a-d1923f905cc8

</div>

<br>

* #### [YouTube demo of the Module's GUI](https://youtu.be/a8YbihowTVg?si=hGUS2KAW_z80Hnx8)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Protect-WindowsSecurity

## Syntax

```powershell
Protect-WindowsSecurity
    [-GUI]
    [-Categories <String[]>]
    [-Log]
    [-Offline]
    [<CommonParameters>]
```

## Description

The `Protect-WindowsSecurity` cmdlet's hybrid design allows it to operate as a standalone script and as a module component. It allows it to operate with and without administrator privileges. You can use this cmdlet in both interactive and non-interactive modes.

In Interactive mode, the cmdlet will ask you to confirm the changes before applying them. In non-interactive mode, you can pre-configure the hardening categories you want to apply and the cmdlet will apply them without asking for confirmation.

It possesses the ability to operate entirely in isolation, useful for systems or servers that are disconnected from the Internet.

## Parameters

### -GUI

Shows a graphical user interface (GUI) that allows you to select the hardening categories you want to apply.

> [!TIP]\
> In the GUI experience:
> * Toast Notification is displayed when all of the selected categories are applied.
> * When using the logging feature, the log file will be created in the path you selected once the GUI is closed.

<br>

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

### -Categories

Specify the hardening categories that you want to apply. This will tell the module to operate in non-interactive or headless/silent mode which won't ask for confirmation before running each selected categories.

You can specify multiple categories by separating them with a comma. If you don't specify any category, the cmdlet will run in interactive mode. **Use this parameter for deployments at a large scale.**

If a selected category requires Administrator privileges and the module is running with Standard privileges, that category is skipped.

This parameter has automatic tab completion. You can press the `Tab` key to see the available categories.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)[]|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

### -Verbose

Shows verbose messages on the console about what the cmdlet is doing.

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

### -Log

Activates comprehensive logging by recording all the information shown on the screen and some additional data to a text file. It is strongly advised to use the -Verbose parameter when you want to enable logging.

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

### -LogPath

The path to save the log file to. If not specified, the log file will be saved in the current working directory.

> [!NOTE]\
> Only available if the `-Log` switch is used.

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

### -Offline

Indicates that the module is being run in offline mode. Will not download any files from the internet. Will not check for updates. Using this parameter will make the following 3 parameters available and mandatory: `PathToLGPO`, `PathToMSFTSecurityBaselines` and `PathToMSFT365AppsSecurityBaselines`.

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

### -PathToLGPO

The path to the 'LGPO.zip'. Make sure it's in the zip format just like it's downloaded from the Microsoft servers. File name can be anything. The parameter has argument completer so you can press tab and use the file picker GUI to select the zip file.

> [!NOTE]\
> Only available if the `-Offline` switch is used.

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

### -PathToMSFTSecurityBaselines

The path to the 'Windows Security Baseline.zip'. Make sure it's in the zip format just like it's downloaded from the Microsoft servers. File name can be anything. The parameter has argument completer so you can press tab and use the file picker GUI to select the zip file.

> [!NOTE]\
> Only available if the `-Offline` switch is used.

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

### -PathToMSFT365AppsSecurityBaselines

The path to the 'Microsoft 365 Apps for Enterprise zip'. Make sure it's in the zip format just like it's downloaded from the Microsoft servers. File name can be anything. The parameter has argument completer so you can press tab and use the file picker GUI to select the zip file.

> [!NOTE]\
> Only available if the `-Offline` switch is used.

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

> [!NOTE]\
> You can control the sub-categories of each category by using the following switch parameters on the Command-line.
>
> Pay attention to the naming convention of them. They are named after the category they belong to.
>
> The switch parameters are dynamic and will only appear if you specify the corresponding category in the `-Categories` parameter. The following table shows the available switch parameters and their corresponding required categories.

<br>

|         Parameter Name                  |          Description                        | Required Category |
|:---------------------------------------:|:-------------------------------------------:|:-----------------:|
|SecBaselines_NoOverrides | Applies the Microsoft Security Baselines without the optional overrides   | MicrosoftSecurityBaselines |
|MSFTDefender_SAC | Enables Smart App Control | MicrosoftDefender |
|MSFTDefender_NoDiagData | Will not enable optional diagnostics data required for Smart App Control (Does not have any effect if Smart App Control is already turned on) | MicrosoftDefender |
|MSFTDefender_NoScheduledTask | Will not create scheduled task for fast MSFT driver block rules  | MicrosoftDefender |
|MSFTDefender_BetaChannels | Set Defender Engine and Intelligence update channels to beta | MicrosoftDefender |
|LockScreen_CtrlAltDel | Require CTRL + ALT + Delete at lock screen | LockScreen |
|LockScreen_NoLastSignedIn | Will not display the last signed in user at the lock screen | LockScreen |
|UAC_NoFastSwitching | Hide entry points for fast user switching | UserAccountControl |
|UAC_OnlyElevateSigned | Only elevate signed and validated executables | UserAccountControl |
|CountryIPBlocking_OFAC | Include the IP ranges of OFAC Sanctioned Countries in the firewall block rules | CountryIPBlocking |
| DangerousScriptHostsBlocking | Deploys the Dangerous Script Hosts Blocking WDAC Policy | DownloadsDefenseMeasures |
| ClipboardSync | Enables Clipboard Sync with Microsoft Account | NonAdminCommands |

<br>

> [!IMPORTANT]\
> It is highly recommended to always include the Microsoft Security Baselines category and place it first as it forms the foundation of all subsequent categories.

<br>

## Examples

### Example 1

If you run the module like this without specifying any categories, the module will run in interactive mode and the usual beautiful prompts will be displayed to the user.

```powershell
Protect-WindowsSecurity
```

### Example 2

This will display a GUI (Graphical UI) allowing you to easily select various options and categories to apply.

```powershell
Protect-WindowsSecurity -GUI
```

### Example 3

If you run the module like this, the 2 categories will be executed automatically without requiring any user input. The results will be displayed on the console.

```powershell
Protect-WindowsSecurity -Categories MicrosoftDefender, AttackSurfaceReductionRules
```

### Example 4

This example will apply the Microsoft Defender category with the Smart App Control sub-category, without the need for user interaction, and will show verbose messages.

```powershell
Protect-WindowsSecurity -Categories MicrosoftDefender -MSFTDefender_SAC -Verbose
```

### Example 5

This example will apply the Microsoft Security Baselines, BitLocker, User Account Control, Lock Screen and Downloads Defense Measures categories. It will also apply the "Only Elevate Signed and Validated Executables" sub-category of the User Account Control category, and the "Require CTRL + ALT + DEL on Lock Screen" sub-category of the Lock Screen category.

```powershell
Protect-WindowsSecurity -Categories MicrosoftSecurityBaselines,BitLockerSettings,UserAccountControl,LockScreen,DownloadsDefenseMeasures -UAC_OnlyElevateSigned -LockScreen_CtrlAltDel
```

### Example 6

This example instructs the cmdlet to run in offline mode and will not download any files from the internet. It also runs it in headless/silent mode by specifying which categories to automatically run. `-MSFTDefender_SAC` switch is used so the Smart App Control sub-category is also applied in the headless/silent mode. `-Log` switch is mentioned which will save the output of the cmdlet to a text file in the current working directory.

```powershell
Protect-WindowsSecurity -Verbose -Offline -PathToLGPO 'C:\Users\Admin\Desktop\LGPO.zip' -PathToMSFTSecurityBaselines 'C:\Users\Admin\Desktop\Baselines.zip' -PathToMSFT365AppsSecurityBaselines 'C:\Users\Admin\Desktop\M365Baselines.zip' -Log -Categories MicrosoftSecurityBaselines,MicrosoftDefender -MSFTDefender_SAC
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Confirm-SystemCompliance

## Syntax

```powershell
Confirm-SystemCompliance
    [-Categories]
    [-ExportToCSV]
    [-ShowAsObjectsOnly]
    [-DetailedDisplay]
    [-Offline]
```

## Description

This cmdlet verifies and validates all of the applied security measures. It checks registry keys if the module uses Group Policy or registry, PowerShell cmdlets if the module invokes them and Security Group Policy if the module applies them.

Compliance checking strictly follows the guidelines and security measures of this GitHub repository. Any minor deviation from them will result in a `false` value for the corresponding check.

> [!NOTE]\
> Based on the score that you get you will see a different ASCII art!

## Parameters

### -Categories

Specify the categories to check compliance for. If not specified, all categories will be checked.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)[]|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

### -ExportToCSV

In addition to displaying the results on the screen, also exports them in a nicely formatted CSV for easier viewing. The CSV is fully compatible with GitHub too so you can upload it to GitHub and view it.

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

### -ShowAsObjectsOnly

Instead of displaying strings on the console, outputs actionable objects and properties. You can use this parameter for when you need to store the output of the function in a variable and use it that way. This provides a very detailed nested object and suppresses the normal string output on the console.

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

### -DetailedDisplay

Shows the output on the PowerShell console with more details and in the list format instead of table format

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

### -Offline

Skips the online update check and allows you to run the cmdlet in completely offline mode.

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Unprotect-WindowsSecurity Cmdlet

## Syntax

```powershell
Unprotect-WindowsSecurity
    [-OnlyProcessMitigations]
    [-OnlyCountryIPBlockingFirewallRules]
    [-WDACPoliciesToRemove <String[]>]
    [-Force]
```

## Description

You can use this cmdlet to remove all of the applied hardening measures, with the following exceptions:

* Bitlocker Encrypted drives are not decrypted when you invoke this cmdlet.

* Security features related to [Device Guard](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Device-Guard-and-Virtualization-Based-Security-in-Windows) that are activated by UEFI Lock remain enabled even after you execute this cmdlet. [Learn more here](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Device-Guard-and-Virtualization-Based-Security-in-Windows#about-uefi-lock)

* Windows optional features that are enabled or disabled by `Protect-WindowsSecurity` cmdlet are not affected.

## Parameters

### -OnlyProcessMitigations

Indicates that the cmdlet will only remove Process Mitigations (Exploit Protection) settings and doesn't change anything else.

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

### -WDACPoliciesToRemove

Select the [WDAC Policy](https://github.com/HotCakeX/Harden-Windows-Security?tab=readme-ov-file#downloads-defense-measures-) names to remove.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)[]|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Accepted values: | `Dangerous-Script-Hosts-Blocking`, `Downloads-Defense-Measures` |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -OnlyCountryIPBlockingFirewallRules

Indicates that the cmdlet will only remove the [country IP blocking firewall rules](https://github.com/HotCakeX/Harden-Windows-Security?tab=readme-ov-file#country-ip-blocking) and doesn't change anything else.

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

<br>

Any feedback or suggestions? Please use GitHub [issues](https://github.com/HotCakeX/Harden-Windows-Security/issues) or [discussions](https://github.com/HotCakeX/Harden-Windows-Security/discussions)

<br>
