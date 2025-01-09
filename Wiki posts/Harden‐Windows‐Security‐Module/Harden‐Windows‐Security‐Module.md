# Harden Windows Security Module

<div align="center">
<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/APNGs/harden%20windows%20security%20Module.apng" alt="Harden Windows Security by Violet Hansen aka HotCakeX">
</div>

<br>

Harden Windows Security is a PowerShell module designed to simplify the application of critical security configurations in Windows. This tool offers a range of intuitive and innovative methods to enhance your system's security posture effortlessly. Detailed explanations of all available security measures can be found in the repository's README file. Harden Windows Security provides several modes of interaction to cater to different user preferences:

* Graphical User Interface (GUI): For those who prefer an interactive experience, a fully-featured GUI is available.

* Command-Line Interface (CLI): The complete feature set is accessible via the PowerShell command line for users who favor a script-based approach.

* Unattended Mode: Ideal for automation, this mode allows you to schedule and execute all or specific security configurations at predefined intervals.

* Executable Format: Thanks to its hybrid design, the same codebase, without any changes to it, can be compiled into an executable file, catering to users who prefer a standalone application.

Harden Windows Security also excels in rigorous compliance verification and security assessment. It empowers you to evaluate your system's adherence to security standards and recommendations outlined in this repository. The module is fully capable of conducting compliance checks and detecting policies applied through modern workplace management tools like Intune MDM, traditional Group Policies, Registry keys, Windows APIs, CIM, and more.

Furthermore, this module is invaluable for security researchers and penetration testers seeking to assess and improve their system's security posture. It is compatible with any system locale and language, ensuring broad usability.

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/a8eb3942e1b3a71c94a7c8811e4d95a3aa991eb9/Pictures/SVG/Logging.svg" width="35" alt="Comprehensive Logging Capabilities Harden Windows Security"> Comprehensive Logging Capabilities

Harden Windows Security includes detailed logging features that track every part of its operations. These logs are helpful for reviewing what actions were taken, making it easier to audit and troubleshoot. You can choose where these logs are saved:

* Log Files: Save logs in files for easy review and storage.

* Windows Event Logs: Add logs to Windows Event Viewer for centralized monitoring.

* Console Output: Display logs in the console for real-time updates.

These logging options ensure that all actions taken by Harden Windows Security are recorded, giving you clear visibility into your security processes. Whether you’re conducting security checks, responding to issues, or just keeping an eye on things, these logs provide valuable information.

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/a8eb3942e1b3a71c94a7c8811e4d95a3aa991eb9/Pictures/SVG/Update.svg" width="35" alt="Automatic Update Harden Windows Security"> Automatic Updates

The module checks for updates every time you run it and updates itself if there is a new version available, so you don't have to manually do anything.

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/a8eb3942e1b3a71c94a7c8811e4d95a3aa991eb9/Pictures/SVG/Apps.svg" width="35" alt="Remove Pre-installed Windows Apps Harden Windows Security"> Remove Pre-installed Windows Apps

The Harden Windows Security provides an intuitive GUI to display a list of pre-installed apps on your device, enabling effortless removal. Once removed, these apps are deleted for all users and will not reappear when new user accounts are created. To reinstall them, you must download them from the Microsoft Store

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/a8eb3942e1b3a71c94a7c8811e4d95a3aa991eb9/Pictures/SVG/AttackSurfaceReductionRules.svg" width="35" alt="Manage Individual Attack Surface Reduction (ASR) Rules Harden Windows Security"> Manage Individual Attack Surface Reduction (ASR) Rules

With the GUI, you can configure each Attack Surface Reduction (ASR) rule individually. Additionally, you can quickly check the current status of any specific ASR rule.

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/a8eb3942e1b3a71c94a7c8811e4d95a3aa991eb9/Pictures/SVG/OptionalFeatures.svg" width="35" alt="Remove Each individual Optional Windows Features Harden Windows Security"> Remove Each individual Optional Windows Features

The Harden Windows Security's GUI allows you to manage and remove optional Windows features and capabilities individually. It also provides a convenient way to check the status of each feature and capability.

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/a8eb3942e1b3a71c94a7c8811e4d95a3aa991eb9/Pictures/SVG/FileReputation.svg" width="35" alt="Verify File Reputation Using Smart App Control or SmartScreen Harden Windows Security"> Verify File Reputation Using Smart App Control or SmartScreen

The Harden Windows Security includes a unique feature that lets you verify a file's reputation using Smart App Control or SmartScreen intelligence, depending on which service is currently active.

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/a8eb3942e1b3a71c94a7c8811e4d95a3aa991eb9/Pictures/SVG/BitLocker.svg" width="35" alt="BitLocker Encryption, Decryption And Backup Harden Windows Security"> BitLocker Encryption, Decryption And Backup

Leverage the Harden Windows Security GUI to securely encrypt your internal and external drives using advanced security configurations, including TPM + PIN + Startup Key for triple-factor authentication or TPM + PIN for 2-factor authentication. You can also back up your recovery keys to a file effortlessly, ensuring safe storage in case they are needed in the future.

<br>

## <img src="https://raw.githubusercontent.com/HotCakeX/.github/513aaf059d12f64b903a32428ea5da3c77b5ecb5/Pictures/SVG/NetworkAdapterRemoval.svg" width="35" alt="Remove Pre-loaded Network Adapter Drivers"> Remove Pre-loaded Network Adapter Drivers

Windows includes pre-loaded Ethernet and Wi-Fi network adapter drivers to enable internet connectivity during the Out-of-Box Experience (OOBE) without requiring manual driver installation. These drivers support hardware from manufacturers such as Intel, Qualcomm, Broadcom, Marvell, Realtek, Ralink, and others.

Using the Harden Windows Security, you can remove unnecessary drivers or those associated with OEM hardware you do not own. This process helps freeing up disk space and reduce the overall attack surface.

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

The `Protect-WindowsSecurity` cmdlet's hybrid design allows it to operate with and without administrator privileges. You can use this cmdlet in both interactive and non-interactive modes.

In Interactive mode, the cmdlet will ask you to confirm the changes before applying them. In non-interactive mode, you can pre-configure the hardening categories you want to apply and the cmdlet will apply them without asking for confirmation.

> [!TIP]\
> It possesses the ability to operate entirely in isolation, useful for systems or servers that are disconnected from the Internet.

## Parameters

### -GUI

Launched the Graphical User Interface (GUI). This is the primary way of launching the GUI of the Harden Windows Security. You will have access to the entire feature set and more.

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

This parameter has automatic tab completion. You can press the `Tab` key to see the available categories on the PowerShell console.

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

Activates comprehensive logging by recording all the information shown on the screen and some additional data to a text file. It is strongly advised to use the `-Verbose` parameter when you want to enable logging.

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
| SecBaselines_NoOverrides | Applies the Microsoft Security Baselines without the optional overrides   | MicrosoftSecurityBaselines |
| MSFTDefender_SAC | Enables Smart App Control | MicrosoftDefender |
| MSFTDefender_NoDiagData | Will not enable optional diagnostics data required for Smart App Control (Does not have any effect if Smart App Control is already turned on) | MicrosoftDefender |
| MSFTDefender_NoScheduledTask | Will not create scheduled task for fast MSFT driver block rules  | MicrosoftDefender |
| MSFTDefender_BetaChannels | Set Defender Engine and Intelligence update channels to beta | MicrosoftDefender |
| DeviceGuard_MandatoryVBS | Enables VBS and Memory Integrity in Mandatory Mode | DeviceGuard |
| LockScreen_CtrlAltDel | Require CTRL + ALT + Delete at lock screen | LockScreen |
| LockScreen_NoLastSignedIn | Will not display the last signed in user at the lock screen | LockScreen |
| UAC_NoFastSwitching | Hide entry points for fast user switching | UserAccountControl |
| UAC_OnlyElevateSigned | Only elevate signed and validated executables | UserAccountControl |
| WindowsNetworking_BlockNTLM | Blocks NTLM Completely | WindowsNetworking |
| Miscellaneous_WindowsProtectedPrint | Enables Windows Protected Print Mode | MiscellaneousConfigurations |
| MiscellaneousConfigurations_LongPathSupport | Enables support for long paths for the programs | MiscellaneousConfigurations |
| MiscellaneousConfigurations_StrongKeyProtection | Forces strong key protection | MiscellaneousConfigurations |
| MiscellaneousConfigurations_ReducedTelemetry | Implements policies that reduce OS telemetry | MiscellaneousConfigurations |
| CountryIPBlocking_OFAC | Include the IP ranges of OFAC Sanctioned Countries in the firewall block rules | CountryIPBlocking |
| DangerousScriptHostsBlocking | Deploys the Dangerous Script Hosts Blocking App Control Policy | DownloadsDefenseMeasures |

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

This cmdlet verifies and validates all of the applied security measures described on the Readme page. Compliance checking strictly follows the guidelines and security measures of this GitHub repository. Any minor deviation from them will result in a `false` value for the corresponding check.

The policies can be applied via a wide variety of ways and they will all be detected:

* Intune
* CIM
* Registry keys
* Group Policies
* PowerShell cmdlets
* Windows APIs

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

* [Bitlocker](https://github.com/HotCakeX/Harden-Windows-Security?tab=readme-ov-file#bitlocker-settings) Encrypted drives are not decrypted when you invoke this cmdlet. **Use the GUI experience to decrypt the BitLocker encrypted drives.**

* Security features related to [Device Guard](https://github.com/HotCakeX/Harden-Windows-Security?tab=readme-ov-file#device-guard) that are activated by UEFI Lock remain enabled even after you execute this cmdlet.

* [Windows optional features](https://github.com/HotCakeX/Harden-Windows-Security?tab=readme-ov-file#optional-windows-features) that are enabled or disabled by `Protect-WindowsSecurity` cmdlet are not affected.

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

Select the [App Control Policy](https://github.com/HotCakeX/Harden-Windows-Security?tab=readme-ov-file#downloads-defense-measures-) names to remove.

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

## Technical Details

Harden Windows Security is a hybrid software solution built on the latest available .NET runtime. Approximately 99% of its codebase is written in C#, with PowerShell serving as the initial launch platform. Upon startup in PowerShell, control is quickly transferred to the C# code, and then returned to PowerShell upon completion. This approach leverages the .NET runtime DLLs that are included with PowerShell, eliminating the need for users to install the .NET runtime separately.

The repository includes a Visual Studio solution that allows you to build the software directly. If you decide to compile it, it's highly recommended to completely review the code first, then sign the binaries with your code-signing certificate for use as a standalone application in personal, business, or enterprise environments. While the code can be modified if needed, no changes are required for a successful compilation result in the latest version of Visual Studio.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

<br>

Any feedback or suggestions? Please use GitHub [issues](https://github.com/HotCakeX/Harden-Windows-Security/issues) or [discussions](https://github.com/HotCakeX/Harden-Windows-Security/discussions)

<br>
