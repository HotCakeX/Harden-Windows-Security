# Edit-SignedWDACConfig available parameters

## Edit-SignedWDACConfig -AllowNewAppsAuditEvents

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Edit-SignedWDACConfig/Edit-SignedWDACConfig%20-AllowNewAppsAuditEvents.apng)

```powershell
Edit-SignedWDACConfig [-AllowNewAppsAuditEvents] -SuppPolicyName <String> [-PolicyPath <String>] [-CertPath
<String>] [-CertCN <String>] [-LogSize <Int64>] [-NoScript] [-NoUserPEs] [-SpecificFileNameLevel <String>]
[-IncludeDeletedFiles] [-Level <String>] [-Fallbacks <String[]>] [-SignToolPath <String>] [-SkipVersionCheck]
[<CommonParameters>]
```

<br>

### How to use

1. Using the provided syntax, run the command and supply values for the parameters.

2. When prompted to start installing your apps, do so and once you're done, press Enter to continue. The rest is automated.

### Description

While a Signed Windows Defender Application Control (WDAC) policy is already deployed on the system, rebootlessly turns on Audit mode in it, which will allow you to install a new app that was otherwise getting blocked. After installation, you will need to browse for the path(s) of the installed app(s) for scanning. The Audit logs that will be included in the scan are only the ones created from the time you ran the module with [-AllowNewAppsAuditEvents](#edit-signedwdacconfig--allownewappsauditevents) parameter till the time you finished app installations and browsed for folders to scan. This parameter can also be used for apps that are already installed on the system.

A new supplemental policy will be created, it will be signed and deployed on the system. The base policy that was initially set to Audit mode will also revert back to enforced mode. The entire process happens without the need for reboot. If something like a power outage occurs during the time Audit mode is deployed, on the next reboot, the enforced mode base policy will be automatically deployed.

This parameter is specially useful for applications that install files outside of their main install directory, such as system drivers. **Make sure you run those applications after installation (and before starting to browse for their install directories) so that Audit logs will capture and create allow rules for them.**

**This parameter can also detect and create allow rules for Kernel protected files, such as the executables of games installed using Xbox app. Make sure you run the game while the base policy is deployed in Audit mode, using this parameter, so that it can capture those executables.**

### 1 Mandatory Parameter

* `-SuppPolicyName <String>`: Add a descriptive name for the Supplemental policy.

### 3 Automatic Parameters

* `-CertPath <String>`: Path to the certificate `.cer` file. Supports tab completion by showing only `.cer` files.

* `-PolicyPath <String>`: Browse for the xml file of the Base policy this Supplemental policy is going to expand. Supports tab completion by showing only `.xml` files with **Base Policy** Type.

* `-CertCN <String>`: Common name of the certificate used to sign the deployed WDAC policies - Supports argument completion so you don't have to manually enter the Certificate's CN, just make sure the certificate is installed in the personal store of the user certificates, then press TAB to auto complete the name. You can however enter it manually if you want to.

### 9 Optional Parameters

* `-SignToolPath <String>`: Press TAB to open the file picker GUI and browse for SignTool.exe. [You can use it in 2 different ways](#signtool-bottom)

* `-Debug`: Indicates that the module will output these additional files for debugging purposes and also show debug messages on the console:
     - *FileRulesAndFileRefs.txt* - Contains the File Rules and Rule refs for the Hash of the files that no longer exist on the disk.
     - *DeletedFileHashesEventsPolicy.xml* - If `-IncludeDeletedFiles` was used and if there were any files detected that were in audit event logs that are no longer on the disk, this file will include allow rules for them based on their hashes.
     - *ProgramDir_ScanResults*.xml* - xml policy files for each program path that is selected by user, contains allow rules.
     - *RulesForFilesNotInUserSelectedPaths.xml* - xml policy file that has allow rules for files that do not reside in any of the user-selected program paths, but have been detected in audit event logs.

* `-Levels <String>`: Offers the same official [Levels](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-level) for scanning of the specified directory paths and Event viewer audit logs. The Default value is ***FilePublisher***.

* `-Fallbacks <String[]>`: Offers the same official [Fallbacks](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-fallback) for scanning of the specified directory paths and Event viewer audit logs. The Default value is ***Hash***.

* `-LogSize <Int64>` - Specifies the log size for ***Microsoft-Windows-CodeIntegrity/Operational*** events. The values must be in the form of `<Digit + Data measurement unit>`. e.g., 2MB, 10MB, 1GB, 1TB. The minimum accepted value is 1MB which is the default.

* `-SpecificFileNameLevel`: You can choose one of the following options: "OriginalFileName", "InternalName", "FileDescription", "ProductName", "PackageFamilyName", "FilePath". [More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-specificfilenamelevel)

* `-IncludeDeletedFiles`: Indicates that hashes of the files that were run during Audit phase but then were deleted and are no longer on the disk, will be added to the Supplemental policy. *If you created a Supplemental policy for your program and it's still getting blocked, try using this parameter. Chances are your program writes and then deletes some files during runtime that are necessary to be included in the Supplemental policy.*

* `-NoUserPEs`: By default the module includes user PEs in the scans. When you use this switch parameter, they won't be included. [More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-userpes)

* `-NoScript`: [More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-noscript)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Edit-SignedWDACConfig -AllowNewApps

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Edit-SignedWDACConfig/Edit-SignedWDACConfig%20-AllowNewApps.apng)

```powershell
Edit-SignedWDACConfig [-AllowNewApps] -SuppPolicyName <String> [-PolicyPath <String>] [-CertPath <String>]
[-CertCN <String>] [-NoScript] [-NoUserPEs] [-SpecificFileNameLevel <String>] [-Level <String>] [-Fallbacks
<String[]>] [-SignToolPath <String>] [-SkipVersionCheck] [<CommonParameters>]
```

<br>

### How to use

1. Using the provided syntax, run the command and supply values for the parameters.

2. When prompted to start installing your apps, do so and once you're done, press Enter to continue. The rest is automated.

### Description

While a Signed Windows Defender Application Control (WDAC) policy is already deployed on the system, rebootlessly turns on Audit mode in it, which will allow you to install a new app that was otherwise getting blocked. After installation, you will need to browse for the path(s) of the installed app(s) for scanning. This parameter can also be used for apps that are already installed on the system.

A new supplemental policy will be created, it will be signed and deployed on the system. The base policy that was initially set to Audit mode will also revert back to enforced mode. The entire process happens without the need for reboot. If something like a power outage occurs during the time Audit mode is deployed, on the next reboot, the enforced mode base policy will be automatically deployed.

### 1 Mandatory Parameter

* `-SuppPolicyName <String>`: Add a descriptive name for the Supplemental policy.

### 3 Automatic Parameters

* `-CertPath <String>`: Path to the certificate `.cer` file. Supports tab completion by showing only `.cer` files.

* `-PolicyPath <String>`: Browse for the xml file of the Base policy this Supplemental policy is going to expand. Supports tab completion by showing only `.xml` files with **Base Policy** Type.

* `-CertCN <String>`: Common name of the certificate used to sign the deployed WDAC policies - Supports argument completion so you don't have to manually enter the Certificate's CN, just make sure the certificate is installed in the personal store of the user certificates, then press TAB to auto complete the name. You can however enter it manually if you want to.

### 6 Optional Parameters

* `-SignToolPath <String>`: Press TAB to open the file picker GUI and browse for SignTool.exe. [You can use it in 2 different ways](#signtool-bottom)

* `-Levels <String>`: Offers the same official [Levels](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-level) for scanning of the specified directory paths. If no level is specified the default, which is set to ***FilePublisher*** in this module, will be used.

* `-Fallbacks <String[]>`: Offers the same official [Fallbacks](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-fallback) for scanning of the specified directory paths. If no fallbacks is specified the default, which is set to ***Hash*** in this module, will be used.

* `-NoUserPEs`: By default the module includes user PEs in the scans. When you use this switch parameter, they won't be included. [More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-userpes)

* `-NoScript`: [More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-noscript)

* `-SpecificFileNameLevel`: You can choose one of the following options: "OriginalFileName", "InternalName", "FileDescription", "ProductName", "PackageFamilyName", "FilePath". [More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-specificfilenamelevel)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Edit-SignedWDACConfig -MergeSupplementalPolicies

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Edit-SignedWDACConfig/Edit-SignedWDACConfig%20-MergeSupplementalPolicies.apng)

```powershell
Edit-SignedWDACConfig [-MergeSupplementalPolicies] -SuppPolicyName <String> -SuppPolicyPaths <String[]>
[-PolicyPath <String>] [-KeepOldSupplementalPolicies] [-CertPath <String>] [-CertCN <String>] [-SignToolPath
<String>] [-SkipVersionCheck] [<CommonParameters>]
```

<br>

Merge multiple deployed **Signed** Supplemental policies into 1 and deploy it, remove the individual ones, all happening automatically. Very useful to keep Supplemental policies below 32 since that's the limit.

### 2 Mandatory Parameters

* `-SuppPolicyName <String>`: Choose a descriptive name for the Supplemental policy that is going to be the merge of multiple policies.

* `-SuppPolicyPaths <String[]>`: Path to the Supplemental policies xml files. Supports argument tab completion by showing only Supplemental policy types.

### 3 Automatic parameters

* `-PolicyPath <String>`: Path to the Base policy xml file the Supplemental policies belong to. Supports argument tab completion by showing only Base policy types.

* `-CertCN <String>`: Common name of the certificate used to sign the deployed WDAC policies - Supports argument completion so you don't have to manually enter the Certificate's CN, just make sure the certificate is installed in the personal store of the user certificates, then press TAB to auto complete the name. You can however enter it manually if you want to.

* `-CertPath <String>`: Path to the certificate `.cer` file. Supports tab completion by showing only `.cer` files.

### 2 Optional Parameters

* `-SignToolPath <String>`: Press TAB to open the file picker GUI and browse for SignTool.exe. [You can use it in 2 different ways](#signtool-bottom)

* `-KeepOldSupplementalPolicies`: Indicates that the module will not remove the old Supplemental policy xml files after creating and deploying the new merged one.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Edit-SignedWDACConfig -UpdateBasePolicy

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Edit-SignedWDACConfig/Edit-SignedWDACConfig%20-UpdateBasePolicy.apng)

```powershell
Edit-SignedWDACConfig [-UpdateBasePolicy] -CurrentBasePolicyName <String[]> -NewBasePolicyType <String> [-CertPath <String>] [-CertCN <String>] [-SignToolPath <String>] [-RequireEVSigners] [-SkipVersionCheck] [<CommonParameters>]
```

<br>

It can rebootlessly change the type of the deployed signed base policy. It can update the recommended block rules and/or change policy rule options in the deployed base policy. The deployed Supplemental policies will stay intact and continue to work with the new Base policy.

**Hint:** When switching from a more permissive base policy type to a more restrictive one, make sure your Supplemental policies will continue to work. E.g., if your current base policy type is *Allow Microsoft* and the one you are switching to is *Default Windows*, there *might* be files that will get blocked as a result of this switch if you created a Supplemental policy using Event viewer capturing. That's simply because they were allowed by the more permissive *Allow Microsoft* policy type so they didn't trigger audit logs thus weren't needed to be included in the Supplemental policy. You will need to update those Supplemental policies if that happens by deleting and recreating them, no immediate reboot required.

### 2 Mandatory Parameters

* `-CurrentBasePolicyName <String[]>`: The name of the currently deployed base policy. It supports tab completion so just press tab to autofill it.

* `-NewBasePolicyType <String>`: The type of the base policy to deploy. It supports tab completion so just press tab to autofill it. Supports all 3 Base policy types:

     - [AllowMicrosoft_Plus_Block_Rules](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig#new-wdacconfig--makeallowmsftwithblockrules)

     - [Lightly_Managed_system_Policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig#new-wdacconfig--makelightpolicy)

     - [DefaultWindows_WithBlockRules](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig#new-wdacconfig--makedefaultwindowswithblockrules)

        - > Since the module uses PowerShell and not Windows PowerShell that is pre-installed in Windows, selecting this argument will automatically scan `C:\Program Files\PowerShell` directory and add PowerShell files to the base policy so that you will be able to continue using the module after redeploying the base policy. The scan uses ***FilePublisher*** level and ***Hash*** fallback.

### 2 Automatic Parameters

* `-CertPath <String>`: Path to the certificate `.cer` file used to sign the deployed base policy. Supports tab completion by showing only `.cer` files.

* `-CertCN <String>`: Common name of the certificate used to sign the deployed base WDAC policy - Supports argument completion so you don't have to manually enter the Certificate's CN, just make sure the certificate is installed in the personal store of the user certificates, then press TAB to auto complete the name. You can however enter it manually if you want to.

### 2 Optional Parameters

* `-SignToolPath <String>`: Press TAB to open the file picker GUI and browse for SignTool.exe. [You can use it in 2 different ways](#signtool-bottom)

* `-RequireEVSigners`: Indicates that the base policy will have [Require EV Signers](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/wdac-wizard-create-base-policy#advanced-policy-rules-description) policy rule option.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Notes

* **Mandatory** parameters indicate you always need to provide values for them.

* **Automatic** parameters indicate that if you used [Set-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig) cmdlet to set default values for them, the module will automatically use them. This saves time and prevents repetitive tasks. However, if no value exists in User Configurations for an Automatic parameter and you didn't explicitly provide a value for that parameter either, then you will see an error asking you to provide value for it. Explicitly providing a value for an Automatic parameter in the command line overrides its default value in User Configurations, meaning the module will ignore the value of the same parameter in the User Configurations file.

* **Optional** parameters indicate that they are not required and without using them the module will automatically run with the optimal settings.

<br>

### The logic behind `-SignToolPath <String>` optional parameter

<a name="signtool-bottom"></a>

1. If [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/) Signing Tools for Desktop Apps components is installed in the default location `C:\Program Files (x86)\Windows Kits`, then `-SignToolPath <String>` parameter isn't necessary.

2. If Windows SDK Signing Tools for Desktop Apps components is not installed in the default location or you want to manually browse for the `signtool.exe`, then make sure you either specify its path using `Set-CommonWDACConfig -SignToolPath` or use the `-SignToolPath <String>` parameter.

3. If SignTool.exe path is available in user configurations then it will be used, unless the `-SignToolPath <String>` parameter is specified which takes priority over auto detection and user configurations.

4. Unless you specify the `-SignToolPath <String>` parameter, or the SignTool.exe path already exists in your user configurations or on your system, you will receive a prompt to authorize the automatic download of the most recent SignTool.exe version from the official Microsoft servers. Upon confirmation, it will be saved in your user configurations and utilized by the cmdlet.

<br>
