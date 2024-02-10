# Edit-SignedWDACConfig available parameters

## Edit-SignedWDACConfig -AllowNewAppsAuditEvents

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Edit-SignedWDACConfig/Edit-SignedWDACConfig%20-AllowNewAppsAuditEvents.apng)

```powershell
Edit-SignedWDACConfig
     [-AllowNewAppsAuditEvents]
     -SuppPolicyName <String>
     [-PolicyPath <FileInfo>]
     [-CertPath <FileInfo>]
     [-CertCN <String>]
     [-LogSize <Int64>]
     [-NoScript]
     [-NoUserPEs]
     [-SpecificFileNameLevel <String>]
     [-IncludeDeletedFiles]
     [-Level <String>]
     [-Fallbacks <String[]>]
     [-SignToolPath <FileInfo>]
     [-SkipVersionCheck]
     [<CommonParameters>]
```

<br>

### How to Use

1. Using the provided syntax, run the command and supply values for the parameters.

2. When prompted to start installing your apps, do so and once you're done, press Enter to continue. The rest is automated.

### Description

While a Signed Windows Defender Application Control (WDAC) policy is already deployed on the system, rebootlessly turns on Audit mode in it, which will allow you to install a new app that was otherwise getting blocked. After installation, you will need to browse for the path(s) of the installed app(s) for scanning. The Audit logs that will be included in the scan are only the ones created from the time you ran the module with [-AllowNewAppsAuditEvents](#edit-signedwdacconfig--allownewappsauditevents) parameter till the time you finished app installations and browsed for folders to scan. This parameter can also be used for apps that are already installed on the system.

A new supplemental policy will be created, it will be signed and deployed on the system. The base policy that was initially set to Audit mode will also revert back to enforced mode. The entire process happens without the need for reboot. If something like a power outage occurs during the time Audit mode is deployed, on the next reboot, the enforced mode base policy will be automatically deployed.

This parameter is specially useful for applications that install files outside of their main install directory, such as system drivers. **Make sure you run those applications after installation (and before starting to browse for their install directories) so that Audit logs will capture and create allow rules for them.**

> [!NOTE]\
> This parameter can also detect and create allow rules for Kernel protected files, such as the executables of games installed using Xbox app. Make sure you run the game while the base policy is deployed in Audit mode so that it can capture those executables.

## Parameters

### -SuppPolicyName

Add a descriptive name for the Supplemental policy.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -CertPath

Path to the certificate `.cer` file. Press TAB to open the file picker GUI and browse for a `.cer` file.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| [Automatic:](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#about-automatic-parameters) | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -CertCN

Common name of the certificate - Supports argument completion so you don't have to manually enter the Certificate's CN, just make sure the `-CertPath` is specified and the certificate is installed in the personal store of the user certificates, then press TAB to auto complete the name. You can however enter it manually if you want to.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| [Automatic:](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#about-automatic-parameters) | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -PolicyPath

Browse for the xml file of the Base policy this Supplemental policy is going to expand. Supports tab completion by showing only `.xml` files with **Base Policy** Type.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| [Automatic:](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#about-automatic-parameters) | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -SignToolPath

Press TAB to open the file picker GUI and browse for SignTool.exe

> [!IMPORTANT]\
> Refer [to this section](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#the-logic-behind-the--signtoolpath-parameter-in-the-module) for more info

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| [Automatic:](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#about-automatic-parameters) | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -Debug

Indicates that the module will output these additional files for debugging purposes and also show debug messages on the console:

* *FileRulesAndFileRefs.txt* - Contains the File Rules and Rule refs for the Hash of the files that no longer exist on the disk.

* *DeletedFileHashesEventsPolicy.xml* - If `-IncludeDeletedFiles` was used and if there were any files detected that were in audit event logs that are no longer on the disk, this file will include allow rules for them based on their hashes.

* *ProgramDir_ScanResults*.xml* - xml policy files for each program path that is selected by user, contains allow rules.

* *RulesForFilesNotInUserSelectedPaths.xml* - xml policy file that has allow rules for files that do not reside in any of the user-selected program paths, but have been detected in audit event logs.

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

### -Levels

Offers the same official [Levels](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-level) for scanning of event logs.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | FilePublisher |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -Fallbacks

Offers the same official [Fallbacks](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-fallback) for scanning of event logs.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)[]|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | Hash |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -LogSize

Specifies the log size for ***Microsoft-Windows-CodeIntegrity/Operational*** events. The values must be in the form of `<Digit + Data measurement unit>`. e.g., 2MB, 10MB, 1GB, 1TB. The minimum accepted value is 1MB which is the default.

<div align='center'>

| Type: |[UInt64](https://learn.microsoft.com/en-us/dotnet/api/system.uint64)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -SpecificFileNameLevel

You can choose one of the following options:

* OriginalFileName
* InternalName
* FileDescription
* ProductName
* PackageFamilyName
* FilePath

[More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-specificfilenamelevel)

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -IncludeDeletedFiles

Indicates that hashes of the files that were run during Audit phase but then were deleted and are no longer on the disk, will be added to the Supplemental policy.

> [!NOTE]\
> If you created a Supplemental policy for your program and it's still getting blocked, try using this parameter. Chances are your program writes and then deletes some files during runtime that are necessary to be included in the Supplemental policy.

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

### -NoUserPEs

By default, the module includes user PEs in the scan. When you use this switch parameter, they won't be included. [More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-userpes)

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

### -NoScript

[More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-noscript)

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

## Edit-SignedWDACConfig -AllowNewApps

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Edit-SignedWDACConfig/Edit-SignedWDACConfig%20-AllowNewApps.apng)

```powershell
Edit-SignedWDACConfig
     [-AllowNewApps]
     -SuppPolicyName <String>
     [-PolicyPath <FileInfo>]
     [-CertPath <FileInfo>]
     [-CertCN <String>]
     [-NoScript]
     [-NoUserPEs]
     [-SpecificFileNameLevel <String>]
     [-Level <String>]
     [-Fallbacks <String[]>]
     [-SignToolPath <FileInfo>]
     [-SkipVersionCheck]
     [<CommonParameters>]
```

<br>

### How to use

1. Using the provided syntax, run the command and supply values for the parameters.

2. When prompted to start installing your apps, do so and once you're done, press Enter to continue. The rest is automated.

### Description

While a Signed Windows Defender Application Control (WDAC) policy is already deployed on the system, rebootlessly turns on Audit mode in it, which will allow you to install a new app that was otherwise getting blocked. After installation, you will need to browse for the path(s) of the installed app(s) for scanning. This parameter can also be used for apps that are already installed on the system.

A new supplemental policy will be created, it will be signed and deployed on the system. The base policy that was initially set to Audit mode will also revert back to enforced mode. The entire process happens without the need for reboot. If something like a power outage occurs during the time Audit mode is deployed, on the next reboot, the enforced mode base policy will be automatically deployed.

## Parameters

### -SuppPolicyName

Add a descriptive name for the Supplemental policy.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -CertPath

Path to the certificate `.cer` file. Press TAB to open the file picker GUI and browse for a `.cer` file.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| [Automatic:](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#about-automatic-parameters) | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -CertCN

Common name of the certificate - Supports argument completion so you don't have to manually enter the Certificate's CN, just make sure the `-CertPath` is specified and the certificate is installed in the personal store of the user certificates, then press TAB to auto complete the name. You can however enter it manually if you want to.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| [Automatic:](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#about-automatic-parameters) | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -PolicyPath

Browse for the xml file of the Base policy this Supplemental policy is going to expand. Supports tab completion by showing only `.xml` files with **Base Policy** Type.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| [Automatic:](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#about-automatic-parameters) | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -SignToolPath

Press TAB to open the file picker GUI and browse for SignTool.exe

> [!IMPORTANT]\
> Refer [to this section](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#the-logic-behind-the--signtoolpath-parameter-in-the-module) for more info

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| [Automatic:](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#about-automatic-parameters) | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -Levels

Offers the same official [Levels](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-level) for scanning of the specified directory path.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | FilePublisher |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -Fallbacks

Offers the same official [Fallbacks](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-fallback) for scanning of the specified directory path.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)[]|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | Hash |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -NoUserPEs

By default, the module includes user PEs in the scan. When you use this switch parameter, they won't be included. [More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-userpes)

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

### -NoScript

[More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-noscript)

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

### -SpecificFileNameLevel

You can choose one of the following options:

* OriginalFileName
* InternalName
* FileDescription
* ProductName
* PackageFamilyName
* FilePath

[More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-specificfilenamelevel)

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
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

## Edit-SignedWDACConfig -MergeSupplementalPolicies

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Edit-SignedWDACConfig/Edit-SignedWDACConfig%20-MergeSupplementalPolicies.apng)

```powershell
Edit-SignedWDACConfig
     [-MergeSupplementalPolicies]
     -SuppPolicyName <String>
     -SuppPolicyPaths <FileInfo[]>
    [-PolicyPath <FileInfo>]
    [-KeepOldSupplementalPolicies]
    [-CertPath <FileInfo>]
    [-CertCN <String>]
    [-SignToolPath <FileInfo>]
    [-SkipVersionCheck]
    [<CommonParameters>]
```

<br>

Merge multiple deployed **Signed** Supplemental policies into 1 and deploy it, remove the individual ones, all happening automatically. Very useful to keep Supplemental policies below 32 since that's the limit.

## Parameters

### -SuppPolicyName

Choose a descriptive name for the Supplemental policy that is going to be the merge of multiple policies.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -SuppPolicyPaths

Path to the Supplemental policies xml files. Supports argument tab completion by showing only Supplemental policy types.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)[]|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -CertPath

Path to the certificate `.cer` file. Press TAB to open the file picker GUI and browse for a `.cer` file.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| [Automatic:](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#about-automatic-parameters) | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -CertCN

Common name of the certificate - Supports argument completion so you don't have to manually enter the Certificate's CN, just make sure the `-CertPath` is specified and the certificate is installed in the personal store of the user certificates, then press TAB to auto complete the name. You can however enter it manually if you want to.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| [Automatic:](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#about-automatic-parameters) | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -PolicyPath

Browse for the xml file of the Base policy this Supplemental policy is going to expand. Supports tab completion by showing only `.xml` files with **Base Policy** Type.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -SignToolPath

Press TAB to open the file picker GUI and browse for SignTool.exe

> [!IMPORTANT]\
> Refer [to this section](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#the-logic-behind-the--signtoolpath-parameter-in-the-module) for more info

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| [Automatic:](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#about-automatic-parameters) | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -KeepOldSupplementalPolicies

Indicates that the module will not remove the old Supplemental policy xml files after creating and deploying the new merged one.

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

## Edit-SignedWDACConfig -UpdateBasePolicy

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Edit-SignedWDACConfig/Edit-SignedWDACConfig%20-UpdateBasePolicy.apng)

```powershell
Edit-SignedWDACConfig
     [-UpdateBasePolicy]
     -CurrentBasePolicyName <String[]>
     -NewBasePolicyType <String>
     [-CertPath <FileInfo>]
     [-CertCN <String>]
     [-SignToolPath <FileInfo>]
     [-RequireEVSigners]
     [-SkipVersionCheck]
     [<CommonParameters>]
```

<br>

It can rebootlessly change the type of the deployed signed base policy. It can update the recommended block rules and/or change policy rule options in the deployed base policy. The deployed Supplemental policies will stay intact and continue to work with the new Base policy.

> [!NOTE]\
> When switching from a more permissive base policy type to a more restrictive one, make sure your Supplemental policies will continue to work. E.g., if your current base policy type is *Allow Microsoft* and the one you are switching to is *Default Windows*, there *might* be files that will get blocked as a result of this switch if you created a Supplemental policy using Event viewer capturing. That's simply because they were allowed by the more permissive *Allow Microsoft* policy type so they didn't trigger audit logs thus weren't needed to be included in the Supplemental policy. You will need to update those Supplemental policies if that happens by deleting and recreating them, no immediate reboot required.

## Parameters

### -CurrentBasePolicyName

The name of the currently deployed base policy. It supports tab completion so just press tab to autofill it.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -NewBasePolicyType

The type of the base policy to deploy. It supports tab completion so just press tab to autofill it. Supports all 3 Base policy types:

* [AllowMicrosoft_Plus_Block_Rules](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig#new-wdacconfig--makeallowmsftwithblockrules)
* [Lightly_Managed_system_Policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig#new-wdacconfig--makelightpolicy)
* [DefaultWindows_WithBlockRules](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig#new-wdacconfig--makedefaultwindowswithblockrules)

> [!NOTE]\
>  Since the module uses PowerShell and not Windows PowerShell that is pre-installed in Windows, selecting this argument will automatically scan `C:\Program Files\PowerShell` directory and add PowerShell files to the base policy (If the module detects that the PowerShell is not installed from Microsoft Store) so that you will be able to continue using the module after redeploying the base policy. The scan uses ***FilePublisher*** level and ***Hash*** fallback.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -CertPath

Path to the certificate `.cer` file. Press TAB to open the file picker GUI and browse for a `.cer` file.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| [Automatic:](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#about-automatic-parameters) | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -CertCN

Common name of the certificate - Supports argument completion so you don't have to manually enter the Certificate's CN, just make sure the `-CertPath` is specified and the certificate is installed in the personal store of the user certificates, then press TAB to auto complete the name. You can however enter it manually if you want to.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| [Automatic:](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#about-automatic-parameters) | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -SignToolPath

Press TAB to open the file picker GUI and browse for SignTool.exe

> [!IMPORTANT]\
> Refer [to this section](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#the-logic-behind-the--signtoolpath-parameter-in-the-module) for more info

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| [Automatic:](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#about-automatic-parameters) | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -RequireEVSigners

Indicates that the created/deployed policy will have [Require EV Signers](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/wdac-wizard-create-base-policy#advanced-policy-rules-description) policy rule option.

* In addition to being WHQL signed, this rule requires that drivers must have been submitted by a partner that has an Extended Verification (EV) certificate. All Windows 10 and later, or Windows 11 drivers will meet this requirement.

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

<br>
