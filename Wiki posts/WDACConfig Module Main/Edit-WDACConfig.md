# Edit-WDACConfig available parameters

## Edit-WDACConfig -AllowNewApps

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Edit-WDACConfig/Edit-WDACConfig%20-AllowNewApps.apng)

## Syntax

```powershell
Edit-WDACConfig
     [-AllowNewApps]
     -SuppPolicyName <String>
     [-BoostedSecurity]
     [-PolicyPath <FileInfo>]
     [-Level <String>]
     [-Fallbacks <String[]>]
     [-NoScript]
     [-NoUserPEs]
     [-SpecificFileNameLevel <String>]
     [-LogSize <UInt64>]
     [-SkipVersionCheck]
     [<CommonParameters>]
```

## Description

While an App Control for Business policy is already deployed on the system, rebootlessly turns on Audit mode in it, which will allow you to install a new app that was otherwise getting blocked.

After installation, you will be able to browse for the path(s) of the installed app(s) for scanning, which is optional.

Any file outside of the paths you select that was executed or run during the audit mode phase and was detected in the audit logs, will be displayed to you in a nice GUI (Graphical User Interface) so you will be able to see detailed information about them and decide whether to include them in the Supplemental policy or not.

This parameter can also be used for apps that are already installed on the system.

A new supplemental policy will be created and deployed on the system. The base policy that was initially set to Audit mode will also revert back to enforced mode. The entire process happens without the need for reboot. If something like a power outage occurs during the audit mode phase, on the next reboot, the enforced mode base policy will be automatically deployed.

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

### -BoostedSecurity

Implements Sandboxing-like restrictions around the program's dependencies.

> [!TIP]\
> When using this mode, it's recommended to only target one program at a time. E.g., don't use this method for creating a supplemental policy for Adobe Photoshop and Steam client at the same time, because they will be put in the same supplemental policy and the dependency sandboxing will be ineffective.
>
> This mode requires the main executable(s) of the programs that need access to the dependencies (such as DLLs) to have the `OriginalFileName` property. Most of the time they do. Use the `-Verbose` parameter to see when they don't.

<div align="center">
<a href="https://www.youtube.com/watch?v=cp7TaTNPZE0"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Thumbnails%20with%20YouTube%20play%20logo/YouTube%20Thumbnail%20-%20Sandboxing-like%20capabilities%20of%20WDAC%20Policies.png" alt="Boosted security dependencies in App Control policies" width="500"></a></div>

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

### -Levels

Offers the same official [Levels](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-level) for scanning event logs and the specified directory path(s).

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | `WHQLFilePublisher` |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -Fallbacks

Offers the same official [Fallbacks](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-fallback) for scanning event logs and the specified directory path(s).

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)[]|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | `FilePublisher`,`Hash` |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -SpecificFileNameLevel

[More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-specificfilenamelevel)

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Accepted values: | `OriginalFileName`, `InternalName`, `FileDescription`, `ProductName`, `PackageFamilyName`, `FilePath` |
| Default value: | None |
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

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Edit-WDACConfig -MergeSupplementalPolicies

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Edit-WDACConfig/Edit-WDACConfig%20-MergeSupplementalPolicies.apng)

## Syntax

```powershell
Edit-WDACConfig
     [-MergeSupplementalPolicies]
     -SuppPolicyName <String>
     [-PolicyPath <FileInfo>]
     -SuppPolicyPaths <FileInfo[]>
     [-KeepOldSupplementalPolicies]
     [-SkipVersionCheck]
     [<CommonParameters>]
```

## Description

Merge multiple deployed Supplemental policies into 1 and deploy it, remove the individual ones, all happening automatically.

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

### -PolicyPath

Path to the Base policy xml file the Supplemental policies belong to. Supports argument tab completion by showing only Base policy types.

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

## Edit-WDACConfig -UpdateBasePolicy

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Edit-WDACConfig/Edit-WDACConfig%20-UpdateBasePolicy.apng)

## Syntax

```powershell
Edit-WDACConfig
     [-UpdateBasePolicy]
     -CurrentBasePolicyName <String[]>
     -NewBasePolicyType <String>
     [-RequireEVSigners]
     [-SkipVersionCheck]
     [<CommonParameters>]
```

## Description

It can rebootlessly change the type or rule options of the deployed base policy. The deployed Supplemental policies will stay intact and continue to work with the new Base policy.

> [!NOTE]\
> When switching from a more permissive base policy type to a more restrictive one, make sure your Supplemental policies will continue to work. E.g., if your current base policy type is *AllowMicrosoft* and the one you are switching to is *DefaultWindows*, there *might* be files that will get blocked as a result of this switch.
>
> That's simply because they were allowed by the more permissive *AllowMicrosoft* policy type so they didn't trigger audit logs (in case the supplemental policy was created based on audit logs) thus weren't needed to be included in the Supplemental policy. You will need to update those Supplemental policies if that happens by deleting and recreating them, no immediate reboot required.

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

The new type of the base policy to deploy. It supports tab completion so just press tab to autofill it. Supports all 3 main Base policy types.

> [!NOTE]\
> If the selected policy type is `DefaultWindows` and the detected PowerShell is not installed through Microsoft Store, the module will scan the PowerShell files and add them to the `DefaultWindows` base policy as allowed files so you will be able to continue using the module after deploying the policy.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Accepted values: | `AllowMicrosoft`, `DefaultWindows`, `SignedAndReputable` |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -RequireEVSigners

Indicates that the created/deployed policy will have [Require EV Signers](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/appcontrol-wizard-create-base-policy#advanced-policy-rules-description) policy rule option.

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
