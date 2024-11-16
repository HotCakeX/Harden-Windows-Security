# Edit-WDACConfig available parameters

## Edit-WDACConfig -MergeSupplementalPolicies

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Edit-WDACConfig/Edit-WDACConfig%20-MergeSupplementalPolicies.apng)

## Syntax

```powershell
Edit-WDACConfig
     [-MergeSupplementalPolicies]
     -SuppPolicyName <String>
     [-PolicyPath <FileInfo>]
     -SuppPolicyPaths <FileInfo[]>
     [-KeepOldSupplementalPolicies]s
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
