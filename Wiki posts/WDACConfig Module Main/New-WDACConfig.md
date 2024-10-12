# New-WDACConfig available parameters

## New-WDACConfig -PolicyType

<div align="center">
<a href="https://www.youtube.com/watch?v=JSwrfe9zYY4"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Thumbnails%20with%20YouTube%20play%20logo/YouTube%20Thumbnail%20-%20create%2C%20audit%20and%20deploy%20WDAC%20policies.png" alt="How to create, deploy and audit WDAC policies" width="550"></a></div>

<br>

![New-WDACConfig -PolicyType](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-WDACConfig/New-WDACConfig%20-PolicyType.apng)

## Syntax

```powershell
New-WDACConfig
    [-PolicyType <String>]
    [-Deploy]
    [-Audit]
    [-TestMode]
    [-RequireEVSigners]
    [-EnableScriptEnforcement]
    [-LogSize <UInt64>]
```

## Description

Use this parameter to create a new App Control **base policy** with different policy types and configurations.

> [!NOTE]\
> If the selected policy type is `DefaultWindows` and the detected PowerShell is not installed through Microsoft Store, the module will scan the PowerShell files and add them to the `DefaultWindows` base policy as allowed files so you will be able to continue using the module after deploying the policy.

> [!Tip]\
> The `SignedAndReputable` policy type uses ISG, [The Microsoft Intelligent Security Graph](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph).

## Parameters

### -PolicyType

There are 3 policy types you can choose from and they are listed below:

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

### -Deploy

Indicates that the policy is to be deployed to the local machine.

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

### -Audit

Turns on Audit mode in the policy so that the policy will be auditing files after deployment instead of blocking them.

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

### -TestMode

Indicates that the created policy will have ***Enabled:Boot Audit on Failure*** and ***Enabled:Advanced Boot Options Menu*** [policy rule options](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#table-1-app-control-for-business-policy---policy-rule-options).

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

### -RequireEVSigners

Indicates that the created policy will have [Require EV Signers](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/appcontrol-wizard-create-base-policy#advanced-policy-rules-description) policy rule option.

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

### -EnableScriptEnforcement

Enables [script enforcement](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/script-enforcement) in the created policy.

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

### -LogSize

> [!NOTE]\
> This parameter is only available when the `-Audit` parameter is used.

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

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-WDACConfig -GetUserModeBlockRules

![New-WDACConfig -GetUserModeBlockRules](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-WDACConfig/New-WDACConfig%20-GetUserModeBlockRules.apng)

## Syntax

```powershell
New-WDACConfig
    [-GetUserModeBlockRules]
    [-Deploy]
```

## Description

Downloads the latest [Microsoft Recommended User-Mode Block Rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol).

## Parameters

### -Deploy

Indicates that the policy is to be deployed to the local machine.

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

## New-WDACConfig -GetDriverBlockRules

![New-WDACConfig -GetDriverBlockRules](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-WDACConfig/New-WDACConfig%20-GetDriverBlockRules.apng)

## Syntax

```powershell
New-WDACConfig
    [-GetDriverBlockRules]
    [-Deploy]
    [-AutoUpdate]
```

## Description

Downloads the latest [Microsoft Recommended Drivers Block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules).

## Parameters

### -Deploy

Indicates that the policy is to be deployed to the local machine.

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

### -AutoUpdate

Creates a scheduled task that runs every 7 days to automatically perform [the official method](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules#steps-to-download-and-apply-the-vulnerable-driver-blocklist-binary) for updating Microsoft recommended driver block rules.

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>