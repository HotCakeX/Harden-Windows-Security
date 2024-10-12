# ConvertTo-WDACPolicy available parameters

## Syntax

```powershell
ConvertTo-WDACPolicy
    [-PolicyToAddLogsTo <FileInfo>]
    [-Source <String>]
    [-SuppPolicyName <String>]
    [-Level <String>]
    [-MDEAHLogs <FileInfo[]>]
    [-EVTXLogs <FileInfo[]>]
    [-FilterByPolicyNames <String[]>]
    [-TimeSpan <String>]
    [-TimeSpanAgo <UInt64>]
    [-KernelModeOnly]
    [-LogType <String>]
    [-Deploy]
    [-ExtremeVisibility]
    [<CommonParameters>]
```

```powershell
ConvertTo-WDACPolicy
    [-BasePolicyFile <FileInfo>]
    [-Source <String>]
    [-SuppPolicyName <String>]
    [-Level <String>]
    [-MDEAHLogs <FileInfo[]>]
    [-EVTXLogs <FileInfo[]>]
    [-FilterByPolicyNames <String[]>]
    [-TimeSpan <String>]
    [-TimeSpanAgo <UInt64>]
    [-KernelModeOnly]
    [-LogType <String>]
    [-Deploy]
    [-ExtremeVisibility]
    [<CommonParameters>]
```

```powershell
ConvertTo-WDACPolicy
    [-BasePolicyGUID <Guid>]
    [-Source <String>]
    [-SuppPolicyName <String>]
    [-Level <String>]
    [-MDEAHLogs <FileInfo[]>]
    [-EVTXLogs <FileInfo[]>]
    [-FilterByPolicyNames <String[]>]
    [-TimeSpan <String>]
    [-TimeSpanAgo <UInt64>]
    [-KernelModeOnly]
    [-LogType <String>]
    [-Deploy]
    [-ExtremeVisibility]
    [<CommonParameters>]
```

## Description

This is a multi-purpose cmdlet that offers a wide range of functionalities that can either be used separately or mixed together for very detailed and specific tasks.

It currently supports Code Integrity and AppLocker logs from the following sources:

* **Local Event logs**
* **Evtx log files**
* **Microsoft Defender for Endpoint Advanced Hunting results**

The cmdlet displays the logs in a GUI and allows the user to select the logs to be processed further.

The logs can be filtered based on many criteria using the available parameters.

The output of this cmdlet is a Supplemental Application Control (WDAC) policy.
Based on the input parameters, it can be associated with a base policy or merged with an existing Base or Supplemental policy.

The cmdlet can be used for local and remote systems. You can utilize this cmdlet to create App Control for Business policies from MDE Advanced Hunting and then deploy them using Microsoft Intune to your endpoints.

You can utilize this cmdlet to use the evtx log files you aggregated from your endpoints and create an App Control policy from them.

This offers scalability and flexibility in managing your security policies.

## Parameters

### -PolicyToAddLogsTo

The policy to add the selected logs to, it can either be a base or supplemental policy.

> [!IMPORTANT]\
> Only select one of the following three parameters: `-PolicyToAddLogsTo`, `-BasePolicyFile`, or `-BasePolicyGUID`.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Aliases: | AddLogs |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -BasePolicyFile

The base policy file to associate the supplemental policy with.

> [!IMPORTANT]\
> Only select one of the following three parameters: `-PolicyToAddLogsTo`, `-BasePolicyFile`, or `-BasePolicyGUID`.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Aliases: | BaseFile |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -BasePolicyGUID

The GUID of the base policy to associate the supplemental policy with.

> [!IMPORTANT]\
> Only select one of the following three parameters: `-PolicyToAddLogsTo`, `-BasePolicyFile`, or `-BasePolicyGUID`.

<div align='center'>

| Type: |[Guid](https://learn.microsoft.com/en-us/dotnet/api/system.guid)|
| :-------------: | :-------------: |
| Aliases: | BaseGUID |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -Source

The source of the logs. Supports validate set and auto-completion, press TAB key to view the list of the available options.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Aliases: | Src |
| Position: | Named |
| Accepted values: | `LocalEventLogs`, `MDEAdvancedHunting`, `EVTXFiles` |
| Default value: | LocalEventLogs |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -SuppPolicyName

The name of the supplemental policy to create

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Aliases: | Name |
| Position: | Named |
| Default value: | `The cmdlet will generate a proper name based on the selected source and time` |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -Level

The level determining rule generation can be one of the following: Auto, FilePublisher, Publisher, or Hash.

The fallback level is always Hash.

By default, which is the same as not using this parameter, the [most secure levels](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide) are prioritized. If a log contains the requisite details for the FilePublisher level, it will be utilized. If not, the Publisher level will be attempted. Should this also fail, the Hash level will be employed.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Aliases: | Lvl |
| Position: | Named |
| Default value: | `Auto` |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -MDEAHLogs

The path(s) to use MDE AH CSV files.

> [!NOTE]\
> This is a dynamic parameter and will only be available if the Source parameter is set to MDEAdvancedHunting.

> [!IMPORTANT]\
> Please [**read this article**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Use-Microsoft-Defender-for-Endpoint-Advanced-Hunting-With-WDAC-App-Control) for complete information on how to use this feature.

<br>

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)[]|
| :-------------: | :-------------: |
| Aliases: | MDELogs |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -EVTXLogs

The path(s) of EVTX files to use.

> [!NOTE]\
> This is a dynamic parameter and will only be available if the Source parameter is set to EVTXFiles.

<br>

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)[]|
| :-------------: | :-------------: |
| Aliases: | Evtx |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -TimeSpan

The unit of time to use when filtering the logs by the time.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Aliases: | Duration |
| Position: | Named |
| Accepted values: | `Minutes`, `Hours`, `Days` |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -TimeSpanAgo

The number of the selected time unit to go back in time from the current time.

> [!NOTE]\
> This is a dynamic parameter and will only be available if the TimeSpan parameter is set.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Aliases: | Past |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -FilterByPolicyNames

The names of the policies to filter the logs by. Supports auto-completion, press TAB key to view the list of the deployed base policy names to choose from.
It will not display the policies that are already selected on the command line.

You can manually enter the name of the policies that are no longer available on the system.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)[]|
| :-------------: | :-------------: |
| Aliases: | FilterNames |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -KernelModeOnly

If used, will filter the logs by including only the Kernel-Mode logs.

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Aliases: | KMode |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -LogType

The type of logs to display.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Aliases: | LogKind |
| Position: | Named |
| Accepted values: | `Audit`, `Blocked` |
| Default value: | `Audit` |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -Deploy

If used, will deploy the policy on the system.

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Aliases: | Up |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -ExtremeVisibility

If used, will display all the properties of the logs without any filtering.

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Aliases: | XVis |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>
