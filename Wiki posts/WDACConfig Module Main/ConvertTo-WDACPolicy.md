# ConvertTo-WDACPolicy available parameters

## Syntax

```powershell
ConvertTo-WDACPolicy 
    [-PolicyToAddLogsTo <FileInfo>] 
    [-FilterByPolicyNames <String[]>] 
    [-MinutesAgo <UInt64>] 
    [-HoursAgo <UInt64>] 
    [-DaysAgo <UInt64>] 
    [-KernelModeOnly]
    [-LogType <String>] 
    [-Deploy] 
    [-ExtremeVisibility] 
    [<CommonParameters>]
```

```powershell
ConvertTo-WDACPolicy 
    [-BasePolicyFile <FileInfo>] 
    [-FilterByPolicyNames <String[]>] 
    [-MinutesAgo <UInt64>] 
    [-HoursAgo <UInt64>] 
    [-DaysAgo <UInt64>] 
    [-KernelModeOnly]
    [-LogType <String>] 
    [-Deploy] 
    [-ExtremeVisibility] 
    [<CommonParameters>]
```

```powershell
ConvertTo-WDACPolicy
    [-BasePolicyGUID <Guid>] 
    [-FilterByPolicyNames <String[]>] 
    [-MinutesAgo <UInt64>] 
    [-HoursAgo <UInt64>] 
    [-DaysAgo <UInt64>] 
    [-KernelModeOnly] 
    [-LogType <String>] 
    [-Deploy] 
    [-ExtremeVisibility] 
    [<CommonParameters>]
```

## Description

This cmdlet presents the Code Integrity logs in a graphical interface (GUI) and enables the user to choose the logs. The logs can be filtered in various ways, such as Date, Type, Policy that generated them, and so on.

This cmdlet is versatile and offers a broad range of functionalities that can be applied independently or combined for very precise and specific tasks.

This cmdlet allows you to perform an in-place upgrade of a deployed base/supplemental policy or create a new supplemental policy based on the selected logs.

## Parameters

### -PolicyToAddLogsTo

The policy to add the selected logs to, it can either be a base or supplemental policy.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -BasePolicyFile

The base policy file to associate the supplemental policy with.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -BasePolicyGUID

The GUID of the base policy to associate the supplemental policy with.

<div align='center'>

| Type: |[Guid](https://learn.microsoft.com/en-us/dotnet/api/system.guid)|
| :-------------: | :-------------: |
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
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -MinutesAgo

The number of minutes ago from the current time to filter the logs by

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

### -HoursAgo

The number of hours ago from the current time to filter the logs by

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

### -DaysAgo

The number of days ago from the current time to filter the logs by

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

### -KernelModeOnly

If used, will filter the logs by including only the Kernel-Mode logs.

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

### -LogType

The type of logs to display: Audit or Blocked

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
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
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

