---
external help file: ConvertTo-WDACPolicy.xml
Module Name: WDACConfig
online version: https://github.com/HotCakeX/Harden-Windows-Security/wiki/ConvertTo-WDACPolicy
schema: 2.0.0
---

# ConvertTo-WDACPolicy

## SYNOPSIS
This is a multi-purpose cmdlet that offers a wide range of functionalities that can either be used separately or mixed together for very detailed and specific tasks.

It currently supports Code Integrity and AppLocker logs from the following sources: Local Event logs, Evtx log files and Microsoft Defender for Endpoint Advanced Hunting results.

The cmdlet displays the logs in a GUI and allows the user to select the logs to be processed further.

The logs can be filtered based on many criteria using the available parameters.

The output of this cmdlet is a Supplemental Application Control (WDAC) policy.
Based on the input parameters, it can be associated with a base policy or merged with an existing Base or Supplemental policy.

## SYNTAX

### In-Place Upgrade
```
ConvertTo-WDACPolicy
    [-PolicyToAddLogsTo <FileInfo>]
    [-Source <String>]
    [-SuppPolicyName]
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

### Base-Policy File Association
```
ConvertTo-WDACPolicy
    [-BasePolicyFile <FileInfo>]
    [-Source <String>]
    [-SuppPolicyName]
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

### Base-Policy GUID Association
```
ConvertTo-WDACPolicy
    [-BasePolicyGUID <Guid>]
    [-Source <String>]
    [-SuppPolicyName]
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

## DESCRIPTION
The cmdlet can be used for local and remote systems. You can utilize this cmdlet to create App Control for Business policies from MDE Advanced Hunting and then deploy them using Microsoft Intune to your endpoints.

You can utilize this cmdlet to use the evtx log files you aggregated from your endpoints and create a WDAC policy from them.

This offers scalability and flexibility in managing your security policies.

## EXAMPLES

### EXAMPLE 1
```
ConvertTo-WDACPolicy -PolicyToAddLogsTo "C:\Users\Admin\AllowMicrosoftPlusBlockRules.xml" -Verbose
```

This example will display the Code Integrity and AppLocker logs in a GUI and allow the user to select the logs to add to the specified policy file.

### EXAMPLE 2
```
ConvertTo-WDACPolicy -Verbose -BasePolicyGUID '{ACE9058C-8A24-47F4-86F0-A33FAB5073E3}'
```

This example will display the Code Integrity and AppLocker logs in a GUI and allow the user to select the logs to create a new supplemental policy and associate it with the specified base policy GUID.

### EXAMPLE 3
```
ConvertTo-WDACPolicy -BasePolicyFile "C:\Users\Admin\AllowMicrosoftPlusBlockRules.xml"
```

This example will display the Code Integrity and AppLocker logs in a GUI and allow the user to select the logs to create a new supplemental policy and associate it with the specified base policy file.

### EXAMPLE 4
```
ConvertTo-WDACPolicy
```

This example will display the Code Integrity and AppLocker logs in a GUI and takes no further action.

### EXAMPLE 5
```
ConvertTo-WDACPolicy -FilterByPolicyNames 'VerifiedAndReputableDesktopFlightSupplemental','WindowsE_Lockdown_Flight_Policy_Supplemental' -Verbose
```

This example will filter the Code Integrity and AppLocker logs by the specified policy names and display them in a GUI. It will also display verbose messages on the console.

### EXAMPLE 6
```
ConvertTo-WDACPolicy -FilterByPolicyNames 'Microsoft Windows Driver Policy - Enforced' -TimeSpan Minutes -TimeSpanAgo 10
```

This example will filter the local Code Integrity and AppLocker logs by the specified policy name and the number of minutes ago from the current time and display them in a GUI.
So, it will display the logs that are 10 minutes old and are associated with the specified policy name.

### EXAMPLE 7
```
ConvertTo-WDACPolicy -BasePolicyFile "C:\Program Files\WDACConfig\DefaultWindowsPlusBlockRules.xml" -Source MDEAdvancedHunting -MDEAHLogs "C:\Users\Admin\Downloads\New query.csv" -Deploy -TimeSpan Days -TimeSpanAgo 2
```

This example will create a new supplemental policy from the selected MDE Advanced Hunting logs and associate it with the specified base policy file and it will deploy it on the system.
The displayed logs will be from the last 2 days. You will be able to select the logs to create the policy from in the GUI.

### EXAMPLE 8
```
ConvertTo-WDACPolicy -BasePolicyGUID '{89CD611D-5557-4833-B73D-716B979AEE3D}' -Source EVTXFiles -EVTXLogs "C:\Users\HotCakeX\App Locker logs.evtx","C:\Users\HotCakeX\Code Integrity LOGS.evtx"
```

This example will create a new supplemental policy from the selected EVTX files and associate it with the specified base policy GUID.

## PARAMETERS

### -PolicyToAddLogsTo
The policy to add the selected logs to, it can either be a base or supplemental policy.

```yaml
Type: FileInfo
Parameter Sets: In-Place Upgrade
Aliases: AddLogs

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -BasePolicyFile
The base policy file to associate the supplemental policy with

```yaml
Type: FileInfo
Parameter Sets: Base-Policy File Association
Aliases: BaseFile

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -BasePolicyGUID
The GUID of the base policy to associate the supplemental policy with

```yaml
Type: Guid
Parameter Sets: Base-Policy GUID Association
Aliases: BaseGUID

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Source
The source of the logs: Local Event logs (LocalEventLogs), Microsoft Defender for Endpoint Advanced Hunting results (MDEAdvancedHunting) or EVTX files (EVTXFiles).
Supports validate set.

```yaml
Type: String
Parameter Sets: (All)
Aliases: Src

Required: False
Position: Named
Default value: LocalEventLogs
Accept pipeline input: False
Accept wildcard characters: False
```

### -SuppPolicyName
The name of the supplemental policy to create. If not specified, the cmdlet will generate a proper name based on the selected source and time.

```yaml
Type: String
Parameter Sets: (All)
Aliases: Name

Required: False
Position: Named
Default value: <Depends on the selected source and time>
Accept pipeline input: False
Accept wildcard characters: False
```

### -Level
The level determining rule generation can be one of the following: Auto, FilePublisher, Publisher, or Hash.

The fallback level is always Hash.

By default, which is the same as not using this parameter, the most secure levels are prioritized. If a log contains the requisite details for the FilePublisher level, it will be utilized. If not, the Publisher level will be attempted. Should this also fail, the Hash level will be employed.

```yaml
Type: String
Parameter Sets: (All)
Aliases: Lvl

Required: False
Position: Named
Default value: Auto
Accept pipeline input: False
Accept wildcard characters: False
```

### -MDEAHLogs
The path(s) to use MDE AH CSV files. This is a dynamic parameter and will only be available if the Source parameter is set to MDEAdvancedHunting.

```yaml
Type: FileInfo[]
Parameter Sets: (All)
Aliases: MDELogs

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EVTXLogs
The path(s) of EVTX files to use.
This is a dynamic parameter and will only be available if the Source parameter is set to EVTXFiles.

```yaml
Type: FileInfo[]
Parameter Sets: (All)
Aliases: Evtx

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -FilterByPolicyNames
The names of the policies to filter the logs by.
Supports auto-completion, press TAB key to view the list of the deployed base policy names to choose from.
It will not display the policies that are already selected on the command line.
You can manually enter the name of the policies that are no longer available on the system or are from remote systems in case of MDE Advanced Hunting logs.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: FilterNames

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TimeSpan
The unit of time to use when filtering the logs by the time.
The allowed values are: Minutes, Hours, Days

```yaml
Type: String
Parameter Sets: (All)
Aliases: Duration

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TimeSpanAgo
The number of the selected time unit to go back in time from the current time.

```yaml
Type: String
Parameter Sets: (All)
Aliases: Past

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -KernelModeOnly
If used, will filter the logs by including only the Kernel-Mode logs. You can use this parameter to easily create Supplemental policies for Strict Kernel-Mode WDAC policy.

More info available here: https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: KMode

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -LogType
The type of logs to display: Audit or Blocked. If not specified, All types will be displayed.

```yaml
Type: String
Parameter Sets: (All)
Aliases: LogKind

Required: False
Position: Named
Default value: All
Accept pipeline input: False
Accept wildcard characters: False
```

### -Deploy
If used, will deploy the policy on the system

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: Up

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExtremeVisibility
If used, will display all the properties of the logs without any filtering.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: XVis

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -SkipVersionCheck
Can be used with any parameter to bypass the online version check - only to be used in rare cases

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProgressAction
Contains the preference for the progress action

```yaml
Type: ActionPreference
Parameter Sets: (All)
Aliases: proga

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.IO.FileInfo
### System.Guid
### System.String
### System.String[]
### System.UInt64
### System.Management.Automation.SwitchParameter

## OUTPUTS

### System.String

## NOTES

## RELATED LINKS

[Cmdlet Guide](https://github.com/HotCakeX/Harden-Windows-Security/wiki/ConvertTo-WDACPolicy)

[YouTube video guide for MDE Advanced Hunting usage](https://www.youtube.com/watch?v=oyz0jFzOOGA)
