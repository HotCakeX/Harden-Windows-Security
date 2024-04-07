---
external help file: ConvertTo-WDACPolicy.xml
Module Name: WDACConfig
online version: https://github.com/HotCakeX/Harden-Windows-Security/wiki/ConvertTo-WDACPolicy
schema: 2.0.0
---

# ConvertTo-WDACPolicy

## SYNOPSIS
Displays the Code Integrity logs in a GUI and allows the user to select the logs to convert to a Supplemental WDAC policy. It's a multi-purpose cmdlet that offers a wide range of functionalities that can either be used separately or mixed together for very detailed and specific tasks.

## SYNTAX

### In-Place Upgrade
```
ConvertTo-WDACPolicy
    [-PolicyToAddLogsTo <FileInfo>]
    [-Source <String>]
    [-MDEAHLogs <FileInfo[]>]
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
    [-MDEAHLogs <FileInfo[]>]
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
    [-MDEAHLogs <FileInfo[]>]
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
You can filter the logs by the policy name and the time. You can add the logs to an existing WDAC policy or create a new one. You can use the local logs or use Microsoft Defender for Endpoint Advanced Hunting results to generate Application Control policies.

## EXAMPLES

### EXAMPLE 1
```
ConvertTo-WDACPolicy -PolicyToAddLogsTo "C:\Users\Admin\AllowMicrosoftPlusBlockRules.xml" -Verbose
```

This example will display the Code Integrity logs in a GUI and allow the user to select the logs to add to the specified policy file.

### EXAMPLE 2
```
ConvertTo-WDACPolicy -Verbose -BasePolicyGUID '{ACE9058C-8A24-47F4-86F0-A33FAB5073E3}'
```

This example will display the Code Integrity logs in a GUI and allow the user to select the logs to create a new supplemental policy and associate it with the specified base policy GUID.

### EXAMPLE 3
```
ConvertTo-WDACPolicy -BasePolicyFile "C:\Users\Admin\AllowMicrosoftPlusBlockRules.xml"
```

This example will display the Code Integrity logs in a GUI and allow the user to select the logs to create a new supplemental policy and associate it with the specified base policy file.

### EXAMPLE 4
```
ConvertTo-WDACPolicy
```

This example will display the Code Integrity logs in a GUI and takes no further action.

### EXAMPLE 5
```
ConvertTo-WDACPolicy -FilterByPolicyNames 'VerifiedAndReputableDesktopFlightSupplemental','WindowsE_Lockdown_Flight_Policy_Supplemental' -Verbose
```

This example will filter the Code Integrity logs by the specified policy names and display them in a GUI.
It will also display verbose messages on the console.

### EXAMPLE 6
```
ConvertTo-WDACPolicy -FilterByPolicyNames 'Microsoft Windows Driver Policy - Enforced' -MinutesAgo 10
```

This example will filter the Code Integrity logs by the specified policy name and the number of minutes ago from the current time and display them in a GUI.
So, it will display the logs that are 10 minutes old and are associated with the specified policy name.

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
The source of the logs: Local Event logs (LocalEventLogs) or Microsoft Defender for Endpoint Advanced Hunting results (MDEAdvancedHunting).
Supports validate set.

```yaml
Type: String
Parameter Sets: (All)
Aliases: Src

Required: False
Position: Named
Default value: Event Logs
Accept pipeline input: False
Accept wildcard characters: False
```

### -MDEAHLogs
The path(s) to use MDE AH CSV files. This is a dynamic parameter and will only be available if the Source parameter is set to MDEAdvancedHunting.

```yaml
Type: FileInfo[]
Parameter Sets: (All)
Aliases: MDELogs

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -FilterByPolicyNames
The names of the policies to filter the logs by.
Supports auto-completion, press TAB key to view the list of the deployed base policy names to choose from.
It will not display the policies that are already selected on the command line.
You can manually enter the name of the policies that are no longer available on the system.

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
If used, will filter the logs by including only the Kernel-Mode logs

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
The type of logs to display: Audit or Blocked

```yaml
Type: String
Parameter Sets: (All)
Aliases: LogKind

Required: False
Position: Named
Default value: Audit
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

