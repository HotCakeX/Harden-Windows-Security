# Set-CiRuleOptions available parameters

![Set-CiRuleOptions demo]()

## Syntax

```powershell
Set-CiRuleOptions
    -FilePath <FileInfo>
    [-Template <String>]
    [-RulesToAdd <String[]>]
    [-RulesToRemove <String[]>]
    [-RequireWHQL <Boolean>]
    [-EnableAuditMode <Boolean>]
    [-DisableFlightSigning <Boolean>]
    [-RequireEVSigners <Boolean>]
    [-ScriptEnforcement <Boolean>]
    [-TestMode <Boolean>]
    [-RemoveAll]
    [<CommonParameters>]
```

## Description

Configures the Policy rule options in a given XML file and sets the HVCI to Strict in the output XML file. It offers many ways to configure the policy rule options in a given XML file.

All of its various parameters provide the flexibility that ensures only one pass is needed to configure the policy rule options.

> [!TIP]\
> First the template is processed, then the individual boolean parameters, and finally the individual rules to add and remove.

## Parameters

### -FilePath

The path to the XML file that contains the WDAC Policy.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Aliases: | MDELogs |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -Template

Specifies the template to use for the CI policy rules.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Accepted values: | `Base`, `BaseISG`, `BaseKernel`, `Supplemental` |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -RulesToAdd

Specifies the rule options to add to the policy XML file. Supports auto tab-completion so you don't need to type them manually.

> [!NOTE]\
> If a rule option is already selected by the RulesToRemove parameter, it won't be suggested by the argument completer of this parameter.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)[]|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -RulesToRemove

Specifies the rule options to remove from the policy XML file. Supports auto tab-completion so you don't need to type them manually.

> [!NOTE]\
> If a rule option is already selected by the RulesToAdd parameter, it won't be suggested by the argument completer of this parameter.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)[]|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -RequireWHQL

Specifies whether to require WHQL signatures for all drivers.

<div align='center'>

| Type: |[BooleanParameter](https://learn.microsoft.com/en-us/dotnet/api/system.boolean)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -EnableAuditMode

Specifies whether to enable audit mode.

<div align='center'>

| Type: |[BooleanParameter](https://learn.microsoft.com/en-us/dotnet/api/system.boolean)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -DisableFlightSigning

Specifies whether to disable flight signing.

<div align='center'>

| Type: |[BooleanParameter](https://learn.microsoft.com/en-us/dotnet/api/system.boolean)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -RequireEVSigners

Specifies whether to require EV signers.

<div align='center'>

| Type: |[BooleanParameter](https://learn.microsoft.com/en-us/dotnet/api/system.boolean)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -ScriptEnforcement

Specifies whether to disable script enforcement

<div align='center'>

| Type: |[BooleanParameter](https://learn.microsoft.com/en-us/dotnet/api/system.boolean)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -TestMode

Specifies whether to enable ***Enabled:Boot Audit on Failure*** and ***Enabled:Advanced Boot Options Menu*** rule options in the policy XML file.

<div align='center'>

| Type: |[BooleanParameter](https://learn.microsoft.com/en-us/dotnet/api/system.boolean)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -RemoveAll

Removes all the existing rule options from the policy XML file.

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
