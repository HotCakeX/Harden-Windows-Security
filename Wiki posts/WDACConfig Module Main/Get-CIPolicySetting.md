# Get-CIPolicySetting available parameters

<div align="center">
<a href="https://www.youtube.com/watch?v=hNpzYlOMCys"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Thumbnails%20with%20YouTube%20play%20logo/YouTube%20Thumbnail%20-%20secure%20settings%20in%20WDAC%20Policies.png" alt="How To Set And Query Secure Settings in App Control Policies" width="500"></a></div>

## Syntax

```powershell
Get-CIPolicySetting
    [-Provider] <String>
    [-Key] <String>
    [-ValueName] <String>
    [-SkipVersionCheck]
    [<CommonParameters>]
```

## Description

Gets the secure settings value from the deployed CI policies. If there is a policy with the same provider, key and value then it returns the following details:

<div align='center'>

| Property | Description |
| :-------------: | :-------------: |
| Value | The actual value of the string |
| ValueType | The type of setting: `WldpString`, `WldpInteger` or `WldpBoolean` |
| ValueSize | the size of the returned value |
| Status | True/False depending on whether the setting exists on the system or not |
| StatusCode | 0 if the value exists on the system, non-zero if it doesn't. |

</div>

## Parameters

### -Provider

The provider of the secure setting.

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

### -Key

The key of the secure setting.

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

### -ValueName

The name of the secure setting.

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
