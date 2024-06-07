# New-DenyWDACConfig available parameters

## New-DenyWDACConfig -Normal

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-DenyWDACConfig/New-DenyWDACConfig%20-Normal.apng)

## Syntax

```powershell
New-DenyWDACConfig
    [-Normal]
    -PolicyName <String>
    [-ScanLocations <DirectoryInfo[]>]
    [-Deploy]
    [-Level <String>]
    [-Fallbacks <String[]>]
    [-SpecificFileNameLevel <String>]
    [-NoUserPEs]
    [-NoScript]
    [-SkipVersionCheck]
    [-WhatIf]
    [-Confirm]
    [<CommonParameters>]
```

## Description

Creates a Deny base policy by scanning a directory. The base policy will have 2 allow all rules, meaning it can be deployed as a standalone base policy, side-by-side any other Base/Supplemental policies.

## Parameters

### -PolicyName

Add a descriptive name for the Deny base policy. Accepts only alphanumeric and space characters.

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

### -ScanLocations

Accepts one or more comma separated folder paths. Supports argument completion, when you press tab, folder picker GUI will open allowing you to easily select a folder, you can then add a comma `,` and press tab again to select another folder path or paste a folder path manually, works both ways.

<div align='center'>

| Type: |[DirectoryInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.directoryinfo)[]|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -Deploy

Indicates that the module will automatically deploy the Deny base policy after creation.

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

Offers the same official [Levels](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-level) to scan the specified directory path(s).

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

Offers the same official [Fallbacks](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-fallback) to scan the specified directory path(s).

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

By default the module includes user PEs in the scan, but when you use this switch parameter, they won't be included. [More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-userpes)

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

## New-DenyWDACConfig -Drivers

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-DenyWDACConfig/New-DenyWDACConfig%20-Drivers.apng)

## Syntax

```powershell
New-DenyWDACConfig
    [-Drivers]
    -PolicyName <String>
    [-ScanLocations <DirectoryInfo[]>]
    [-Deploy]
    [-SkipVersionCheck]
    [-Confirm]
    [<CommonParameters>]
```

## Description

Creates a Deny base policy by scanning a directory, this parameter uses [DriverFile objects](https://learn.microsoft.com/en-us/powershell/module/configci/get-systemdriver) so it's best suitable for driver files. The base policy will have 2 allow all rules, meaning it can be deployed as a standalone base policy, side-by-side any other Base/Supplemental policies.

> [!NOTE]\
> The scan uses **WHQLFilePublisher** level without any fallbacks, and includes both usermode and kernel mode drivers.

## Parameters

### -PolicyName

Add a descriptive name for the Deny base policy. Accepts only alphanumeric and space characters.

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

### -ScanLocations

Accepts one or more comma separated folder paths. Supports argument completion, when you press tab, folder picker GUI will open allowing you to easily select a folder, you can then add a comma `,` and press tab again to select another folder path or paste a folder path manually, works both ways.

<div align='center'>

| Type: |[DirectoryInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.directoryinfo)[]|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -Deploy

Indicates that the module will automatically deploy the Deny base policy after creation.

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

## New-DenyWDACConfig -InstalledAppXPackages

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-DenyWDACConfig/New-DenyWDACConfig%20-InstalledAppXPackages.apng)

## Syntax

```powershell
New-DenyWDACConfig
    [-InstalledAppXPackages]
    -PackageName <String>
    -PolicyName <String>
    [-Deploy]
    [-Force]
    [-SkipVersionCheck]
    [-Confirm]
    [<CommonParameters>]
```

## Description

Creates a Deny base policy for one or more installed Windows Apps (Appx) based on their PFN (Package Family Name). The base policy will have 2 allow all rules, meaning it can be deployed as a standalone base policy, side-by-side any other Base/Supplemental policies.

## Parameters

### -PackageName

Enter the [package name](https://learn.microsoft.com/en-us/powershell/module/appx/get-appxpackage) of an installed app. Supports wildcard `*` character. e.g, `*Edge*` or `"*Microsoft*"`.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | True |

</div>

<br>

### -PolicyName

Add a descriptive name for the Deny base policy. Accepts only alphanumeric and space characters.

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

### -Deploy

Indicates that the module will automatically deploy the Deny base policy after creation.

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

### -Force

Indicates that the cmdlet won't ask for confirmation and will proceed with creating the deny policy.

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

## New-DenyWDACConfig -PathWildCards

![New-DenyWDACConfig -PathWildCards demo](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-DenyWDACConfig/New-DenyWDACConfig%20-PathWildCards.apng)

## Syntax

```powershell
New-DenyWDACConfig
    [-PathWildCards]
    -PolicyName <String>
    -FolderPath <DirectoryInfo>
    [-Deploy]
    [-SkipVersionCheck]
    [-Confirm]
    [<CommonParameters>]
```

## Description

Creates a Deny standalone base policy for a folder using wildcards. The base policy created by this parameter can be deployed side by side any other base/supplemental policy.

> [!NOTE]\
> This feature is also used internally by [the Harden Windows Security Module](https://github.com/HotCakeX/Harden-Windows-Security?tab=readme-ov-file#downloads-defense-measures-).

## Parameters

### -PolicyName

Add a descriptive name for the Deny base policy. Accepts only alphanumeric and space characters.

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

### -FolderPath

A folder path that includes at least one wildcard `*` character. Press TAB to open the folder picker GUI. Once you selected a folder, you will see the path will have `\*` at the end of it. You can modify the selected path by adding/removing wildcards `*` to it before proceeding.

<div align='center'>

| Type: |[DirectoryInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.directoryinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | True |

</div>

<br>

### -Deploy

Indicates that the module will automatically deploy the Deny base policy after creation.

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
