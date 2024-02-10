# New-DenyWDACConfig available parameters

## New-DenyWDACConfig -Normal

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-DenyWDACConfig/New-DenyWDACConfig%20-Normal.apng)

```powershell
New-DenyWDACConfig
    [-Normal]
    -PolicyName <String>
    [-ScanLocations <DirectoryInfo[]>]
    [-Level <String>]
    [-Fallbacks <String[]>]
    [-SpecificFileNameLevel <String>]
    [-NoUserPEs]
    [-NoScript]
    [-Deploy]
    [-SkipVersionCheck]
    [-Confirm]
    [<CommonParameters>]
```

<br>

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

Offers the same official [Levels](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-level) for scanning of the specified directory path.

Offers the same official [Levels](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-level) for scanning of event logs.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | FilePublisher |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -Fallbacks

Offers the same official [Fallbacks](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-fallback) for scanning of the specified directory path.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)[]|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | Hash |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -SpecificFileNameLevel

You can choose one of the following options:
* OriginalFileName
* InternalName
* FileDescription
* ProductName
* PackageFamilyName
* FilePath

[More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-specificfilenamelevel)

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
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

```powershell
New-DenyWDACConfig
    [-Drivers]
    -PolicyName <String>
    [-ScanLocations <DirectoryInfo[]>]
    [-Level <String>]
    [-Fallbacks <String[]>]
    [-Deploy]
    [-SkipVersionCheck]
    [-Confirm]
    [<CommonParameters>]
```

<br>

Creates a Deny base policy by scanning a directory, this parameter uses [DriverFile objects](https://learn.microsoft.com/en-us/powershell/module/configci/get-systemdriver) so it's best suitable for driver files. The base policy will have 2 allow all rules, meaning it can be deployed as a standalone base policy, side-by-side any other Base/Supplemental policies.

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

Offers the same official [Levels](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-level) for scanning of event logs.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | FilePublisher |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -Fallbacks

Offers the same official [Fallbacks](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-fallback) for scanning of event logs.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)[]|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | Hash |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-DenyWDACConfig -InstalledAppXPackages

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-DenyWDACConfig/New-DenyWDACConfig%20-InstalledAppXPackages.apng)

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

<br>

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

```powershell
New-DenyWDACConfig
    [-PathWildCards]
    -PolicyName <String>
    -FolderPath <String>
    [-Deploy]
    [-SkipVersionCheck]
    [-Confirm]
    [<CommonParameters>]
```

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
