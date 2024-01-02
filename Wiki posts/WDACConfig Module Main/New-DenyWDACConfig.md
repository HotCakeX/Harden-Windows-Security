# New-DenyWDACConfig available parameters

## New-DenyWDACConfig -Normal

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-DenyWDACConfig/New-DenyWDACConfig%20-Normal.apng)

```powershell
New-DenyWDACConfig [-Normal] -PolicyName <String> [-ScanLocations <String[]>] [-Level <String>] [-Fallbacks
<String[]>] [-SpecificFileNameLevel <String>] [-NoUserPEs] [-NoScript] [-Deploy] [-SkipVersionCheck] [-WhatIf]
[-Confirm] [<CommonParameters>]
```

<br>

Creates a Deny base policy by scanning a directory. The base policy will have 2 allow all rules, meaning it can be deployed as a standalone base policy, side-by-side any other Base/Supplemental policies.

### 2 Mandatory Parameters

- `-PolicyName <String>`: Add a descriptive name for the Deny base policy. Accepts only alphanumeric and space characters.

- `ScanLocations <String[]>`: Accepts one or more comma separated folder paths. Supports argument completion, when you press tab, folder picker GUI will open allowing you to easily select a folder, you can then add a comma `,` and press tab again to select another folder path or paste a folder path manually, works both ways.

### 6 Optional Parameters

* `-Deploy`: Indicates that the module will automatically deploy the Deny base policy after creation.

* `-Levels <String>`: Offers the same official [Levels](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-level) for scanning of the specified directory path. If no level is specified the default, which is set to ***FilePublisher*** in this module, will be used.

* `-Fallbacks <String[]>`: Offers the same official [Fallbacks](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-fallback) for scanning of the specified directory path. If no fallbacks is specified the default, which is set to ***Hash*** in this module, will be used.

* `-SpecificFileNameLevel`: You can choose one of the following options: "OriginalFileName", "InternalName", "FileDescription", "ProductName", "PackageFamilyName", "FilePath". [More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-specificfilenamelevel)

* `-NoUserPEs`: By default the module includes user PEs in the scan, but when you use this switch parameter, they won't be included. [More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-userpes)

* `-NoScript`: [More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-noscript)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-DenyWDACConfig -Drivers

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-DenyWDACConfig/New-DenyWDACConfig%20-Drivers.apng)

```powershell
New-DenyWDACConfig [-Drivers] -PolicyName <String> [-ScanLocations <String[]>] [-Level <String>] [-Fallbacks
<String[]>] [-Deploy] [-SkipVersionCheck] [-WhatIf] [-Confirm] [<CommonParameters>]
```

<br>

Creates a Deny base policy by scanning a directory, this parameter uses [DriverFile objects](https://learn.microsoft.com/en-us/powershell/module/configci/get-systemdriver) so it's best suitable for driver files. The base policy will have 2 allow all rules, meaning it can be deployed as a standalone base policy, side-by-side any other Base/Supplemental policies.

### 2 Mandatory Parameters

- `-PolicyName <String>`: Add a descriptive name for the Deny base policy. Accepts only alphanumeric and space characters.

- `ScanLocations <String[]>`: Accepts one or more comma separated folder paths. Supports argument completion, when you press tab, folder picker GUI will open allowing you to easily select a folder, you can then add a comma `,` and press tab again to select another folder path or paste a folder path manually, works both ways.

### 3 Optional Parameters

* `-Deploy`: Indicates that the module will automatically deploy the Deny base policy after creation.

* `-Levels <String>`: Offers the same official [Levels](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-level) for scanning of the specified directory path. If no level is specified the default, which is set to ***FilePublisher*** in this module, will be used.

* `-Fallbacks <String[]>`: Offers the same official [Fallbacks](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-fallback) for scanning of the specified directory path. If no fallbacks is specified the default, which is set to ***Hash*** in this module, will be used.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-DenyWDACConfig -InstalledAppXPackages

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-DenyWDACConfig/New-DenyWDACConfig%20-InstalledAppXPackages.apng)

```powershell
New-DenyWDACConfig [-InstalledAppXPackages] -PackageName <String> -PolicyName <String> [-Deploy] [-Force]
[-SkipVersionCheck] [-WhatIf] [-Confirm] [<CommonParameters>]
```

<br>

Creates a Deny base policy for one or more installed Windows Apps (Appx) based on their PFN (Package Family Name). The base policy will have 2 allow all rules, meaning it can be deployed as a standalone base policy, side-by-side any other Base/Supplemental policies.

### 2 Mandatory Parameters

- `-PackageName <String>`: Enter the [package name](https://learn.microsoft.com/en-us/powershell/module/appx/get-appxpackage) of an installed app. Supports wildcard `*` character. e.g, `*Edge*` or `"*Microsoft*"`.

- ` -PolicyName <String>`: Add a descriptive name for the Deny base policy. Accepts only alphanumeric and space characters.

### 2 Optional Parameter

- `-Deploy`: Indicates that the module will automatically deploy the Deny base policy after creation.

- `-Force`: Indicates that the cmdlet won't ask for confirmation and will proceed with creating the deny policy.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-DenyWDACConfig -PathWildCards

![New-DenyWDACConfig -PathWildCards demo](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-DenyWDACConfig/New-DenyWDACConfig%20-PathWildCards.apng)

```powershell
New-DenyWDACConfig [-PathWildCards] -PolicyName <String> -FolderPath <String> [-Deploy] [-SkipVersionCheck] [<CommonParameters>]
```

### 2 Mandatory Parameters

- ` -PolicyName <String>`: Add a descriptive name for the Deny base policy. Accepts only alphanumeric and space characters.

* `-FolderPath`: A folder path that includes at least one wildcard `*` character and ends with a `\`. Press TAB to open the folder picker GUI. Once you selected a folder, you will see the path will have `\*` at the end of it. You can modify the selected path by adding/removing wildcards `*` to it before proceeding.

### 1 Optional Parameter

- `-Deploy`: Indicates that the module will automatically deploy the Deny base policy after creation.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Notes

* **Mandatory** parameters indicate you always need to provide values for them.

* **Automatic** parameters indicate that if you used [Set-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig) cmdlet to set default values for them, the module will automatically use them. This saves time and prevents repetitive tasks. However, if no value exists in User Configurations for an Automatic parameter and you didn't explicitly provide a value for that parameter either, then you will see an error asking you to provide value for it. Explicitly providing a value for an Automatic parameter in the command line overrides its default value in User Configurations, meaning the module will ignore the value of the same parameter in the User Configurations file.

* **Optional** parameters indicate that they are not required and without using them the module will automatically run with the optimal settings.

<br>
