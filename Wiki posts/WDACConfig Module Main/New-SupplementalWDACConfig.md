# New-SupplementalWDACConfig available parameters

## New-SupplementalWDACConfig -Normal

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-SupplementalWDACConfig/New-SupplementalWDACConfig%20-Normal.apng)

```powershell
New-SupplementalWDACConfig [-Normal] -ScanLocation <String> -SuppPolicyName <String> [-PolicyPath <String>]
[-Deploy] [-SpecificFileNameLevel <String>] [-NoUserPEs] [-NoScript] [-Level <String>] [-Fallbacks <String[]>]
[-SkipVersionCheck] [-WhatIf] [-Confirm] [<CommonParameters>]
```

<br>

Creates a normal Supplemental policy for a base policy.

### 2 Mandatory Parameters

* `-ScanLocation <String>`: The directory or drive that you want to scan for files that will be allowed to run by the Supplemental policy.

* `-SuppPolicyName <String>`: Add a descriptive name for the Supplemental policy. Accepts only alphanumeric and space characters.

### 1 Automatic Parameter

* `-PolicyPath <String>`: Browse for the xml file of the Base policy this Supplemental policy is going to expand. Supports tab completion by showing only `.xml` files with **Base Policy** Type.

### 6 Optional Parameters

* `-Deploy`: Indicates that the module will automatically deploy the Supplemental policy after creation.

* `-Levels <String>`: Offers the same official [Levels](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-level) for scanning of the specified directory path. If no level is specified the default, which is set to ***FilePublisher*** in this module, will be used.

* `-Fallbacks <String[]>`: Offers the same official [Fallbacks](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-fallback) for scanning of the specified directory path. If no fallbacks is specified the default, which is set to ***Hash*** in this module, will be used.

* `-SpecificFileNameLevel`: You can choose one of the following options: "OriginalFileName", "InternalName", "FileDescription", "ProductName", "PackageFamilyName", "FilePath". [More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-specificfilenamelevel)

* `-NoUserPEs`: By default the module includes user PEs in the scan, but when you use this switch parameter, they won't be included. [More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-userpes)

* `-NoScript`: [More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-noscript)

### The outputs of the parameter are

* ***SupplementalPolicy`<Custom Name>`.xml***
* ***{GUID}.cip***

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-SupplementalWDACConfig -PathWildCards

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-SupplementalWDACConfig/New-SupplementalWDACConfig%20-PathWildCards.apng)

```powershell
New-SupplementalWDACConfig [-PathWildCards] -FolderPath <String> -SuppPolicyName <String> [-PolicyPath <String>] [-Deploy] [-SkipVersionCheck] [-WhatIf] [-Confirm] [<CommonParameters>]
```

<br>

Creates a Supplemental policy that allows a folder path that includes one or more wildcard `*` character in it.

### 2 Mandatory Parameters

* `-FolderPath`: A folder path that includes at least one wildcard `*` character and ends with a `\`. Press TAB to open the folder picker GUI. Once you selected a folder, you will see the path will have `\*` at the end of it. You can modify the selected path by adding/removing wildcards `*` to it before proceeding.

* `-SuppPolicyName <String>`: Add a descriptive name for the Supplemental policy. Accepts only alphanumeric and space characters.

### 1 Automatic Parameter

* `-PolicyPath`: Browse for the xml file of the Base policy this Supplemental policy is going to expand. Supports tab completion by showing only `.xml` files with **Base Policy** Type.

### 1 Optional Parameter

* `-Deploy`: Indicates that the module will automatically deploy the Supplemental policy after creation.

### The outputs of the parameter are

* ***SupplementalPolicy`<Custom Name>`.xml***
* ***{GUID}.cip***

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-SupplementalWDACConfig -InstalledAppXPackages

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-SupplementalWDACConfig/New-SupplementalWDACConfig%20-InstalledAppXPackages.apng)

```powershell
New-SupplementalWDACConfig [-InstalledAppXPackages] -PackageName <String> -SuppPolicyName <String> [-PolicyPath
<String>] [-Deploy] [-Force] [-SkipVersionCheck] [-WhatIf] [-Confirm] [<CommonParameters>]
```

<br>

Creates a Supplemental policy based on the package name of an installed app.

More information at [Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/manage-packaged-apps-with-wdac)

### 2 Mandatory Parameters

* `-PackageName`: Enter the [package name](https://learn.microsoft.com/en-us/powershell/module/appx/get-appxpackage) of an installed app. Supports wildcard `*` character. e.g., `*Edge*` or `"*Microsoft*"`.

* `-SuppPolicyName <String>`: Add a descriptive name for the Supplemental policy. Accepts only alphanumeric and space characters.

### 1 Automatic Parameter

* `-PolicyPath`: Browse for the xml file of the Base policy this Supplemental policy is going to expand. Supports tab completion by showing only `.xml` files with **Base Policy** Type.

### 2 Optional Parameter

* `-Deploy`: Indicates that the module will automatically deploy the Supplemental policy after creation.

- `-Force`: Indicates that the cmdlet won't ask for confirmation and will proceed with creating the Supplemental policy.

### The outputs of the parameter are

* ***SupplementalPolicy`<Custom Name>`.xml***
* ***{GUID}.cip***

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Notes

* **Mandatory** parameters indicate you always need to provide values for them.

* **Automatic** parameters indicate that if you used [Set-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig) cmdlet to set default values for them, the module will automatically use them. This saves time and prevents repetitive tasks. However, if no value exists in User Configurations for an Automatic parameter and you didn't explicitly provide a value for that parameter either, then you will see an error asking you to provide value for it. Explicitly providing a value for an Automatic parameter in the command line overrides its default value in User Configurations, meaning the module will ignore the value of the same parameter in the User Configurations file.

* **Optional** parameters indicate that they are not required and without using them the module will automatically run with the optimal settings.

<br>
