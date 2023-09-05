# New-SupplementalWDACConfig available parameters

## Notes

* **Mandatory** parameters indicate you always need to provide values for them.

* **Automatic** parameters indicate that if you used [Set-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig) cmdlet to set default values for them, the module will automatically use them. This saves time and prevents repetitive tasks. However, if no value exists in User Configurations for an Automatic parameter and you didn't explicitly provide a value for that parameter either, then you will see an error asking you to provide value for it. Explicitly providing a value for an Automatic parameter in the command line overrides its default value in User Configurations, meaning the module will ignore the value of the same parameter in the User Configurations file.

* **Optional** parameters indicate that they are not required and without using them the module will automatically run with the optimal settings.

* Many cmdlets and parameters of the module support the PowerShell's built-in `-Debug` switch and when that switch is used, they display extra details and debugging messages on the console, showing you what's happening under the hood.

<br>

## New-SupplementalWDACConfig -Normal

![image](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Wiki%20APNGs/New-SupplementalWDACConfig%20-Normal.apng)

```powershell
New-SupplementalWDACConfig [-Normal] -ScanLocation <String> -SuppPolicyName <String> -PolicyPath <String>
[-Deploy] [-SpecificFileNameLevel <String>] [-NoUserPEs] [-NoScript] [-Level <String>]
[-Fallbacks <String[]>]
```

<br>

Creates a normal Supplemental policy for a base policy.

### 2 mandatory parameters

* `-ScanLocation <String>`: The directory or drive that you want to scan for files that will be allowed to run by the Supplemental policy.

* `-SuppPolicyName <String>`: Add a descriptive name for the Supplemental policy. Accepts only alphanumeric and space characters.

### 1 Automatic Parameter

* `-PolicyPath <String>`: Browse for the xml file of the Base policy this Supplemental policy is going to expand. Supports tab completion by showing only `.xml` files with **Base Policy** Type.

### 6 optional parameters

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

## New-SupplementalWDACConfig -FilePathWildCards

![image](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Wiki%20APNGs/New-SupplementalWDACConfig%20-FilePathWildCards.apng)

```powershell
New-SupplementalWDACConfig [-FilePathWildCards] -WildCardPath <String> -SuppPolicyName <String> -PolicyPath
<String> [-Deploy]
```

<br>

Creates a Supplemental policy that allows a file path that includes one or more wildcard `*` character in it.

### 2 mandatory parameters

* `-WildCardPath`: A file path that includes at least one wildcard `*` character and ends with a `\`.

* `-SuppPolicyName <String>`: Add a descriptive name for the Supplemental policy. Accepts only alphanumeric and space characters.

### 1 Automatic parameter

* `-PolicyPath`: Browse for the xml file of the Base policy this Supplemental policy is going to expand. Supports tab completion by showing only `.xml` files with **Base Policy** Type.

### 1 optional parameter

* `-Deploy`: Indicates that the module will automatically deploy the Supplemental policy after creation.

### The outputs of the parameter are

* ***SupplementalPolicy`<Custom Name>`.xml***
* ***{GUID}.cip***

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-SupplementalWDACConfig -InstalledAppXPackages

![image](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Wiki%20APNGs/New-SupplementalWDACConfig%20-InstalledAppXPackages.apng)

```powershell
New-SupplementalWDACConfig [-InstalledAppXPackages] -PackageName <String> -SuppPolicyName <String> -PolicyPath
<String> [-Deploy]
```

<br>

Creates a Supplemental policy based on the package name of an installed app.

More information at [Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/manage-packaged-apps-with-windows-defender-application-control)

### 2 mandatory parameters

* `-PackageName`: Enter the [package name](https://learn.microsoft.com/en-us/powershell/module/appx/get-appxpackage) of an installed app. Supports wildcard `*` character. e.g, `*Edge*` or `"*Microsoft*"`.

* `-SuppPolicyName <String>`: Add a descriptive name for the Supplemental policy. Accepts only alphanumeric and space characters.

### 1 Automatic paremeter

* `-PolicyPath`: Browse for the xml file of the Base policy this Supplemental policy is going to expand. Supports tab completion by showing only `.xml` files with **Base Policy** Type.

### 1 optional parameter

* `-Deploy`: Indicates that the module will automatically deploy the Supplemental policy after creation.

### The outputs of the parameter are

* ***SupplementalPolicy`<Custom Name>`.xml***
* ***{GUID}.cip***

<br>
