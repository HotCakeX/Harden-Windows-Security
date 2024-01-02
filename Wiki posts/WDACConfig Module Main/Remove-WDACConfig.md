# Remove-WDACConfig available parameters

## Remove-WDACConfig -SignedBase

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Remove-WDACConfig/Remove-WDACConfig%20-SignedBase.apng)

```powershell
Remove-WDACConfig [-SignedBase] -PolicyPaths <String[]> [-CertCN <String>] [-SignToolPath <String>] [-Force]
[-SkipVersionCheck] [-WhatIf] [-Confirm] [<CommonParameters>]
```

<br>

Uses [the official procedure](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/disable-wdac-policies) to Re-Deploy the Signed base WDAC policies with ***Enabled:Unsigned System Integrity Policy*** rule option.

### 1 Mandatory Parameter

* `-PolicyPaths <String[]`: Path to xml file(s) of the currently deployed policy that you want to remove, can be multiple. Supports tab completion by showing only `.xml` files.

### 2 Automatic Parameters

* `-SignToolPath <String>`: Press TAB to open the file picker GUI and browse for SignTool.exe. [You can use it in 2 different ways](#the-logic-behind--signtoolpath-string-optional-parameter)

* `-CertCN <String>`: Common name of the certificate used to sign the deployed WDAC policies - Supports argument completion so you don't have to manually enter the Certificate's CN, just make sure the certificate is installed in the personal store of the user certificates, then press TAB to auto complete the name. You can however enter it manually if you want to.

### 1 Optional Parameter

- `-Force`: Indicates that the cmdlet won't ask for confirmation and will proceed with redeploying the signed base policy in unsigned mode.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Remove-WDACConfig -UnsignedOrSupplemental

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Remove-WDACConfig/Remove-WDACConfig%20-UnsignedOrSupplemental.apng)

```powershell
Remove-WDACConfig [-UnsignedOrSupplemental] [-PolicyNames <String[]>] [-PolicyIDs <String[]>] [-Force]
[-SkipVersionCheck] [-WhatIf] [-Confirm] [<CommonParameters>]
```

<br>

Removes Unsigned deployed WDAC policies as well as [Signed deployed Supplemental WDAC policies](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes#removing-supplemental-policies)

### 2 Parameters

* `-PolicyIDs <String[]>`
* `-PolicyNames <String[]>`

You can choose either of them or both of them, at the same time, but you do need to use one of them at least.

They use argument completion with ValidateSet, meaning you can't specify wrong PolicyIDs or PolicyNames, just press TAB key and it will autofill the arguments for you based on the deployed policies. If you want to select multiple items, after each one, enter a comma `,` and then press TAB again to choose another Name/ID.

For example, you can specify 2 policies by IDs and 3 policies by names, and it will automatically remove all of them.

**Hint:** First use [-ListActivePolicies](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Confirm-WDACConfig#confirm-wdacconfig--listactivepolicies) parameter to list the deployed policies on the screen.

**Hint 2:** When using `-PolicyNames <String[]>` parameter, if multiple policies with the exact same name are deployed, when you press TAB, you will only see 1 of them, if you select it, all of the policies with that name will be removed. If that's not desired, consider using `-PolicyIDs <String[]>` parameter instead.

**Hint 3:** The argument completers on this parameter are very smart. E.g., if there are 10 policies deployed on the system and you use argument Tab completion to select 5 of them by IDs, when you try to select the other 5 by their names, the name of the policies that you already selected by IDs don't show up anymore. This greatly reduces user error and simplifies the workflow for end user.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Notes

* **Mandatory** parameters indicate you always need to provide values for them.

* **Automatic** parameters indicate that if you used [Set-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig) cmdlet to set default values for them, the module will automatically use them. This saves time and prevents repetitive tasks. However, if no value exists in User Configurations for an Automatic parameter and you didn't explicitly provide a value for that parameter either, then you will see an error asking you to provide value for it. Explicitly providing a value for an Automatic parameter in the command line overrides its default value in User Configurations, meaning the module will ignore the value of the same parameter in the User Configurations file.

* **Optional** parameters indicate that they are not required and without using them the module will automatically run with the optimal settings.

<br>

### The logic behind `-SignToolPath <String>` optional parameter

1. If [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/) Signing Tools for Desktop Apps components is installed in the default location `C:\Program Files (x86)\Windows Kits`, then `-SignToolPath <String>` parameter isn't necessary.

2. If Windows SDK Signing Tools for Desktop Apps components is not installed in the default location or you want to manually browse for the `signtool.exe`, then make sure you either specify its path using `Set-CommonWDACConfig -SignToolPath` or use the `-SignToolPath <String>` parameter.

3. If SignTool.exe path is available in user configurations then it will be used, unless the `-SignToolPath <String>` parameter is specified which takes priority over auto detection and user configurations.

4. Unless you specify the `-SignToolPath <String>` parameter, or the SignTool.exe path already exists in your user configurations or on your system, you will receive a prompt to authorize the automatic download of the most recent SignTool.exe version from the official Microsoft servers. Upon confirmation, it will be saved in your user configurations and utilized by the cmdlet.

<br>
