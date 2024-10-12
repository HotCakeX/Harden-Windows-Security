# Remove-WDACConfig available parameters

## Remove-WDACConfig -SignedBase

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Remove-WDACConfig/Remove-WDACConfig%20-SignedBase.apng)

## Syntax

```powershell
Remove-WDACConfig
    [-SignedBase]
    -PolicyPaths <FileInfo[]>
    [-CertCN <String>]
    [-SignToolPath <FileInfo>]
    [-Force]
    [-SkipVersionCheck]
    [-Confirm]
    [<CommonParameters>]
```

## Description

Uses [the official procedure](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/disable-appcontrol-policies) to Re-Deploy the Signed base App Control policies with ***Enabled:Unsigned System Integrity Policy*** rule option.

## Parameters

### -PolicyPaths

Path to xml file(s) of the currently deployed policy that you want to remove. Supports tab completion by showing only `.xml` files.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)[]|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -CertCN

Common name of the certificate - Supports argument completion so you don't have to manually enter the Certificate's CN. Make sure the certificate is installed in the personal store of the user certificates, then press TAB to auto complete the name. You can however enter it manually if you want to.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| [Automatic:](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#about-automatic-parameters) | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -SignToolPath

Press TAB to open the file picker GUI and browse for SignTool.exe

> [!IMPORTANT]\
> Refer [to this section](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#the-logic-behind-the--signtoolpath-parameter-in-the-module) for more info

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| [Automatic:](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig#about-automatic-parameters) | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -Force

Indicates that the cmdlet won't ask for confirmation and will proceed with redeploying the signed base policy in unsigned mode.

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

## Remove-WDACConfig -UnsignedOrSupplemental

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Remove-WDACConfig/Remove-WDACConfig%20-UnsignedOrSupplemental.apng)

## Syntax

```powershell
Remove-WDACConfig
    [-UnsignedOrSupplemental]
    [-PolicyNames <String[]>]
    [-PolicyIDs <String[]>]
    [-Force]
    [-SkipVersionCheck]
    [-Confirm]
    [<CommonParameters>]
```

## Description

Removes Unsigned deployed App Control policies as well as [Signed deployed Supplemental App Control policies](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes#removing-supplemental-policies)

> [!NOTE]\
>  When using `-PolicyNames` parameter, if multiple policies with the exact same name are deployed, when you press TAB, you will only see 1 of them, if you select it, all of the policies with that name will be removed. If that's not desired, consider using `-PolicyIDs` parameter instead.

> [!NOTE]\
> The auto-completion in these 2 parameters are smart. E.g., if there are 10 policies deployed on the system, you can press Tab to select 5 of them by IDs, but when you try to select the other 5 by their names, the name of the policies that you already selected by IDs don't show up anymore. This greatly reduces user error and simplifies the workflow for end user.

## Parameters

### -PolicyIDs

The submitted values are verified against the currently deployed policies and if they match, the policies are removed.

Just press TAB key and it will autofill the values for you based on the deployed policies. If you want to select multiple names, after each one, enter a comma `,` and then press TAB again to choose another name.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)[]|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -PolicyNames

The submitted values are verified against the currently deployed policies and if they match, the policies are removed.

Just press TAB key and it will autofill the values for you based on the deployed policies. If you want to select multiple IDs, after each one, enter a comma `,` and then press TAB again to choose another ID.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)[]|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>
