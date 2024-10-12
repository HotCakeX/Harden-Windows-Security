# Deploy-SignedWDACConfig available parameters

<div align="center">
<a href="https://www.youtube.com/watch?v=nZ5c9ceaEwA"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Thumbnails%20with%20YouTube%20play%20logo/YouTube%20Thumbnal%20-%20deploy%20Signed%20WDAC%20policies.png" alt="How to sign and deploy signed App Control policies" width="550"></a></div>

<br>

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Deploy-SignedWDACConfig/Deploy-SignedWDACConfig.apng)

## Syntax

```powershell
Deploy-SignedWDACConfig
    -PolicyPaths <FileInfo[]>
    [-Deploy]
    [-CertPath <FileInfo>]
    [-CertCN <String>]
    [-SignToolPath <FileInfo>]
    [-Force]
    [-SkipVersionCheck]
    [-Confirm]
    [<CommonParameters>]
```

## Description

Creates and signs a `.CIP` file that can be either deployed locally using the `-Deploy` parameter or you can deploy the signed policy binary on a different machine later using the built-in [Citool](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/citool-commands), Intune etc.

## Parameters

### -PolicyPaths

The XML Policies to deploy. Supports File picker GUI.

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

### -CertPath

Path to the certificate `.cer` file. Press TAB to open the file picker GUI and browse for a `.cer` file.

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

### -CertCN

Common name of the certificate - Supports argument completion so you don't have to manually enter the Certificate's CN, just make sure the `-CertPath` is specified and the certificate is installed in the personal store of the user certificates, then press TAB to auto complete the name. You can however enter it manually if you want to.

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

### -Deploy

Deploys the signed policy on the system

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

Indicates that the cmdlet won't ask for confirmation and will proceed with deploying the signed policy.

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
