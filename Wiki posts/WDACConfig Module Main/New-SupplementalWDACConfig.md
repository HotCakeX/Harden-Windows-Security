# New-SupplementalWDACConfig available parameters

## New-SupplementalWDACConfig -PathWildCards


## Syntax

```powershell
New-SupplementalWDACConfig
    [-PathWildCards]
    -FolderPath <DirectoryInfo>
    -SuppPolicyName <String>
    [-PolicyPath <FileInfo>]
    [-Deploy]
    [-Confirm]
    [<CommonParameters>]
```

## Description

Creates a Supplemental policy that allows a folder path that includes one or more wildcard `*` character in it.

## Parameters

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

### -SuppPolicyName

Add a descriptive name for the Supplemental policy. Accepts only alphanumeric and space characters.

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

### -PolicyPath

Browse for the xml file of the Base policy this Supplemental policy is going to expand.
Supports GUI file picker that only shows XML files, press TAB after the parameter to launch it.

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

Indicates that the module will automatically deploy the Supplemental policy after creation.

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

### The outputs of the parameter are

* ***SupplementalPolicy`<Custom Name>`.xml***
* ***{GUID}.cip***

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-SupplementalWDACConfig -InstalledAppXPackages

## Syntax

```powershell
New-SupplementalWDACConfig
    [-InstalledAppXPackages]
    -PackageName <String>
    -SuppPolicyName <String>
    [-PolicyPath <FileInfo>]
    [-Deploy]
    [-Force]
    [-Confirm]
    [<CommonParameters>]
```

## Description

Creates a Supplemental policy based on the package name of an installed app. More information at [Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/manage-packaged-apps-with-appcontrol)

## Parameters

### -PackageName

Enter the [package name](https://learn.microsoft.com/en-us/powershell/module/appx/get-appxpackage) of an installed app. Supports wildcard `*` character. e.g., `*Edge*` or `"*Microsoft*"`.

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

### -SuppPolicyName

Add a descriptive name for the Supplemental policy. Accepts only alphanumeric and space characters.

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

### -PolicyPath

Browse for the xml file of the Base policy this Supplemental policy is going to expand.
Supports GUI file picker that only shows XML files, press TAB after the parameter to launch it.

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

Indicates that the module will automatically deploy the Supplemental policy after creation.

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

Indicates that the cmdlet won't ask for confirmation and will proceed with creating the Supplemental policy.

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

### The outputs of the parameter are

* ***SupplementalPolicy`<Custom Name>`.xml***
* ***{GUID}.cip***

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-SupplementalWDACConfig -Certificates

## Syntax

```powershell
    New-SupplementalWDACConfig
    [-Certificates]
    -CertificatePaths <FileInfo[]>
    -SuppPolicyName <String>
    [-PolicyPath <FileInfo>]
    [-Deploy]
    [-SigningScenario <String>]
    [<CommonParameters>]
```

## Description

Creates a Supplemental policy based on the certificate paths.

* If you select a root CA certificate, it will generate Signer rules based on RootCertificate level which contains TBS Hash only.

* If you select a non-root CA certificate such as Leaf Certificate or Intermediate certificate, it will generate Signer rules based on LeafCertificate level, that means it will contain TBS Hash as well as the subject name of the selected certificate.

## Parameters

### -CertificatePaths

Browse for the certificate file(s) that you want to use to create the Supplemental policy. Supports file picker GUI by showing only .cer files.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)[]|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | True |

</div>

<br>

### -SuppPolicyName

Add a descriptive name for the Supplemental policy. Accepts only alphanumeric and space characters.

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

### -PolicyPath

Browse for the xml file of the Base policy this Supplemental policy is going to expand.
Supports GUI file picker that only shows XML files, press TAB after the parameter to launch it.

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

Indicates that the module will automatically deploy the Supplemental policy after creation.

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

### -SigningScenario

You can choose one of the following options: "UserMode", "KernelMode"
The certificate will be added to the policy based on the selected scenario.

<div align='center'>

| Type: |[SwitchParameter](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.switchparameter)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | `UserMode` |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>
