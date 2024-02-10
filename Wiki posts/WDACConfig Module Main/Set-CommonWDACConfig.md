# Set-CommonWDACConfig available parameters

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Set-CommonWDACConfig/Set-CommonWDACConfig.apng)

```powershell
Set-CommonWDACConfig
    [[-CertCN] <String>]
    [[-CertPath] <FileInfo>]
    [[-SignToolPath] <FileInfo>]
    [[-UnsignedPolicyPath] <FileInfo>]
    [[-SignedPolicyPath] <FileInfo>]
    [[-StrictKernelPolicyGUID] <Guid>]
    [[-StrictKernelNoFlightRootsPolicyGUID] <Guid>]
    [[-LastUpdateCheck] <DateTime>]
    [[-StrictKernelModePolicyTimeOfDeployment] <DateTime>]
    [<CommonParameters>]
```

<br>

Use this cmdlet to store the values for common and frequently used parameters so that you won't have to specify them again every time.

All of the applicable cmdlets of the module automatically check the User Configuration file for any available input, if you don't specify values for their parameters.

<br>

## An Example

Instead of specifying all of the parameters for `Edit-SignedWDACConfig` cmdlet like this:

```powershell
Edit-SignedWDACConfig -AllowNewApps -SuppPolicyName "App 1" -CertPath "Path To Certificate.cer" -PolicyPaths "Path To Policy.xml" -CertCN "Certificate Common Name"
```

You can just run this

```powershell
Edit-SignedWDACConfig -AllowNewApps -SuppPolicyName "App 1"
```

If correct and valid values for the missing parameters exist in User Configuration file, the cmdlet will automatically detect and use them seamlessly.

<br>

### -CertCN

Common Name of an installed certificate. Supports argument completion so you don't have to manually enter the Certificate's CN, just make sure the certificate is installed in the personal store of the user certificates, then press TAB to auto complete the name. You can however enter it manually if you want to.

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

### -CertPath

Path to the certificate `.cer` file. Press TAB to open the file picker GUI and browse for a `.cer` file.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -SignToolPath

Press TAB to open the file picker GUI and browse for SignTool.exe

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -UnSignedPolicyPath

Path to the xml file of an Unsigned policy. Supports tab completion by showing only the base policies in the current working directory.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -SignedPolicyPath

Path to the xml file of a Signed policy. Supports tab completion by showing only the base policies in the current working directory.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>
