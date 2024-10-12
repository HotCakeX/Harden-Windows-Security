# Assert-WDACConfigIntegrity available parameters

![Assert-WDACConfigIntegrity demo](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Assert-WDACConfigIntegrity/Assert-WDACConfigIntegrity.gif)

## Syntax

```powershell
Assert-WDACConfigIntegrity
    [-SaveLocally]
    [-Path <DirectoryInfo>]
    [-SkipVersionCheck]
    [<CommonParameters>]
```

## Description

This cmdlet scans all of the relevant files in the WDACConfig module's folder and computes their SHA2-512 hashes.

Then it downloads the [cloud CSV file](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/WDACConfig/Utilities/Hashes.csv) from the GitHub repository and compares the hashes of the local files with the ones in the cloud.

By doing so, you can ascertain that the files in your local WDACConfig folder are identical to the ones in the cloud and devoid of any interference.

If there is any indication of tampering, the outcomes will be displayed on the console.

## Parameters

### -SaveLocally

This parameter is used to generate hashes of the final module's files prior to publishing them to the GitHub. This parameter shouldn't be used.

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

### -Path

Can define a different path for the `Hashes.csv` file. This parameter shouldn't be used.

<div align='center'>

| Type: |[DirectoryInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.directoryinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | Module's Root Directory |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>
