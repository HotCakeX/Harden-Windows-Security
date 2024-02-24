# Invoke-WDACSimulation available parameters

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Invoke-WDACSimulation/Invoke-WDACSimulation.apng)

## Syntax

```powershell
Invoke-WDACSimulation
    [-XmlFilePath] <FileInfo>
    [[-FolderPath] <DirectoryInfo>]
    [[-FilePath] <FileInfo>]
    [-BooleanOutput]
    [-Log]
    [-SkipVersionCheck]
    [<CommonParameters>]
```

## Description

This cmdlet allows you to simulate a WDAC (App Control for Business) policy deployment. Simply select a folder or file and a policy XML file, it will show you whether the selected files would be allowed or blocked by your WDAC policy if it was actually deployed on a system and those files were run.

Upon completion of the simulation, you will obtain a CSV file in the current working directory containing the output of the simulation with exhaustive details of each file that would be blocked/allowed by the selected policy.

<br>

## Supported Levels and SpecificFileNameLevel Options

* The WDAC Simulation engine supports the following levels: (Support for the remaining [levels](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create#table-2-windows-defender-application-control-policy---file-rule-levels) will be added in a future update)

  * FilePublisher
  * Publisher
  * SignedVersion
  * PCA Certificate
  * Root Certificate
  * Leaf Certificate
  * Hash

* The engine supports all of the [SpecificFileNameLevel](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create#table-3--specificfilenamelevel-options) options when validating the FilePublisher level.

  * FileDescription
  * InternalName
  * OriginalFileName
  * PackageFamilyName
  * ProductName
  * Filepath

<br>

## Accuracy

* The engine can determine with 100% accuracy whether a file is authorized by a given policy or not as long as the file was scanned based on one of the supported levels mentioned above.

* The `SpecificFileNameLevel` is established with 99.99% accuracy. The only exception is when a file is damaged in a manner that impairs the detection of its additional attributes. *However, this is a rare occurrence, as I have not encountered any such file in over 1 million tests*.

* Explicit Deny rules are not taken into account during simulation. Support for them will be added in a future update. **The nature of the WDAC policies is whitelisting and anything not mentioned in them is automatically blocked/denied**.

<br>

## Some Use Cases

* Have a WDAC policy and you want to test whether all of the files of a program will be allowed by the policy without running the program first? Use this WDAC simulation to find out.

* Employ this simulation method to discover files that are not explicitly specified in the WDAC policy but are still authorized to run by it.

* Identify files that have hash mismatch and will not be permitted by WDAC engine using signature. These files are typically found in [*questionable* software](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes#allowing-questionable-software-in-a-wdac-policy) because they are tampered with.

* And many more.

## Parameters

### -FolderPath

Path to a folder. Supports argument tab completion, select the parameter then press TAB to open the Folder picker GUI.

> [!IMPORTANT]\
> Either FilePath or FolderPath must be provided.

<div align='center'>

| Type: |[DirectoryInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.directoryinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -FilePath

Provide path to a file that you want WDAC simulation to run against

Uses LiteralPath to take the path exactly as typed including Special characters such as `[` and `]`

> [!IMPORTANT]\
> Either FilePath or FolderPath must be provided.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -XmlFilePath

Path to a xml file. Supports argument tab completion, select the parameter then press TAB to open the file picker GUI that only shows xml files.

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -BooleanOutput

Can be used with any parameter to return a boolean value instead of displaying the object output

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

### -Log

Use this switch to start a transcript of the WDAC simulation and log everything displayed on the screen.

> [!IMPORTANT]\
> Highly recommended to use the `-Verbose` parameter with this switch to log the verbose output as well.

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

## Notes

* A small part of this cmdlet's code includes [Vadims Podāns's](https://www.sysadmins.lv/disclaimer.aspx) code for [nested certificate calculation](https://www.sysadmins.lv/blog-en/reading-multiple-signatures-from-signed-file-with-powershell.aspx) of double signed files.

<br>
