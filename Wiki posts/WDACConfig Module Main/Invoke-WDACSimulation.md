# Invoke-WDACSimulation available parameters

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Invoke-WDACSimulation/Invoke-WDACSimulation.apng)

<a href="https://www.youtube.com/watch?v=A0bKDaeYomg"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Simulating%20Application%20Control%20(WDAC)%20Policies%20Using%20The%20WDACConfig%20Module%20-%20low%20res.png" Alt="Simulating Application Control Deployment in Windows"></a>

## Syntax

```powershell
Invoke-WDACSimulation
  [-XmlFilePath] <FileInfo>
  [[-FolderPath] <DirectoryInfo[]>]
  [[-FilePath] <FileInfo[]>]
  [-BooleanOutput]
  [-CSVOutput]
  [-Log]
  [-NoCatalogScanning]
  [[-CatRootPath] <DirectoryInfo[]>]
  [[-ThreadsCount] <UInt32>]
  [<CommonParameters>]
```

## Description

This cmdlet allows you to simulate an App Control for Business policy deployment. Simply select folders or files and a policy XML file, it will show you whether the selected files would be allowed or blocked by your App Control policy if it was actually deployed on a system and those files were run.

<br>

## Supported Levels and SpecificFileNameLevel Options

* The App Control Simulation engine **supports** the following [levels](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide):

  * WHQLFilePublisher
  * WHQLPublisher
  * WHQL
  * FilePublisher
  * Publisher
  * SignedVersion
  * PCA Certificate
  * Root Certificate
  * Leaf Certificate
  * Hash
  * FilePath

* The engine **supports** all of the [SpecificFileNameLevel](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#table-3--specificfilenamelevel-options) options when validating the FilePublisher level.

  * FileDescription
  * InternalName
  * OriginalFileName
  * PackageFamilyName
  * ProductName
  * Filepath

* The Simulation engine *doesn't support* the following [level](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide#--filename) yet (they will be added in a future update):

    * FileName

<br>

## Accuracy

* The engine can determine with 100% accuracy whether a file is authorized by a given policy or not as long as the file was scanned based on one of the supported levels mentioned above.

<br>

## Some Use Cases

* Have an App Control policy and you want to test whether all of the files of a program will be allowed by the policy without running the program first? Use this App Control simulation to find out.

* Employ this simulation method to discover files that are not explicitly specified in the App Control policy but are still authorized to run by it.

* Identify files that have hash mismatch and will not be permitted by App Control engine using signature. These files are typically found in [*questionable* software](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes#allowing-questionable-software-in-a-wdac-policy) because they are tampered with.

* And many more.

## Parameters

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

### -FolderPath

Path to folders. Supports argument tab completion, select the parameter then press TAB to open the Folder picker GUI.

<div align='center'>

| Type: |[DirectoryInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.directoryinfo)[]|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -FilePath

Provide path to files that you want App Control simulation to run against

<div align='center'>

| Type: |[FileInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileinfo)[]|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -BooleanOutput

Can be used with any parameter to return a boolean value instead of displaying the object output. If any of the selected files or any of the files in the selected folders are not authorized by the selected XML file, the result is `$false`. Otherwise, the result is `$true`.

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

### -CSVOutput

Upon completion of the simulation, you will obtain a CSV file containing the output of the simulation with exhaustive details of each file that would be blocked/allowed by the selected policy, and which rule or signer in the XML policy is responsible for the decision.

It is saved in the WDACConfig folder in `C:\Program Files\WDACConfig`

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

Use this switch to start a transcript of the App Control simulation and log everything displayed on the screen.

The log file is saved in the WDACConfig folder in `C:\Program Files\WDACConfig`

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

### -CatRootPath

Provide path(s) to directories where security catalog `.cat` files are located. If not provided, the default path is `C:\Windows\System32\CatRoot`. Supports argument tab completion, select the parameter then press TAB to open the Folder picker GUI.

<div align='center'>

| Type: |[DirectoryInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.directoryinfo)[]|
| :-------------: | :-------------: |
| Aliases: | Cat |
| Position: | Named |
| Default value: | None |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -NoCatalogScanning

Bypass the scanning of the security catalogs on the system. It can make the scan results less accurate.

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

### -ThreadsCount

The number of the concurrent/parallel tasks to use when performing App Control Simulation.

* Max is the number of your system's CPU cores.
* Min is 1.
* If you enter a number higher than your system's CPU cores, it will be set to your system's CPU cores count.

<div align='center'>

| Type: |[UInt32](https://learn.microsoft.com/en-us/dotnet/api/system.uint32)|
| :-------------: | :-------------: |
| Aliases: | CPU |
| Position: | Named |
| Default value: | 2 |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>
