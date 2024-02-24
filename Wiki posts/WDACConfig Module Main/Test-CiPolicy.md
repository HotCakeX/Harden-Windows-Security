# Test-CiPolicy available parameters

## Syntax

```powershell
Test-CiPolicy
    [-XmlFile] <FileInfo>
    [<CommonParameters>]
```

## Description

Tests a Code Integrity (WDAC) Policy XML file against the Schema file located at:

```powershell
$Env:SystemDrive\Windows\schemas\CodeIntegrity\cipolicy.xsd
```

It returns a boolean value indicating whether the XML file is valid or not.


## Parameters

### -XmlFile

The XML file to validate

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