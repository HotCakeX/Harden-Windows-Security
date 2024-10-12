# Test-CiPolicy available parameters

![Test-CiPolicy demo](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Test-CiPolicy/Test-CiPolicy%20-XmlFile.gif)

## Syntax

```powershell
Test-CiPolicy
    -XmlFile <FileInfo>
    -CipFile <FileInfo>
    [<CommonParameters>]
```

## Description

Tests a Code Integrity (App Control) Policy XML file against the Schema file located at:

```powershell
$Env:SystemDrive\Windows\schemas\CodeIntegrity\cipolicy.xsd
```

It returns a boolean value indicating whether the XML file is valid or not.

It can also be used to display the signer certificates used to sign a `.CIP` binary file.

## Parameters

### -XmlFile

The Code Integrity Policy XML file to test. Supports file picker GUI.

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

### -CipFile

The binary Code Integrity Policy file to test for signers. Supports file picker GUI.

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
