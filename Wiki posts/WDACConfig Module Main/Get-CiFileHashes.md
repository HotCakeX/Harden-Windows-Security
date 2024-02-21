# Get-CiFileHashes available parameters

## Syntax

```powershell
Get-CiFileHashes
    [-FilePath] <FileInfo>
    [<CommonParameters>]
```

## Description

Calculates the Authenticode hash and first page hash of the PEs with SHA1 and SHA256 algorithms. The hashes are compliant wih the Windows Defender Application Control (WDAC) policy.

The cmdlet outputs an ordered hashtable. The keys are the hash algorithm names and the values are the hashes.

For more information please visit [this page](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create#more-information-about-hashes)

> [!NOTE]\
>  If the file is non-conformant, the function will calculate the flat hash of the file using the specified hash algorithm and return them as the Authenticode hashes. This is compliant with how the WDAC engine in Windows works.

## Parameters

### -FilePath

The path to the file for which the hashes are to be calculated. Supports TAB completion, when you press Tab key, file picker GUI will open allowing you to select a file.

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
