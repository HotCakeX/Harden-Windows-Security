# Remove-CommonWDACConfig available parameters

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Remove-CommonWDACConfig/Remove-CommonWDACConfig.apng)

## Syntax

```powershell
Remove-CommonWDACConfig
    [-CertCN]
    [-CertPath]
    [-SignToolPath]
    [-UnsignedPolicyPath]
    [-SignedPolicyPath]
    [-StrictKernelPolicyGUID]
    [-StrictKernelNoFlightRootsPolicyGUID]
```

## Description

Use this cmdlet to remove the values stored in the User Configurations JSON file. If you use it without any parameters it will delete the User configuration folder and everything in it, which is located in `C:\Users\UserName\.WDACConfig`

## Parameters

### -CertCN

Removes the saved Certificate Common Name from User Configurations

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

### -CertPath

Removes the saved Certificate path from User Configurations

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

### -SignToolPath

Removes the saved SignTool.exe Path from User Configurations

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

### -UnsignedPolicyPath

Removes the saved Unsigned Policy Path from User Configurations

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

### -SignedPolicyPath

Removes the saved Signed Policy Path from User Configurations

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

### -StrictKernelPolicyGUID

Removes the saved Strict Kernel Policy GUID from User Configurations

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

### -StrictKernelNoFlightRootsPolicyGUID

Removes the saved Strict Kernel NoFlight Roots Policy GUID from User Configurations

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
