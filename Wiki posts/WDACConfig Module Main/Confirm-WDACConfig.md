# Confirm-WDACConfig available parameters

## Confirm-WDACConfig -ListActivePolicies

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Confirm-WDACConfig/Confirm-WDACConfig%20-ListActivePolicies.apng)

```powershell
Confirm-WDACConfig
    [-ListActivePolicies]
    [-OnlyBasePolicies]
    [-OnlySupplementalPolicies]
```

<br>

Lists the non-System Base and Supplemental WDAC Policies using [CITool](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/citool-commands) and displays their counts.

### -OnlyBasePolicies

Using this will only display Base policies.

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

### -OnlySupplementalPolicies

Using this will only display Supplemental policies.

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

## Confirm-WDACConfig -VerifyWDACStatus

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Confirm-WDACConfig/Confirm-WDACConfig%20-VerifyWDACStatus.apng)

```powershell
Confirm-WDACConfig
    [-VerifyWDACStatus]
```

<br>

Shows the [status](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes#how-to-verify-the-status-of-user-mode-and-kernel-mode-wdac-on-a-system) of User-mode and Kernel-mode application control.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Confirm-WDACConfig -CheckSmartAppControlStatus

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Confirm-WDACConfig/Confirm-WDACConfig%20-CheckSmartAppControlStatus.apng)

```powershell
Confirm-WDACConfig
    [-CheckSmartAppControlStatus]
```

<br>

Checks the status of Smart App Control and reports the results on the console, including the evaluation mode expiration date.

<br>
