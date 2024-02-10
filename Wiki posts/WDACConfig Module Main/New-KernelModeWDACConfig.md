# New-KernelModeWDACConfig available parameters

## New-KernelModeWDACConfig -Default

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-KernelModeWDACConfig/New-KernelModeWDACConfig%20-Default.apng)

```powershell
New-KernelModeWDACConfig
    [-Default]
    [-PrepMode]
    [-AuditAndEnforce]
    [-Deploy]
    [-EVSigners]
    [-SkipVersionCheck]
    [-Confirm]
    [<CommonParameters>]
```

<br>

### How to use

This cmdlet generates a Kernel-mode WDAC policy derived from the Default Windows template policy. [You can learn more about that procedure in here.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection)

The **-Default** parameter signifies that the Strict Kernel-mode WDAC policy will be deployed with flight root certificates, enabling you to utilize insider builds of the OS.

Initially, you need to use the **-PrepMode** parameter to deploy the base policy in Audit mode, then restart your system. After restarting, event logs are produced for Kernel-mode drivers that are running but would otherwise be blocked if the policy was not deployed in Audit mode.

Subsequently, you need to use the **-AuditAndEnforce** parameter to generate the final base policy. This parameter will:

1. Scan all of the event logs that were produced after deploying the audit mode policy on the system
2. Generate a supplemental policy for the drivers detected in event logs
3. Merge the supplemental policy with the Strict Kernel-mode base policy
4. Deploy it as a single base policy, rebootlessly.

Hardware drivers are scanned with [WHQLFilePublisher](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create#table-2-windows-defender-application-control-policy---file-rule-levels) level. so they will not necessitate a policy update when they are updated.

<br>

### -PrepMode

Deploys the Strict Kernel-mode WDAC policy in Audit mode, preparing the system for an Audit.

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

### -AuditAndEnforce

Audits the system using event logs for any blocked drivers, generates the final Strict Kernel-mode WDAC policy.

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

### -EVSigners

Uses EVSigners policy rule option. If you want to use this parameter, make sure you use it for both PrepMode and AuditAndEnforce parameters. [Read more about EV Signers](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes#policies-with-requiredev-signers-rule-option)

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

### -Deploy

Indicates that the policy will be deployed. If you want to deploy the final strict kernel-mode base policy Signed, do not use this parameter with `-AuditAndEnforce`. Instead just create the policy and then use [Deploy-SignedWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-SignedWDACConfig) cmdlet to deploy it.

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

## New-KernelModeWDACConfig -NoFlightRoots

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-KernelModeWDACConfig/New-KernelModeWDACConfig%20-NoFlightRoots.apng)

```powershell
New-KernelModeWDACConfig
    [-NoFlightRoots]
    [-PrepMode]
    [-AuditAndEnforce]
    [-Deploy]
    [-EVSigners]
    [-SkipVersionCheck]
    [-WhatIf]
    [-Confirm]
    [<CommonParameters>]
```

<br>

### How to use

This cmdlet generates a Kernel-mode WDAC policy derived from the Default Windows template policy. [You can learn more about that procedure in here.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection)

The **-NoFlightRoots** parameter signifies that the Strict Kernel-mode WDAC policy will not be deployed with flight root certificates, disallowing you to use insider builds of the OS.

Initially, you need to use the **-PrepMode** parameter to deploy the base policy in Audit mode, then restart your system. After restarting, event logs are produced for Kernel-mode drivers that are running but would otherwise be blocked if the policy was not deployed in Audit mode.

Subsequently, you need to use the **-AuditAndEnforce** parameter to generate the final base policy. This parameter will:

1. Scan all of the event logs that were produced after deploying the audit mode policy on the system
2. Generate a supplemental policy for the drivers detected in event logs
3. Merge the supplemental policy with the Strict Kernel-mode base policy
4. Deploy it as a single base policy, rebootlessly.

Hardware drivers are scanned with [WHQLFilePublisher](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create#table-2-windows-defender-application-control-policy---file-rule-levels) level so they will not necessitate a policy update when they are updated.

<br>

### -PrepMode

Deploys the Strict Kernel-mode WDAC policy in Audit mode, preparing the system for an Audit.

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

### -AuditAndEnforce

Audits the system using event logs for any blocked drivers, generates the final Strict Kernel-mode WDAC policy.

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

### -EVSigners

Uses EVSigners policy rule option. If you want to use this parameter, make sure you use it for both PrepMode and AuditAndEnforce parameters. [Read more about EV Signers](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes#policies-with-requiredev-signers-rule-option)

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

### -Deploy

Indicates that the policy will be deployed. If you want to deploy the final strict kernel-mode base policy Signed, do not use this parameter with `-AuditAndEnforce`. Instead just create the policy and then use [Deploy-SignedWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-SignedWDACConfig) cmdlet to deploy it.

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
