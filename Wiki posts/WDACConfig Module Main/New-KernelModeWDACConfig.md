# New-KernelModeWDACConfig available parameters
![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-KernelModeWDACConfig/New-KernelModeWDACConfig%20-Default.apng)

## Syntax

```powershell
New-KernelModeWDACConfig
    -Mode <String>
    [-Deploy]
    [-EVSigners]
    [-Base <String>]
    [-SkipVersionCheck]
    [<CommonParameters>]
```

## Description

This cmdlet generates a Kernel-mode App Control policy derived from the Default Windows template policy. [You can learn more about that procedure in here.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection)

Initially, you need to use the `-Mode Prep` parameter to deploy the base policy in Audit mode, then restart your system. After restarting, event logs are produced for Kernel-mode drivers that are running but would otherwise be blocked if the policy was not deployed in Audit mode.

Subsequently, you need to use the `-Mode AuditAndEnforce` parameter to generate the final base policy. This parameter will:

1. Scan all of the event logs that were produced after deploying the audit mode policy on the system
2. Generate a supplemental policy for the drivers detected in event logs
3. Merge the supplemental policy with the Strict Kernel-mode base policy
4. Deploy it as a single base policy, rebootlessly.

> [!IMPORTANT]\
> All Kernel-mode drivers are scanned with [WHQLFilePublisher](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#table-2-app-control-for-business-policy---file-rule-levels) level, so they will not necessitate a policy update when they are updated.

<br>

## Parameters

### -Mode

Specifies the mode of operation. The acceptable values for this parameter are: `Prep` and `AuditAndEnforce`.

* Prep: Deploys the Strict Kernel-mode App Control policy in Audit mode, preparing the system for an Audit.

* AuditAndEnforce: Audits the system using event logs for any blocked drivers, generates the final Strict Kernel-mode App Control policy.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | None |
| Required: | True |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>

### -Deploy

Indicates that the policy will be deployed. If you want to deploy the final strict kernel-mode base policy Signed, do not use this parameter, Instead just create the policy and then use the [Deploy-SignedWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-SignedWDACConfig) cmdlet to deploy it.

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

Uses EVSigners policy rule option. If you want to use this parameter, make sure you use it for both `Prep` and `AuditAndEnforce` modes. [Read more about EV Signers](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes#policies-with-requiredev-signers-rule-option)

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

### -Base

The base policy to be used. The acceptable values for this parameter are: `Default` and `NoFlightRoots`.


> [!NOTE]\
> The **NoFlightRoots** value signifies that the Strict Kernel-mode App Control policy will not be deployed with flight root certificates, disallowing you to use insider builds of the OS in the Dev and Canary channels. Insider builds in the Beta and Release Preview channels are signed with production root certificates and will not be affected.

<div align='center'>

| Type: |[String](https://learn.microsoft.com/en-us/dotnet/api/system.string)|
| :-------------: | :-------------: |
| Position: | Named |
| Default value: | `Default` |
| Required: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

</div>

<br>
