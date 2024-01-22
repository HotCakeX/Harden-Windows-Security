# New-KernelModeWDACConfig available parameters

## New-KernelModeWDACConfig -Default

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-KernelModeWDACConfig/New-KernelModeWDACConfig%20-Default.apng)

```powershell
New-KernelModeWDACConfig [-Default] [-PrepMode] [-AuditAndEnforce] [-Deploy] [-EVSigners] [-SkipVersionCheck]
[-WhatIf] [-Confirm] [<CommonParameters>]
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

Hardware drivers are scanned based on their certificates so they will not necessitate a policy update when they are updated as long as they are still signed with the same certificate.

The deployed base policy can have supplemental policies too so if in the future you need to allow more Kernel-mode drivers to run on your system, you can use the following command to automatically generate and deploy a Supplemental policy.

```powershell
Edit-WDACConfig -AllowNewAppsAuditEvents -SuppPolicyName "Kernel mode drivers for software X" -PolicyPath <Path to Strict Kernel-mode policy xml file> -Fallbacks None -NoUserPEs -NoScript
```

[**More info about the command above**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-WDACConfig)

<br>

### 4 Optional Parameters

* `-PrepMode`: Deploys the Strict Kernel-mode WDAC policy in Audit mode, preparing the system for an Audit.

* `-AuditAndEnforce`: Audits the system using event logs for any blocked drivers, generates the final Strict Kernel-mode WDAC policy.

* `-EVSigners`: Uses EVSigners policy rule option. If you want to use this parameter, make sure you use it for both PrepMode and AuditAndEnforce parameters. [Read more about EV Signers](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes#policies-with-requiredev-signers-rule-option)

* `-Deploy`: Indicates that the policy will be deployed. If you want to deploy the final strict kernel-mode base policy Signed, do not use this parameter with `-AuditAndEnforce`. Instead just create the policy and then use [Deploy-SignedWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-SignedWDACConfig) cmdlet to deploy it.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-KernelModeWDACConfig -NoFlightRoots

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-KernelModeWDACConfig/New-KernelModeWDACConfig%20-NoFlightRoots.apng)

```powershell
New-KernelModeWDACConfig [-NoFlightRoots] [-PrepMode] [-AuditAndEnforce] [-Deploy] [-EVSigners]
[-SkipVersionCheck] [-WhatIf] [-Confirm] [<CommonParameters>]
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

Hardware drivers are scanned based on their certificates so they will not necessitate a policy update when they are updated as long as they are still signed with the same certificate.

The deployed base policy can have supplemental policies too so if in the future you need to allow more Kernel-mode drivers to run on your system, you can use the following command to automatically generate and deploy a Supplemental policy.

```powershell
Edit-WDACConfig -AllowNewAppsAuditEvents -SuppPolicyName "Kernel mode drivers for software X" -PolicyPath <Path to Strict Kernel-mode policy xml file> -Fallbacks None -NoUserPEs -NoScript
```

[**More info about the command above**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-WDACConfig)

<br>

### 4 Optional Parameters

* `-PrepMode`: Deploys the Strict Kernel-mode WDAC policy in Audit mode, preparing the system for an Audit.

* `-AuditAndEnforce`: Audits the system using event logs for any blocked drivers, generates the final Strict Kernel-mode WDAC policy.

* `-EVSigners`: Uses EVSigners policy rule option. If you want to use this parameter, make sure you use it for both PrepMode and AuditAndEnforce parameters. [Read more about EV Signers](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes#policies-with-requiredev-signers-rule-option)

* `-Deploy`: Indicates that the policy will be deployed. If you want to deploy the final strict kernel-mode base policy Signed, do not use this parameter with `-AuditAndEnforce`. Instead just create the policy and then use [Deploy-SignedWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-SignedWDACConfig) cmdlet to deploy it.
<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Notes

* **Mandatory** parameters indicate you always need to provide values for them.

* **Automatic** parameters indicate that if you used [Set-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig) cmdlet to set default values for them, the module will automatically use them. This saves time and prevents repetitive tasks. However, if no value exists in User Configurations for an Automatic parameter and you didn't explicitly provide a value for that parameter either, then you will see an error asking you to provide value for it. Explicitly providing a value for an Automatic parameter in the command line overrides its default value in User Configurations, meaning the module will ignore the value of the same parameter in the User Configurations file.

* **Optional** parameters indicate that they are not required and without using them the module will automatically run with the optimal settings.

<br>
