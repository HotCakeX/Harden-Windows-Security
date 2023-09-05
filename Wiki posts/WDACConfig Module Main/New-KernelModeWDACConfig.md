# New-KernelModeWDACConfig available parameters

## Notes

* **Mandatory** parameters indicate you always need to provide values for them.

* **Automatic** parameters indicate that if you used [Set-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig) cmdlet to set default values for them, the module will automatically use them. This saves time and prevents repetitive tasks. However, if no value exists in User Configurations for an Automatic parameter and you didn't explicitly provide a value for that parameter either, then you will see an error asking you to provide value for it. Explicitly providing a value for an Automatic parameter in the command line overrides its default value in User Configurations, meaning the module will ignore the value of the same parameter in the User Configurations file.

* **Optional** parameters indicate that they are not required and without using them the module will automatically run with the optimal settings.

* Many cmdlets and parameters of the module support the PowerShell's built-in `-Debug` switch and when that switch is used, they display extra details and debugging messages on the console, showing you what's happening under the hood.

<br>

### During the PrepModes, [the following event log categories](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/event-id-explanations) are cleared

* Applications and Services logs – Microsoft – Windows – CodeIntegrity – Operational includes events about Application Control policy activation and the control of executables, dlls, and drivers.

* Applications and Services logs – Microsoft – Windows – AppLocker – MSI and Script includes events about the control of MSI installers, scripts, and COM objects.

This behavior is required so that the audit phase will have the correct logs to scan and add to the base policy for allow listing. This behavior can be changed/improved in a future module update.

Before the audit mode phase, make sure you trust all the files and programs installed on your system, otherwise you risk allow listing vulnerable or malicious drivers in your policy.

<br>

## New-KernelModeWDACConfig -Default

![image](https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Wiki%20APNGs/New-KernelModeWDACConfig%20-Default%20-PrepMode.apng)

```powershell
New-KernelModeWDACConfig [-Default] [-PrepMode] [-AuditAndEnforce] [-EVSigners] [-Deploy]
```

<br>

### How to use

This cmdlet creates a Kernel-mode WDAC policy based on the Default Windows example policy. [You can read more about that process in here.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection)

The default parameter indicates that the Strict Kernel-mode WDAC policy will be deployed with flight root certificates, allowing you to use insider builds of the OS.

First you need to use the **PrepMode** parameter to deploy the base policy in Audit mode, then reboot your system, after reboot event logs are generated for Kernel-mode drivers that are running but would otherwise get blocked if the policy was not deployed in Audit mode.

<br>

Now you need to use the **AuditAndEnforce** parameter to create the final base policy. This parameter will scan the event logs, create a supplemental policy for the drivers detected in event logs, merge the supplemental policy with the Strict Kernel-mode base policy and deploy it as a single base policy. **No reboot required after deploying the final enforced mode policy, reboot is only required 1 time, after deploying the Audit mode policy.**

Hardware drivers are scanned based on their certificates so they won't require a policy update when they are updated as long as they are still signed with the same certificate.

The deployed base policy can have supplemental policies too so if in the future you need to allow more Kernel-mode drivers to run on your system, you can use the following command to automatically create and deploy a Supplemental policy.

```powershell
Edit-WDACConfig -AllowNewAppsAuditEvents -SuppPolicyName "Kernel mode drivers for software X" -PolicyPaths <Path to Strict Kernel-mode policy xml file> -Fallbacks None -NoUserPEs -NoScript
```

[**More info about the command above**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-WDACConfig)

<br>

### 4 optional parameter

* `-PrepMode`: Deploys the Strict Kernel-mode WDAC policy in Audit mode, preparing the system for an Audit.

* `-AuditAndEnforce`: Audits the system using event logs for any blocked drivers, generates and deploys the final Strict Kernel-mode WDAC policy on the system.

* `-EVSigners`: Uses EVSigners policy rule option. If you want to use this parameter, make sure you use it for both PrepMode and AuditAndEnforce parameters. [Read more about EV Signers](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes#policies-with-requiredev-signers-rule-option)

* `-Deploy`: Indicates that the policy will be deployed. If you want to deploy the final strict kernel-mode base policy Signed, do not use this parameter with `-AuditAndEnforce`. Instead just create the policy and then use [Deploy-SignedWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-SignedWDACConfig) cmdlet to deploy it.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-KernelModeWDACConfig -NoFlightRoots

![image](https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Wiki%20APNGs/New-KernelModeWDACConfig%20-NoFlightRoots%20-PrepMode.apng)

```powershell
New-KernelModeWDACConfig [-NoFlightRoots] [-PrepMode] [-AuditAndEnforce] [-EVSigners] [-Deploy]
```

<br>

### How to use

This cmdlet creates a Kernel-mode WDAC policy based on the Default Windows example policy. [You can read more about that process in here.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection)

The NoFlightRoots parameter indicates that the Strict Kernel-mode WDAC policy will not be deployed with flight root certificates, disallowing you to use insider builds of the OS.

First you need to use the **PrepMode** parameter to deploy the base policy in Audit mode, then reboot your system, after reboot event logs are generated for Kernel-mode drivers that are running but would otherwise get blocked if the policy was not deployed in Audit mode.

Now you need to use the **AuditAndEnforce** parameter to create the final base policy. This parameter will scan the event logs, create a supplemental policy for the drivers detected in event logs, merge the supplemental policy with the Strict Kernel-mode base policy and deploy it as a single base policy. **No reboot required after deploying the final enforced mode policy, reboot is only required 1 time, after deploying the Audit mode policy.**

Hardware drivers are scanned based on their certificates so they won't require a policy update when they are updated as long as they are still signed with the same certificate.

The deployed base policy can have supplemental policies too so if in the future you need to allow more Kernel-mode drivers to run on your system, you can use the following command to automatically create and deploy a Supplemental policy.

```powershell
Edit-WDACConfig -AllowNewAppsAuditEvents -SuppPolicyName "Kernel mode drivers for software X" -PolicyPaths <Path to Strict Kernel-mode policy xml file> -Fallbacks None -NoUserPEs -NoScript
```

[**More info about the command above**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-WDACConfig)

<br>

### 4 optional parameter

* `-PrepMode`: Deploys the Strict Kernel-mode WDAC policy in Audit mode, preparing the system for an Audit.

* `-AuditAndEnforce`: Audits the system using event logs for any blocked drivers, generates and deploys the final Strict Kernel-mode WDAC policy on the system.

* `-EVSigners`: Uses EVSigners policy rule option. If you want to use this parameter, make sure you use it for both PrepMode and AuditAndEnforce parameters. [Read more about EV Signers](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes#policies-with-requiredev-signers-rule-option)

* `-Deploy`: Indicates that the policy will be deployed. If you want to deploy the final strict kernel-mode no flight roots base policy Signed, do not use this parameter with `-AuditAndEnforce`. Instead just create the policy and then use [Deploy-SignedWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-SignedWDACConfig) cmdlet to deploy it.
