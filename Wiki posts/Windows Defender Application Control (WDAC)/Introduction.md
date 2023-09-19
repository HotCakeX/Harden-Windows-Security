# What is Windows Defender Application Control?

Application control is a crucial line of defense for protecting enterprises given today's threat landscape, and it has an inherent advantage over traditional antivirus solutions. Specifically, application control moves away from an application trust model where all applications are assumed trustworthy to one where applications must earn trust in order to run.

Devices where Windows Defender Application control (WDAC) policies are deployed on can either be centrally managed via MDM, Intune etc. or they can be home devices, devices that are private and don't belong to any organization, the computer of someone that you want to keep 100% safe and secure [so that even the device's owner can't willingly or forcefully compromise themselves,](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Create-and-Deploy-a-Signed-WDAC-Policy-Windows-Defender-Application-Control) the possibilities are endless.

<br>

## Windows Defender Application Control (WDAC) wiki posts

* [Introduction](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction)
* [**WDACConfig** Module](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig)
* [WDAC for Lightly managed device](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-for-Lightly-Managed-Devices)
* [WDAC for Fully managed device - Variant 1](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-for-Fully-Managed-Devices)
* [WDAC for Fully managed device - Variant 2](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-for-Fully-Managed-Devices--Variant-2)
* [WDAC for Fully managed device - Variant 3](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-Fully-managed-device---Variant-3)
* [WDAC for Fully managed device - Variant 4](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-Fully-managed-device---Variant-4)
* [WDAC Notes](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes)
* [**How to Create and Deploy a Signed WDAC Policy**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Create-and-Deploy-a-Signed-WDAC-Policy-Windows-Defender-Application-Control)
* [Fast and Automatic Microsoft Recommended Driver Block Rules updates](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Fast-and-Automatic-Microsoft-Recommended-Driver-Block-Rules-updates)
* [WDAC policy for BYOVD Kernel mode only protection](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection)

<br>

## [My WDACConfig Module](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig)

[**WDACConfig**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) is an advanced PowerShell module designed with the aim of automating [Application and File whitelisting in Windows](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/wdac) using Windows Defender Application Control. Install it from [PowerShell gallery](https://www.powershellgallery.com/packages/WDACConfig/).

<br>

## WDAC usage levels

There are many ways you can utilize WDAC features and here they are sorted by the level of restriction and protection they provide; From top (having the least restriction and protection) to bottom (having the most restriction and protection).

1. Use Microsoft recommended driver block rules.
      - **No user action required**. Starting with Windows 11 2022 update, the vulnerable driver blocklist is enabled by default for all devices, using HVCI or Memory Integrity.
      - [The built-in driver blocklist is updated with each new major release of Windows, typically 1-2 times per year.](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)

2. Update Microsoft recommended driver block rules **outside of the twice a year schedule.**
      - The drivers block list itself [is updated more frequently](https://github.com/MicrosoftDocs/windows-itpro-docs/commits/public/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md) than twice a year schedule, [use my WDAC Module to download and apply them regularly and ***automatically***.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Fast-and-Automatic-Microsoft-Recommended-Driver-Block-Rules-updates)
3. Use Microsoft recommended block rules PLUS Recommended driver block rules
      - [The WDAC XML policy content is provided here](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac), copy them, create a new XML file and paste the content in it and save it. [Reset its policy ID and convert it to multiple policy format](https://learn.microsoft.com/en-us/powershell/module/configci/set-cipolicyidinfo?view=windowsserver2022-ps#-resetpolicyid). [Convert it to `.cip` policy binary](https://docs.microsoft.com/en-us/powershell/module/configci/convertfrom-cipolicy) and then [deploy it](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/citool-commands#deploy-a-wdac-policy). Keep it up to date by regularly repeating this.
4. Create WDAC policy for **Lightly managed devices**
      - [Microsoft's guide: Create a WDAC policy for lightly managed devices](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/create-wdac-policy-for-lightly-managed-devices)
      - [My guide: WDAC for Lightly Managed Devices](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-for-Lightly-Managed-Devices)
5. Use [Smart App Control](https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003)
      - It's just a toggle in Windows Security under App & Browser control. It uses a special kind of WDAC policy that provides more protection than a lightly managed workstation but less protection than a fully managed workstation.
      - It uses both of Microsoft's recommended block rules.
6. Create WDAC policy for **Fully managed devices**
      - The following scenarios [provide the highest protection](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Create-and-Deploy-a-Signed-WDAC-Policy-Windows-Defender-Application-Control) against any threats from any sources when cryptographically signed and deployed and properly configured.
      - [WDAC for Fully managed device - Variant 1](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-for-Fully-Managed-Devices)
      - [WDAC for Fully managed device - Variant 2](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-for-Fully-Managed-Devices--Variant-2)
      - [WDAC for Fully managed device - Variant 3](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-Fully-managed-device---Variant-3)
      - [WDAC for Fully managed device - Variant 4](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-Fully-managed-device---Variant-4)
      - [Microsoft's guide: Create a WDAC policy for fully managed devices](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/create-wdac-policy-for-fully-managed-devices)
      - [Microsoft's guide: Create a WDAC policy for fixed-workload devices (reference computer)](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/create-wdac-policy-using-reference-computer)
      - [Microsoft's guide: Use audit events to create WDAC policy rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/audit-wdac-policies)

<br>

## Methods we can use to create a WDAC policy

* Using [PowerShell cmdlets](https://learn.microsoft.com/en-us/powershell/module/configci)
* Using [WDACConfig PowerShell module](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig)
* Using [WDAC Policy Wizard](https://webapp-wdac-wizard.azurewebsites.net/)

<br>

## Plan for Windows Defender Application Control lifecycle policy management

Microsoft provides the [following official document](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/plan-wdac-management) to understand the decisions you need to make to establish the processes for managing and maintaining Windows Defender Application Control (WDAC) policies. The rest of them are mentioned below at the **Resources** section.

<br>

## Resources

*There are a lot more WDAC resources and cmdlets available on Microsoft's websites.*

## Cmdlets

* [New-CIPolicy](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy)
* [New-CIPolicyRule](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicyrule)
* [Merge-CIPolicy](https://learn.microsoft.com/en-us/powershell/module/configci/merge-cipolicy)
* [Set-RuleOption](https://learn.microsoft.com/en-us/powershell/module/configci/set-ruleoption)
* [Set-CIPolicyIdInfo](https://learn.microsoft.com/en-us/powershell/module/configci/set-cipolicyidinfo)

## Documents

* [Application Control for Windows](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/wdac)
* [Understand Windows Defender Application Control policy design decisions](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/understand-wdac-policy-design-decisions)
* [Deploying Windows Defender Application Control (WDAC) policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/wdac-deployment-guide)
* [Use multiple Windows Defender Application Control Policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/deploy-multiple-wdac-policies)
* [Use audit events to create WDAC policy rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/audit-wdac-policies)
* [Merge Windows Defender Application Control (WDAC) policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/merge-wdac-policies)
* [Understand Windows Defender Application Control (WDAC) policy rules and file rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create#windows-defender-application-control-policy-rules)
* [Testing and Debugging AppId Tagging Policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/AppIdTagging/debugging-operational-guide-appid-tagging-policies)
* [Editing existing base and supplemental WDAC policies with the Wizard](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/wdac-wizard-editing-policy)
* [Creating a new Supplemental Policy with the Wizard](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/wdac-wizard-create-supplemental-policy)
* [Generate Windows Defender Application Control (WDAC) policies Online](https://schneegans.de/windows/wdac-policy-generator/)
* [Windows Defender Application Control (WDAC) example base policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/example-wdac-base-policies)
* [Configure the Application Identity service](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/configure-the-application-identity-service)
* [Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)
* [Microsoft recommended block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac)
* [Create a WDAC policy using a reference computer (for fixed-workload devices)](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/create-wdac-policy-using-reference-computer)
* [Create a WDAC policy for fully managed devices](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/create-wdac-policy-for-fully-managed-devices)
* [Create a WDAC policy for lightly managed devices](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/create-wdac-policy-for-lightly-managed-devices)
* [Guidance on Creating WDAC Deny Policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/create-wdac-deny-policy)
* [Hypervisor-protected Code Integrity enablement](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-hvci-enablement)

<br>
