# What is Windows Defender Application Control?

<div align="center">
<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/Application%20Control%20for%20Business.gif" alt="App Control for Business introduction and WDACConfig Module">
</div>

<br>

Application control is crucial for protecting computer systems in today's threat landscape and offers a distinct advantage over traditional antivirus solutions. Specifically, application control uses tailored access, shifting from a model where all applications are assumed trustworthy to one where applications must earn trust before they can run.

Devices where Application Control policies are deployed on can either be centrally managed via MDM, Intune etc. or they can be home devices, devices that are private and don't belong to any organization, the computer of someone that you want to keep very much safe and secure [so that even the device's owner can't willingly or forcefully compromise themselves,](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Create-and-Deploy-a-Signed-WDAC-Policy-Windows-Defender-Application-Control) the possibilities are endless.

<br>

> [!IMPORTANT]\
> This repository provides 2 main methods that allows you to manage App Control in Windows. The primary method is the **AppControl Manager** app, and the other one is the WDACConfig PowerShell module. They are one-stop shops for all your Application Control (WDAC) needs. they are scalable, easy to use, enterprise-ready, Azure VM ready and more importantly, they are free and always will be that way. [**Check it out here**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig)

<br>

## App Control for Business wiki posts

* [Introduction](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction)
* [WDAC for Lightly managed device](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-for-Lightly-Managed-Devices)
* [WDAC for Fully managed device - Variant 1](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-for-Fully-Managed-Devices)
* [WDAC for Fully managed device - Variant 2](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-for-Fully-Managed-Devices--Variant-2)
* [WDAC for Fully managed device - Variant 3](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-Fully-managed-device---Variant-3)
* [WDAC for Fully managed device - Variant 4](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-Fully-managed-device---Variant-4)
* [WDAC Notes](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes)
* [How to Create and Deploy a Signed WDAC Policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Create-and-Deploy-a-Signed-WDAC-Policy-Windows-Defender-Application-Control)
* [Fast and Automatic Microsoft Recommended Driver Block Rules updates](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Fast-and-Automatic-Microsoft-Recommended-Driver-Block-Rules-updates)
* [WDAC policy for BYOVD Kernel mode only protection](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection)
* [EKUs in WDAC, App Control for Business, Policies](https://github.com/HotCakeX/Harden-Windows-Security/wiki/EKUs-in-WDAC,-App-Control-for-Business,-Policies)
* [WDAC Rule Levels Comparison and Guide](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide)
* [Script Enforcement and PowerShell Constrained Language Mode in WDAC App Control Policies](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Script-Enforcement-and-PowerShell-Constrained-Language-Mode-in-WDAC-App-Control-Policies)
* [How to Use Microsoft Defender for Endpoint Advanced Hunting With WDAC App Control](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Use-Microsoft-Defender-for-Endpoint-Advanced-Hunting-With-WDAC-App-Control)
* [Application Control (WDAC) Frequently Asked Questions (FAQs)](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Application-Control-(WDAC)-Frequently-Asked-Questions-(FAQs))

<br>

## WDACConfig Module

[**WDACConfig**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) is an advanced PowerShell module designed with the aim of automating [Application and File whitelisting in Windows](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol) using App Control for Business. It is available in [PowerShell gallery](https://www.powershellgallery.com/packages/WDACConfig/).

<br>

## Application Control Usage Levels

There are many ways you can utilize Application Control features and here they are sorted by the level of restriction and protection they provide; From top (having the least restriction and protection) to bottom (having the most restriction and protection).

1. Use Microsoft recommended driver block rules.
      - **No user action required**; The vulnerable driver blocklist is enabled by default for all devices using HVCI or Memory Integrity.
      - [The built-in driver blocklist is updated with each new major release of Windows, typically 1-2 times per year.](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)

2. Update Microsoft recommended driver block rules outside of the twice a year schedule.
      - The drivers block list itself [is updated more frequently](https://github.com/MicrosoftDocs/windows-itpro-docs/commits/public/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md) than twice a year schedule, [use the WDACConfig Module to setup a scheduled task that keeps the list up-to-date.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Fast-and-Automatic-Microsoft-Recommended-Driver-Block-Rules-updates)
3. Use Microsoft recommended block rules + Recommended driver block rules
      - Use the [WDACConfig Module](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig#new-wdacconfig--getblockrules) to easily deploy the User-Mode Microsoft recommended block rules on your system.
4. Create WDAC policy for **Lightly managed devices**
      - [Microsoft's guide: Create a WDAC policy for lightly managed devices](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/create-appcontrol-policy-for-lightly-managed-devices)
      - [My guide: WDAC for Lightly Managed Devices](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-for-Lightly-Managed-Devices)
5. Use [Smart App Control](https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003)
      - It's just a toggle in Windows Security under App & Browser control. It uses a special kind of WDAC policy that provides more protection than a lightly managed workstation but less protection than a fully managed workstation.
      - It uses both of Microsoft's recommended block rules.
6. Use Smart App Control + [Strict Kernel-Mode WDAC Policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New%E2%80%90KernelModeWDACConfig)
7. Create WDAC policy for **Fully managed devices**
      - The following scenarios provide the highest protection against any threats from any sources when cryptographically signed and deployed and properly configured.
      - [WDAC for Fully managed device - Variant 1](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-for-Fully-Managed-Devices)
      - [WDAC for Fully managed device - Variant 2](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-for-Fully-Managed-Devices--Variant-2)
      - [WDAC for Fully managed device - Variant 3](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-Fully-managed-device---Variant-3)
      - [WDAC for Fully managed device - Variant 4](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-Fully-managed-device---Variant-4)
      - [Microsoft's guide: Create a WDAC policy for fully managed devices](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/create-appcontrol-policy-for-fully-managed-devices)
      - [Microsoft's guide: Create a WDAC policy for fixed-workload devices (reference computer)](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/create-appcontrol-policy-using-reference-computer)
      - [Microsoft's guide: Use audit events to create WDAC policy rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/audit-appcontrol-policies)

<br>

## Methods we can use to create an Application Control policy (WDAC)

* Using [PowerShell cmdlets](https://learn.microsoft.com/en-us/powershell/module/configci)
* Using [WDACConfig PowerShell module](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) - **Recommended**
* Using [WDAC Policy Wizard](https://webapp-wdac-wizard.azurewebsites.net/)

<br>

## Plan for App Control for Business lifecycle policy management

Microsoft provides the [following official document](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/plan-appcontrol-management) to understand the decisions you need to make to establish the processes for managing and maintaining Application Control policies. The rest of them are mentioned below at the **Resources** section.

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

* [Application Control for Windows](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol)
* [Understand App Control for Business policy design decisions](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/understand-appcontrol-policy-design-decisions)
* [Deploying App Control for Business policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/appcontrol-deployment-guide)
* [Use multiple App Control for Business Policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/deploy-multiple-appcontrol-policies)
* [Use audit events to create WDAC policy rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/audit-appcontrol-policies)
* [Merge App Control for Business policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/merge-appcontrol-policies)
* [Understand App Control for Business policy rules and file rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#app-control-for-business-policy-rules)
* [Testing and Debugging AppId Tagging Policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/AppIdTagging/debugging-operational-guide-appid-tagging-policies)
* [Editing existing base and supplemental WDAC policies with the Wizard](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/appcontrol-wizard-editing-policy)
* [Creating a new Supplemental Policy with the Wizard](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/appcontrol-wizard-create-supplemental-policy)
* [App Control for Business example base policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/example-appcontrol-base-policies)
* [Configure the Application Identity service](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/configure-the-application-identity-service)
* [Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)
* [Microsoft recommended block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol)
* [Create a WDAC policy using a reference computer (for fixed-workload devices)](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/create-appcontrol-policy-using-reference-computer)
* [Create a WDAC policy for fully managed devices](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/create-appcontrol-policy-for-fully-managed-devices)
* [Create a WDAC policy for lightly managed devices](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/create-appcontrol-policy-for-lightly-managed-devices)
* [Guidance on Creating WDAC Deny Policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/create-appcontrol-deny-policy)
* [Hypervisor-protected Code Integrity enablement](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-hvci-enablement)

<br>
