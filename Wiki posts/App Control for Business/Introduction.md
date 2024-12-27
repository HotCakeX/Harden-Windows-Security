# What is Application Control for Business?

<div align="center">
<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/Application%20Control%20for%20Business.gif" alt="App Control for Business introduction">
</div>

<br>

Application control is crucial for protecting computer systems in today's threat landscape and offers a distinct advantage over traditional antivirus solutions. Specifically, application control uses tailored access, shifting from a model where all applications are assumed trustworthy to one where applications must earn trust before they can run.

Devices where Application Control policies are deployed on can either be centrally managed via MDM, Intune etc. or they can be home devices, devices that are private and don't belong to any organization, the computer of someone that you want to keep very much safe and secure [so that even the device's owner can't willingly or forcefully compromise themselves,](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Create-and-Deploy-a-Signed-WDAC-Policy-Windows-Defender-Application-Control) the possibilities are endless.

<br>

> [!IMPORTANT]\
> Use [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) for all of your Application Control and Code Integrity management needs. It is scalable, easy to use, enterprise-ready, Azure VM ready and more importantly, it is free, open-source and always will be that way.

<br>

App Control puts the power of security directly in your hands, giving you complete control over your system and the systems you manage. Unlike other solutions that create dependency on other people, App Control eliminates the need to constantly chase and block new malware variants. Once you configure your system and define the apps and files that are permitted to run, everything else is automatically blocked.

**It's time to shift from a reactive approach to a proactive one.**

<br>

## But What Is App Control in Simpler Terms?

By default, you can install any program and run any file on your system. These files can either be signed or unsigned. Signed files come with a certificate that verifies their authenticity, and Windows maintains [a list of trusted certificates](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-trust).

Application Control is a security feature designed to regulate and restrict which programs and files are allowed to run on your system. It eliminates the default open-ended approach where any file can be executed freely. Instead, you define a policy—formatted as an XML file—that specifies which certificates or files are trusted. The system then enforces this policy, permitting only the approved files and programs to run while blocking everything else.

This fundamentally changes the security landscape. Instead of allowing everything by default, the system now demands that programs and files prove their trustworthiness to the policy you created, before execution.

Windows also includes a feature called [Smart App Control](https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003). It acts as a fully automated Application Control system for your device. Being fully automated means it cannot be manually configured or overridden. Smart App Control leverages [the Microsoft Intelligent Security Graph](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph#how-does-wdac-work-with-the-isg), which utilizes AI and advanced technologies to assess whether a file or program is safe to execute.

For those seeking more granular control, [**the AppControl Manager app**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) offers a highly intuitive graphical interface. It allows you to create detailed policies, specifying which files or programs are permitted to run. Policies can be defined using various criteria within the XML format. For example, you can create rules to block all files from running in a particular folder or allow only files signed with a specific certificate, effectively blocking unsigned or differently signed files. AppControl Manager provides a comprehensive suite of tools to manage and configure App Control on your system. With all functionalities built directly into the app, it eliminates the need to switch between different tools or interfaces, making the process seamless and efficient.

App Control is deeply integrated into Windows core and a component known as Code Integrity is mainly responsible for enforcing App Control policies that we create. It runs very early during the system boot, ensuring tight policy enforcement from the very beginning.

<br>

## Application Control Usage Levels

There are many ways you can utilize Application Control features and here they are sorted by the level of restriction and protection they provide; From top (having the least restriction and protection) to bottom (having the most restriction and protection).

1. Use Microsoft recommended driver block rules.
      - **No user action required**; The vulnerable driver blocklist is enabled by default for all devices using HVCI or Memory Integrity.
      - [The built-in driver blocklist is updated with each new major release of Windows, typically 1-2 times per year.](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)

2. Update Microsoft recommended driver block rules outside of the twice a year schedule.
      - The drivers block list itself [is updated more frequently](https://github.com/MicrosoftDocs/windows-itpro-docs/commits/public/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md) than twice a year schedule, [use the AppControl Manager to setup a scheduled task that keeps the list up-to-date.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Fast-and-Automatic-Microsoft-Recommended-Driver-Block-Rules-updates)
3. Use Microsoft recommended block rules + Recommended driver block rules
      - Use the [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to easily deploy the User-Mode Microsoft recommended block rules on your system.
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

## Plan for App Control for Business lifecycle policy management

Microsoft provides the [following official document](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/plan-appcontrol-management) to understand the decisions you need to make to establish the processes for managing and maintaining Application Control policies. The rest of them are mentioned below at the **Resources** section.

<br>

## Documents

* [Application Control for Windows](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol)
* [Understand App Control for Business policy design decisions](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/understand-appcontrol-policy-design-decisions)
* [Deploying App Control for Business policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/appcontrol-deployment-guide)
* [Use multiple App Control for Business Policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/deploy-multiple-appcontrol-policies)
* [Use audit events to create WDAC policy rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/audit-appcontrol-policies)
* [Merge App Control for Business policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/merge-appcontrol-policies)
* [Understand App Control for Business policy rules and file rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#app-control-for-business-policy-rules)
* [Testing and Debugging AppId Tagging Policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/AppIdTagging/debugging-operational-guide-appid-tagging-policies)
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
