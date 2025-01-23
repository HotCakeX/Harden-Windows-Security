# What is Application Control for Business?

<div align="center">
<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/Application%20Control%20for%20Business.gif" alt="App Control for Business introduction">
</div>

<br>

Application Control is crucial for protecting computer systems in today's threat landscape and offers a distinct advantage over traditional antivirus solutions. Specifically, application control uses tailored access, shifting from a model where all applications are assumed trustworthy to one where applications must earn trust before they can run.

Devices where Application Control policies are deployed on can either be centrally managed via MDM, Intune etc. or they can be home devices, devices that are private and don't belong to any organization, the computer of someone that you want to keep very much safe and secure [so that even the device's owner can't willingly or forcefully compromise themselves,](https://github.com/HotCakeX/Harden-Windows-Security/wiki/The-Strength-of-Signed-App-Control-Policies) the possibilities are endless.

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

**App Control operates on the principle of trust enforcement rather than threat detection.** It does not distinguish between outright malware and files signed with multiple legitimate certificates—if a file is not explicitly permitted by your locally defined policy, it is blocked from execution. This proactive approach is particularly effective against zero-day threats that may evade traditional antivirus, signature-based, or other detection mechanisms. Waiting even a short period for new threats to be detected, analyzed, and countered with updated signatures can be too late.

By preventing the execution of any unauthorized files or programs, App Control imposes significant barriers to attackers, potentially deterring them from even attempting to breach your system. For instance, even if an attacker manages to deceive you into downloading seemingly legitimate software or file to exploit vulnerabilities or infect your device (such as through social engineering, phishing and other techniques), it will be denied execution unless it adheres to the locally defined policy(ies) on your system.

<br>

> [!TIP]\
> [App Control Frequently Asked Questions (FAQs)](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Application-Control-(WDAC)-Frequently-Asked-Questions-(FAQs))

<br>

## What Are The Different Ways to Use App Control in Windows?

Windows includes a feature called [Smart App Control](https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003). It acts as a fully automated Application Control system for your device. Being fully automated means it cannot be manually configured or overridden. Smart App Control leverages [the Microsoft Intelligent Security Graph](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph#how-does-wdac-work-with-the-isg), which utilizes AI and advanced technologies to assess whether a file or program is safe to execute.

For those seeking more granular control, [**the AppControl Manager**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) offers a highly intuitive graphical interface. It allows you to create detailed policies, specifying which files or programs are permitted to run. Policies can be defined using various criteria within the XML format. For example, you can create rules to block all files from running in a particular folder or allow only files signed with a specific certificate, effectively blocking unsigned or differently signed files. AppControl Manager provides a comprehensive suite of tools to manage and configure App Control on your system. With all functionalities built directly into the app, it eliminates the need to switch between different tools or interfaces, making the process seamless and efficient.

App Control is deeply integrated into Windows core and a component known as Code Integrity is mainly responsible for enforcing App Control policies that we create. It runs very early during the system boot, ensuring tight policy enforcement from the very beginning.

<br>

## App Control Concepts and Keywords

### Base Policy

App Control policies come in different types, one of which is the base policy. A base policy is a standalone policy that can be deployed independently, without relying on other policies. It can contain both allow and deny rules. Multiple base policies can coexist on the same system.

<br>

### Supplemental policy

Supplemental policies depend on base policies and cannot function without an associated base policy. The only purpose of a supplemental policy is to add more allow rules to a base policy, thereby expanding its scope.

<br>

### AppID Tagging Policy

This type of policy does not allow or block any files. Instead, it programmatically tags files and programs based on the rules defined within it. Other programs can then detect these tags and treat the tagged programs differently.

<br>

### Table: Policy Types and Their Capabilities

| Features                                                                    | Base Policy | Supplemental Policy | AppID Tagging Policy |
|-----------------------------------------------------------------------------|-------------|---------------------|----------------------|
| Can be Standalone                                                           | Yes         | No                  | Yes                  |
| Can Have Deny Rules                                                         | Yes         | No                  | No                   |
| Applies to User and Kernel Mode Files?                                      | Yes         | Yes                 | No - User Mode only                   |
| Can be Signed                                                               | Yes         | Yes                 | Yes                  |
| Can the Signed Version be Removed Without Access to the Certificate?          | No          | Yes                 | No                   |
| Can be Used for Auditing                                                    | Yes         | No                  | No                   |

<br>

### Policy ID

All policy types are assigned a unique ID in GUID format. No two policies with the same ID can exist on the same system. Attempting to deploy a policy with a duplicate ID will overwrite the existing policy.

<br>

### Deployment

The terms deploy or deployment refer to the process of installing policies on the system. Deployment involves:

* Copying the policy to specific system locations.

* Refreshing the system's policy repository to recognize and enforce the new policies.

<br>

### Audit Mode

Audit Mode is a feature available for base policies. When deployed in audit mode, the policy does not block any files. Instead, it generates event logs for any files that would have been blocked if the policy were deployed in enforced mode.

<br>

### Enforced Mode

If a policy is not deployed in audit mode, it is considered to be in enforced mode. In this mode:

* The policy enforces its rules by allowing specified files and programs.

* All other files and programs are blocked.

<br>

## App Control Guides

* [How To Generate Audit Logs via App Control Policies](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-To-Generate-Audit-Logs-via-App-Control-Policies)

* [How To Create an App Control Supplemental Policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-To-Create-an-App-Control-Supplemental-Policy)

* [The Strength of Signed App Control Policies](https://github.com/HotCakeX/Harden-Windows-Security/wiki/The-Strength-of-Signed-App-Control-Policies)

* [How To Upload App Control Policies To Intune Using AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-To-Upload-App-Control-Policies-To-Intune-Using-AppControl-Manager)

* [How To Create and Maintain Strict Kernel‐Mode App Control Policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-To-Create-and-Maintain-Strict-Kernel%E2%80%90Mode-App-Control-Policy)

* [How to Create an App Control Deny Policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Create-an-App-Control-Deny-Policy)

* [Fast and Automatic Microsoft Recommended Driver Block Rules updates](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Fast-and-Automatic-Microsoft-Recommended-Driver-Block-Rules-updates)

* [App Control Notes](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes)

* [How to use Windows Server to Create App Control Code Signing Certificate](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Create-and-Deploy-a-Signed-WDAC-Policy-Windows-Defender-Application-Control)

* [App Control policy for BYOVD Kernel mode only protection](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection)

* [EKUs in App Control for Business Policies](https://github.com/HotCakeX/Harden-Windows-Security/wiki/EKUs-in-WDAC,-App-Control-for-Business,-Policies)

* [App Control Rule Levels Comparison and Guide](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide)

* [Script Enforcement and PowerShell Constrained Language Mode in App Control Policies](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Script-Enforcement-and-PowerShell-Constrained-Language-Mode-in-WDAC-App-Control-Policies)

* [How to Use Microsoft Defender for Endpoint Advanced Hunting With App Control](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Use-Microsoft-Defender-for-Endpoint-Advanced-Hunting-With-WDAC-App-Control)

<br>

## Application Control Usage Levels

There are many ways you can utilize Application Control features and here they are sorted by the level of restriction and protection they provide.

| Protection Level |Type | Description |
|:----------------:|:---:|:-----------:|
|⭐| Microsoft recommended driver block rules| The vulnerable driver blocklist is enabled by default for all devices using HVCI or Memory Integrity. [The built-in driver blocklist is updated with each new major release of Windows, typically 1-2 times per year.](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) |
|⭐⭐|Fast Microsoft recommended driver block rules Update| The drivers block list itself [is updated more frequently](https://github.com/MicrosoftDocs/windows-itpro-docs/commits/public/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md) than twice a year schedule, [use the AppControl Manager to setup a scheduled task that keeps the list up-to-date.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Fast-and-Automatic-Microsoft-Recommended-Driver-Block-Rules-updates) |
|⭐⭐⭐| Microsoft recommended driver + User Mode block rules | Use the [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to easily deploy the User-Mode Microsoft recommended block rules on your system in addition to the drivers block rules that only enforces Kernel-mode drivers.|
|⭐⭐⭐⭐| Block Rules + App Control policy using ISG | In Addition to using the block rules, deploy an App Control policy that uses the [ISG](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph#how-does-wdac-work-with-the-isg) for automated reputation-based authorization. |
|⭐⭐⭐⭐⭐|Smart App Control| It's just a toggle in Windows Security under App & Browser control. [Smart App Control](https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003) uses a special kind of App Control policy that provides more protection than the previous type because of how it is crafted to handle reputable apps. It uses both of Microsoft's recommended block rules by default.|
|⭐⭐⭐⭐⭐⭐| Smart App Control + Strict Kernel-Mode App Control Policy | The [special strict kernel-mode policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection) augments the Smart App Control by enforcing tight restrictions and control over anything that wants access the OS Kernel.|
|⭐⭐⭐⭐⭐⭐⭐| Block Rules + Allow Microsoft policy (unsigned)| Block rules must always be deployed along with other App Control policies. The Allow Microsoft policy will enforce both User + Kernel mode files.|
|⭐⭐⭐⭐⭐⭐⭐⭐| Block Rules + Allow Microsoft policy (Signed)| Signing the Allow Microsoft policy along with the block rules will make them tamper proof even against system administrators.|
|⭐⭐⭐⭐⭐⭐⭐⭐⭐| Block Rules + Default Windows (unsigned)| The Default Windows template offers more control and restrictions than the Allow Microsoft template.|
|⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐| Block Rules + Default Windows (Signed)|  Signing the Default Windows policy along with the block rules will make them tamper proof even against system administrators.|
|⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐ | Block Rules + Default Windows + Strict Kernel-Mode policy (All Policies Signed) | the Default Windows policy + Strict Kernel-mode policy + block rules and all of them signed provides the highest level of protection. |

<br>

## The Philosophy of Application Control

Traditional security paradigms operate reactively, predicated on the notion of learning from failure—be it a breach, malware behavior, or an exploit. Antivirus solutions, EDRs, and even advanced Security Operations Centers are, at their core, systems that require evidence of failure or malicious activity to evolve their defenses. This dependence on post-incident learning creates a dangerous temporal gap between detection and mitigation, a gap that adversaries exploit to maximum effect. But what if the entire paradigm of learning from failure is rendered obsolete? What if the very need for mistakes to act as catalysts for growth is removed?

App Control dares to challenge this model, offering a proactive, deterministic approach to security. Instead of waiting for an adversary to breach a boundary, it operates on the principle of preemptive denial. By enforcing a meticulously curated policy of trust, it shifts the locus of control back to the defender. No unauthorized file or program—no matter how cleverly disguised or insidiously crafted—can execute without explicit consent. In this model, the defender doesn't merely learn from the adversary's moves; they nullify the need to learn by negating the adversary's opportunity to act.

This approach transcends technical effectiveness and ventures into a broader philosophical question: must growth and innovation always be rooted in failure? In the realm of cybersecurity, App Control suggests an alternative path—a future where systems are designed to anticipate and preempt the very conditions that lead to mistakes. It embodies the philosophy that prevention is not merely better than cure; it is the evolution of cure itself.

Why wait for failure to inform your defenses when you can architect systems that proactively uphold their integrity? Why depend on the adversary's initiative to dictate your response when you can reclaim the initiative entirely? What if failure is not an option and cannot be afforded under any circumstances?

<br>

## Microsoft Learn Documents Related to Application Control

* [Application Control for Windows](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol)
* [Understand App Control for Business policy design decisions](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/understand-appcontrol-policy-design-decisions)
* [Deploying App Control for Business policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/appcontrol-deployment-guide)
* [Use multiple App Control for Business Policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/deploy-multiple-appcontrol-policies)
* [Use audit events to create App Control policy rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/audit-appcontrol-policies)
* [Understand App Control for Business policy rules and file rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#app-control-for-business-policy-rules)
* [Testing and Debugging AppId Tagging Policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/AppIdTagging/debugging-operational-guide-appid-tagging-policies)
* [App Control for Business example base policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/example-appcontrol-base-policies)
* [Configure the Application Identity service](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/configure-the-application-identity-service)
* [Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)
* [Microsoft recommended block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol)
* [Create an App Control policy using a reference computer](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/create-appcontrol-policy-using-reference-computer)
* [Create an App Control policy for fully managed devices](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/create-appcontrol-policy-for-fully-managed-devices)
* [Create an App Control policy for lightly managed devices](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/create-appcontrol-policy-for-lightly-managed-devices)
* [Guidance on Creating App Control Deny Policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/create-appcontrol-deny-policy)
* [Hypervisor-protected Code Integrity enablement](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-hvci-enablement)

<br>
