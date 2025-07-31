# <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/585563111520600091.png" alt="Emoji of a Windows eating moomoo"> Rationale

This document provides the justification and objective of this GitHub repository and its contents. It outlines how it addresses various threats and how to adjust your expectations for different scenarios and environments. It also supplies lots of useful additional resources.

This repository currently has 2 ***main*** products. <img width="30" src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/animebop.gif" alt="head shaking girl">

1. [**The Harden Windows Security module**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden%E2%80%90Windows%E2%80%90Security%E2%80%90Module)
2. [**The AppControl Manager**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager)

<br>

Let's explore each of them in detail below

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/Windows365.png" alt="Windows modern logo"> Harden Windows Security Module

Use the Harden Windows Security module to secure your personal and enterprise devices against the majority of advanced threats. The module is suitable to be used by everyone.

If you are a personal user, you can use the Harden Windows Security to harden your Operation System, remove unnecessary features, apps and so on, check its security score or undo the hardening measures.

If you are an enterprise user or admin, you can use the [provided Intune security policies](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/Intune%20Files) from this repository and apply them from your Intune Portal to all of your workstations using [Microsoft Graph API](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Microsoft-Graph-Explorer-and-API-Basics). You can then use the module to verify the compliance of the workstations against the applied policies and receive a security score.

It uses the same security features built into your device and Windows operating system to fine-tune it towards the highest security and locked-down state. It does not install any outside components and does not increase your attack surface at all.

Let's Take a look at the infographics below:

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Only%20a%20Small%20Portion%20of%20The%20Windows%20OS%20Security%20Apparatus/Smaller%20version.png" alt="Only a Small Portion of The Windows OS Security Apparatus">

> [*More Info About This Map*](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Only-a-Small-Portion-of-The-Windows-OS-Security-Apparatus)

<br>

<br>

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/SecurityBenchmarksComparisonChart.png" alt="Infographic of comparison of security benchmarks"></p>

> [*The reasoning behind the infographic above*](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Comparison-of-security-benchmarks)

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/Windows11.png" alt="Modern Windows 11 logo"> AppControl Manager

[AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) is a secure [open-source](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/AppControl%20Manager) Windows application designed to help you easily configure Application Control in your system. It is suitable for both personal users as well as enterprises, businesses and highly secure workstations.

> [!TIP]\
> If you aren't familiar with what App Control is, [please refer to this article](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction) where it's explained in great detail.

Proper usage of Application Control, when coupled with the Harden Windows Security module's policies, [can provide 99% protection from various threats](https://github.com/HotCakeX/Harden-Windows-Security/wiki/The-Strength-of-Signed-App-Control-Policies), either from the Internet or physical. It's true that there is no absolute security, but then again there is nothing absolute in the universe either. Everything, even the most fundamental physical laws, are and have been subject to change and conditions.

* [Here is a walkthrough video of the AppControl Manager](https://www.youtube.com/watch?v=SzMs13n7elE)

* [Here is the AppControl Manager's landing page on this repository](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager)

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/350387930319028225.png" alt="Microsoft Zune logo"> How Do You Make the Right Choice?

First use the Harden Windows Security Module to apply the hardening measures described [in the Readme](https://github.com/HotCakeX/Harden-Windows-Security#hardening-categories). After applying these hardening measures, your system will be secure against at least ~98% of the threats when you use Standard (non-Privileged) account for everyday work. These threats aren't the usual computer viruses, they are ***motivated nation state threat actors.***

### If you want even more security and control, you have at least 2 more options:

1. you can either use **[Smart App Control](https://learn.microsoft.com/windows/apps/develop/smart-app-control/overview)**, which deploys an automatic and AI based App Control policy that uses [Intelligent Security Graph](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph) to authorize safe and reputable applications and files and blocks unknown and malicious files.

2. Use [AppControl Manager](https://spynetgirl.github.io/AppControl%20Manager/AppControl%20Manager/) to deploy an App Control policy and have even more control over the operation of the Windows Application Control.

These methods will create multiple layers of security; also known as defense in depth. Additionally, you can create [**Kernel-level Zero-Trust strategy**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection) for your system.

If there will ever be a zero-day vulnerability in one or even some of the security layers at the same time, there will still be enough layers left to protect your device. It's practically impossible to penetrate all of them at once.

Also, zero-day vulnerabilities are patched quickly, so keeping your device and OS up to date, regardless of what OS you use, is one of the most basic security recommendations and best practices you must follow.

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/Account.png" alt="Microsoft Identity logo"> Vulnerabilities Such as Zero-Days Are Disclosed in 3 Different Ways

1. The vulnerability is disclosed responsibly. It is first communicated privately with the software vendor/developer so they can have the time to fix and issue updates/patches for the vulnerability before it is disclosed publicly. In this way, people are always safe because all that's needed is to keep your OS and software up to date to receive the latest security patches.

2. The vulnerability is disclosed irresponsibly. It is disclosed publicly, through social media or by creating PoCs (Proof of Concept) so that it can be used and abused by everyone.

3. The vulnerability is abused by malicious actors. It is exploited by threat actors in cyber attacks and privately. These vulnerabilities are either discovered by the threat actors themselves or bought from security researchers who find them first, all of which is illegal and has consequences.

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/StonkUp.png" alt="Stonks up"> What About More Advanced Security at Scale ?

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/534534.png" width="650" alt="AI generated image of a girl"></p>

<br>

To achieve the Highest level of Security **at Scale** for Businesses, Enterprises and Military scenarios, you can use the following services to create impenetrable devices and environments.

> [!IMPORTANT]\
> The following services must be used **in addition** to the measures already talked about in this repository, such as proper Application Control policies and the security measures that the Harden Windows Security module applies. They are not a replacement for them.
>
> As an individual user you can still utilize these features and services, they add an additional layer of protection to your security stack.

* [Microsoft Defender for Endpoint](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-endpoint) - Discover and secure endpoint devices across your multiplatform enterprise.

* [Microsoft Security Copilot](https://www.microsoft.com/en-us/security/business/ai-machine-learning/microsoft-copilot-security) - Build a defense [so automated](https://learn.microsoft.com/security-copilot/microsoft-security-copilot) that even your intern becomes a cybersecurity expert.

* [Confidential Computing on Azure](https://learn.microsoft.com/azure/confidential-computing/overview-azure-products) - Protect your highly sensitive data while it's in use

* [Confidential AI](https://learn.microsoft.com/azure/confidential-computing/confidential-ai) - Train your data Privately and Securely on the most advanced AI Super computers

* [Microsoft Entra conditional access](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-conditional-access) - Increase protection without compromising productivity

* [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel/) - Scalable, cloud-native solution that provides SIEM, SOAR and more!

* [Key Vault](https://azure.microsoft.com/en-us/products/key-vault/) - Safeguard cryptographic keys and other secrets used by cloud apps and services. This [Azure service uses the best products in the world](https://cpl.thalesgroup.com/partners/microsoft) for the job, such as [Thales HSMs](https://cpl.thalesgroup.com/encryption/hardware-security-modules/network-hsms). More info [available here](https://learn.microsoft.com/windows-hardware/manufacture/desktop/secure-boot-key-generation-and-signing-using-hsm--example).

* [Microsoft Defender for Cloud](https://azure.microsoft.com/en-us/products/defender-for-cloud) - Protect multicloud and hybrid environments with integrated security from code to cloud

* [Microsoft Defender for Cloud Apps]() - Modernize how you secure your apps, protect your data, and elevate your app posture with software as a service (SaaS) security.

* [Microsoft Defender for Identity](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-for-identity) - Protect your on-premises identities with cloud-powered intelligence.

* [Passwordless authentication options for Azure Active Directory](https://learn.microsoft.com/azure/active-directory/authentication/concept-authentication-passwordless) - Multifactor and Passwordless Authentication, the most secure and convenient way of authentication.

* [PIM (PAM)](https://www.microsoft.com/en-us/security/business/security-101/what-is-privileged-access-management-pam) - Privileged Access Management

* [PAW](https://learn.microsoft.com/security/privileged-access-workstations/privileged-access-devices) - Privileged Access Workstation

* [SAW](https://www.microsoft.com/insidetrack/blog/improving-security-by-protecting-elevated-privilege-accounts-at-microsoft/) - Secure Admin Workstations

* [List of all Azure security services for Enterprises, Businesses etc.](https://learn.microsoft.com/azure/security/fundamentals/services-technologies)

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/673731848341553152.png" alt="head patting"> Important Considerations

* Avoid using any 3rd party security solutions when using Harden Windows Security module or App Control for Business. 3rd party solutions are weak, incompatible and unnecessary, **they also increase your attack surface**.

* Use Virtual machines for any questionable or unsafe software. Use [Windows Sandbox or Hyper-V VM](https://github.com/HotCakeX/Privacy-Anonymity-Compartmentalization). Also consider using Virtual machines or Microsoft Defender Application Guard (MDAG) for browsing on highly secure workstations.

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/surface.gif" alt="Surface device gif"> [Which Device to Use ?](#-which-device-to-use-)

Use Microsoft Surface products for the best device and firmware security. They support [secured-core PC specifications](https://www.microsoft.com/en-us/windows/business/windows-11-secured-core-computers), the manufacturing process and platform is trusted and secure.

Make sure to use Surface products that support [Device Firmware Configuration Interface (DFCI)](https://learn.microsoft.com/mem/autopilot/dfci-management) for extra protection and security. Here is a [list of Surface products](https://learn.microsoft.com/surface/surface-manage-dfci-guide#dfci-policy-settings-reference-for-surface-devices) that support it.

* [How to use Device Firmware Configuration Interface (DFCI) for Surface Devices with Intune](https://techcommunity.microsoft.com/t5/intune-customer-success/how-to-use-device-firmware-configuration-interface-dfci-for/ba-p/3041293)

* Among other features, devices set up with DFCI can be set that boot from USB device(s) is disabled and there is no way to bypass the chip level security directly, not even CMOS clear can bypass it, because it uses non-volatile memory aka flash storage. It sets BIOS cert authentication, and the private key is behind the cloud edge inside Intune and not even Microsoft support can get that key.

* The list of Surface products supporting DFCI might not get updated quickly in that doc but fear not, this is an active project and all new surface devices have this built in, the docs team might be just a little laggy.

* Microsoft Surface devices use [Project Mu](https://microsoft.github.io/mu/) for the source code of their firmware.

* Surface devices can use certificates instead of password for UEFI. They don't have a reset switch like other devices either. You create and install your own certificate using [Surface Management Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=46703). You can build a config package that has the certificate in it and install it to the firmware, then the package can't be removed or changed without the signing cert authorizing the change, aka, cert auth, or you can just use DFCI as previously mentioned and not have to worry because the packages are signed with MS's private key and there is no PKI that you have to self host.

* Business class Surface devices have dedicated TPM chips.

* Check out [the Device Guard category](https://github.com/HotCakeX/Harden-Windows-Security?tab=readme-ov-file#device-guard) about Secured-Core specifications.

* Pluton security chip is **not** a requirement for Secured-Core certification.

* Pluton security chip is included in [Qualcomm Snapdragon ARM CPUs](https://www.qualcomm.com/products/mobile/snapdragon/pcs-and-tablets/snapdragon-x-elite), [AMD](https://blogs.windows.com/windowsexperience/2024/04/16/amds-commercial-ai-pc-portfolio-integrates-microsoft-pluton-includes-microsoft-copilot/) and [Intel CPUs](https://www.theverge.com/2024/6/3/24169115/intel-lunar-lake-architecture-platform-feature-reveal).

* [Copilot+](https://www.microsoft.com/en-us/windows/copilot-plus-pcs) PCs are among [the most secure consumer grade devices](https://blogs.windows.com/windowsexperience/2024/09/27/update-on-recall-security-and-privacy-architecture/). They are secured-core and incorporate the Pluton security chip.

<br>

> [!IMPORTANT]\
> <img width="30" src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/blue.gif" alt="Attention gif"> It is important to be aware of [potential hardware backdoors](https://bios-pw.org/) that may compromise the security of your system. Some common OEMs, such as Compaq, Dell, Fujitsu, Hewlett-Packard (HP), Sony, and Samsung, with OEMs that use unmodified Insyde H20, or Phoenix firmwares utilize algorithms based on device serial numbers for password resets. These algorithms allow for master password removal from the firmware, potentially granting unauthorized access to the system.

<br>

> [!NOTE]\
> <img width="30" src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/diamond-7.gif" alt="rotating diamond gif"> When buying 3rd party devices, make sure they have the [Pluton](https://www.microsoft.com/en-us/security/blog/2020/11/17/meet-the-microsoft-pluton-processor-the-security-chip-designed-for-the-future-of-windows-pcs/) security chip, it [addresses security needs](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/defending-against-ransomware-with-microsoft-defender-for/ba-p/3243941) like booting an operating system securely **even against firmware threats** and storing sensitive data safely **even against physical attacks**.

<br>

### <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/9935-catkeyboard.gif" alt="BYOVD device gif animated"> [Protection against BYOVD (Bring Your Own Vulnerable Driver) attacks](#-protection-against-byovd-bring-your-own-vulnerable-driver-attacks)

* Secured core PCs provide the hardware that is capable of protecting against BYOVD attacks. It is your responsibility to turn the features on, those include App Control for Business, ASR (Attack Surface Reduction) rules, Dynamic/static root of trust and [firmware](https://learn.microsoft.com/windows-hardware/drivers/bringup/firmware-attack-surface-reduction) that is extensible for revoking drivers. They are specially useful for drivers not explicitly mentioned in the [Microsoft Recommended Driver Block List](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules), which are the more dynamic side of things.

* Use [Strict Kernel-mode App Control policy for complete BYOVD protection](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection)

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/Red%20police%20light.gif" alt="Alert gif for what to do when under attack"> [What to Do When There Is an Attack ?](#-what-to-do-when-there-is-an-attack-)

You should have an existing [***Unified Contract***](https://www.microsoft.com/en-us/unifiedsupport/overview) with Microsoft ([formerly](https://www.microsoft.com/en-us/unifiedsupport/premier) known as [Premier Support](https://www.microsoft.com/en-us/premier-support-end-of-sale)). Microsoft offers a wide range of services and teams to help you recover from a cyber attack such as:

- GHOST: Global Hunting, Oversight and Strategic Triage
- [DART](https://www.microsoft.com/en-us/security/blog/2019/03/25/dart-the-microsoft-cybersecurity-team-we-hope-you-never-meet/) - The Microsoft Detection and Response Team
- [CRSP](https://www.microsoft.com/en-us/security/blog/2021/06/09/crsp-the-emergency-team-fighting-cyber-attacks-beside-customers/) - Global Compromise Recovery Security Practice Team - [including Ransomware](https://learn.microsoft.com/azure/security/fundamentals/ransomware-detect-respond#road-to-recovery)

After you've got hacked, you should request them by contacting your Customer Success Account Manager and telling them you need the help of one of these teams.

<br>

> [!TIP]\
> When getting cyber security insurance for your company or organization, make sure to get one that covers the cost of hiring Microsoft's **elite** teams such as **GHOST/DART**, i.e. those Microsoft teams will be in-network for your insurance.

<br>

### Color breakdown of security teams in organizations

- 🔴 Red - Pen Testers/White Hat Hackers
- 🔵 Blue - SOC/Data Science/Telemetry Analysis/SIEM Junkies
- 🟢 Green - Fixers, takes input from blue and red and builds the fixes that are needed for identified blind spots (blue) or vulnerability/risk (red)
- 🟡 Yellow - Tooling, SWE to build new stuff for all of the above to operate faster and more effectively

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/david%20star.gif" alt="icon for For Penetration testing and benchmarking section"> [For Penetration testing and benchmarking](#-for-penetration-testing-and-benchmarking)

How to properly perform a pentest and benchmark a system hardened by this repository and make it as close to a real-world scenario as possible:

1. Use a physical machine if possible, it should have Windows 11 certified hardware, [Standard user account](https://learn.microsoft.com/windows-server/remote/multipoint-services/create-a-standard-user-account).
   * If you can't use a physical machine, use Hyper-V hypervisor. Your host (aka physical machine) must have Windows 11 certified hardware and meet all the hardware and UEFI security requirements explained in the Readme. VMs however are prone to side channel attacks, so don't use that attack vector in pentests if you want more realistic results.

2. First apply the [Harden Windows Security module](https://github.com/HotCakeX/Harden-Windows-Security) *(All categories of it)* and then use the [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to deploy a suitable [Signed](https://github.com/HotCakeX/Harden-Windows-Security/wiki/The-Strength-of-Signed-App-Control-Policies) App Control policy.

<br>

> [!IMPORTANT]\
> Always Pay attention to the [Microsoft Security Servicing Criteria for Windows](https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria), specially the Security boundaries. There is no security boundary between Administrator to Kernel.
>
> Some penetration testers overlook this fact, assuming it is a vulnerability that they can perform administrative tasks such as disabling security features as Administrator. This is an expected behavior. Administrators have the power to control the security of a device and can disable security features at their discretion. This is why you need to use a Standard user account when performing a realistic penetration test.
>
> Another aspect to consider is the ambiguity in the word "Admin". There are at least two distinct types of Admins: Local Admin and Cloud Admin. For instance, when you are penetration testing a system that leverages enterprise cloud security solution such as Microsoft Defender for Endpoint (MDE), Admin access should be regarded as Cloud Admin since those devices use Microsoft Entra ID and lack Local Admin. In this situation, Cloud Admin can effortlessly disable security features as expected, rendering a pentest using Local Admin access utterly pointless. Conversely, when pentesting a system that only relies on personal security features such as Microsoft Defender, then Admin should be treated as Local Admin. In this case, the Admin can also disable any security feature for the same reasons stated above.
>
> Of course, Microsoft employs additional security measures such as Protected Process Light (PPL) for Defense in Depth strategies, but they do not alter the facts stated above. **The goal is to always hope for the best, plan for the worst.**

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/WhiteGhost.gif" alt="Ghost emoji"> [Any questions or suggestions?](#-any-questions-or-suggestions)

Please open a new [issue](https://github.com/HotCakeX/Harden-Windows-Security/issues) or [discussion](https://github.com/HotCakeX/Harden-Windows-Security/discussions) in the repository.

<br>
