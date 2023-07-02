# <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/585563111520600091.png"> Rationale

This document explains the rationale and purpose of this GitHub repository and its content. It describes how it mitigates various threats and how to adjust your expectations for different scenarios and environments. It also offers additional support materials.

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/Windows365.png"> Harden Windows Security PowerShell script

This is a general purpose [script](https://github.com/HotCakeX/Harden-Windows-Security), it's suitable to be used by everyone, as long as your device is not being managed by a domain controller or Azure Active Directory, because those devices are already controlled in different manner and different set of policies are applied to them.

Use Harden Windows Security script to secure your personal device. Your device will be secure against the majority of threats.

Harden Windows Security script uses the same security features built into your device and Windows operating system to fine-tune it towards the highest security and locked-down state.

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/Windows11.png"> Windows Defender Application Control

[Windows Defender Application Control (WDAC) resources](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction) are suitable for both personal users as well as enterprises, businesses and highly secure workstations.

When a proper WDAC policy is deployed on your device, it will be secure against 99.999% of the threats [^1], either from the Internet or physical. It's true that there is no absolute security, but then again there is nothing absolute in the universe either. Everything, even the most fundamental physical laws, are and have been subject to change and conditions.

I've created a PowerShell module called [**WDACConfig**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig), designed with the aim of automating Application and File whitelisting in Windows using Windows Defender Application Control. It's an alternative to [WDAC Wizard](https://webapp-wdac-wizard.azurewebsites.net/) which only has a fraction of the features that WDACConfig module offers.

Full details, guides and videos available [here on GitHub](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) and on [my website.](https://spynetgirl.github.io/WDACConfig%20Module/WDACConfig/)

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/350387930319028225.png"> How do you make the right choice?

For the highest possible security, you should use both the Harden Windows Security script and the WDAC policy on your device if possible.

This will create multiple layers of security; also known as defense in depth. If there will ever be a zero-day vulnerability in one or even some of the security layers, there will still be enough layers left to protect your device. It's impossible to penetrate all of them.

Also, zero-day vulnerabilities are patched quickly, so keeping your device and OS up to date, regardless of what OS you use, is one of the most basic security recommendations and best practices you must follow.

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/Account.png"> Vulnerabilities such as zero-days are disclosed in 3 different ways

1. The vulnerability is disclosed responsibly. It is first communicated with the software developer and company privately so they can have the time to fix and issue updates/patches for the vulnerability before it is disclosed publicly. In this way, people are always safe because all that's needed is to keep your OS and software up to date to receive the latest security patches.

2. The vulnerability is disclosed irresponsibly. It is disclosed publicly, through social media or by creating PoCs (Proof of Concept) so that it can be used and abused by everyone.

3. The vulnerability is abused by malicious actors. It is exploited by threat actors in cyber attacks and privately. These vulnerabilities are either discovered by the threat actors themselves or bought from security researchers who find them first, all of which is illegal and has consequences.

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/StonkUp.png"> What about other Enterprise security ?

<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Enterprise%20Security%20img.png">

<br>

Windows Defender Application Control is not the only security solution for enterprises and businesses; it’s just one piece of the puzzle. There are other necessary ways to secure these devices, such as a wide range of security services that create bulletproof devices for various organizations and use cases:

* [Microsoft Defender for Endpoint](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-endpoint) - Discover and secure endpoint devices across your multiplatform enterprise.

* [Confidential Computing on Azure](https://learn.microsoft.com/en-us/azure/confidential-computing/overview-azure-products) - Protect your highly sensitive data while it's in use

* [Conditional access in Azure AD](https://www.microsoft.com/en-us/security/business/identity-access/azure-active-directory-conditional-access) - Increase protection without compromising productivity

* [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel/) - Scalable, cloud-native solution that provides SIEM, SOAR and more!

* [Key Vault](https://azure.microsoft.com/en-us/products/key-vault/) - Safeguard cryptographic keys and other secrets used by cloud apps and services. This [Azure service uses the best products in the world](https://cpl.thalesgroup.com/partners/microsoft) for the job, such as [Thales HSMs](https://cpl.thalesgroup.com/encryption/hardware-security-modules/network-hsms). More info [available here](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/secure-boot-key-generation-and-signing-using-hsm--example).

* [Microsoft Defender for Cloud](https://azure.microsoft.com/en-us/products/defender-for-cloud) - Protect multicloud and hybrid environments with integrated security from code to cloud

* [Confidential AI](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-ai) - Train your data Privately and Securely on the most advanced AI Super computers

* [Microsoft Defender for Identity](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-for-identity) - Protect your on-premises identities with cloud-powered intelligence.

* [Passwordless authentication options for Azure Active Directory](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-passwordless) - Multifactor and Passwordless Authentication, the most secure and convenient way of authentication.

* [PIM (PAM)](https://www.microsoft.com/en-us/security/business/security-101/what-is-privileged-access-management-pam) - Privileged Access Management

* [PAW](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-devices) - Privileged Access Workstation

* [SAW](https://www.microsoft.com/insidetrack/blog/improving-security-by-protecting-elevated-privilege-accounts-at-microsoft/) - Secure Admin Workstations

* [List of all Azure security services for Enterprises, Businesses etc.](https://learn.microsoft.com/en-us/azure/security/fundamentals/services-technologies)

* [**Moot Security Management**](https://mootinc.com/) - Automate your Security Fabric. All in a few seconds. Create Top Secure PAWs and more with the same products mentioned above, automatically, using 1st party solutions. **Suitable for the most sensitive and important tasks.**

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/673731848341553152.png"> Important Considerations

* Avoid using any 3rd party security solutions when using Harden Windows Security script or Windows Defender Application Control (WDAC). They are neither necessary nor compatible.

* Minimize your exposure to 3rd parties. You don’t need any 3rd party AV or EDR. Use 3rd party software only when there is no 1st party solution.

* Use Virtual machines for any questionable or unsafe software. Use Windows Sandbox or Hyper-V VM. Also consider using Virtual machines or Microsoft Defender Application Guard (MDAG) for browsing on highly secure workstations.

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/surface.gif"> Which device to use ?

Use Microsoft Surface products for the best device and firmware security. They support [secured-core PC specifications](https://www.microsoft.com/en-us/windows/business/windows-11-secured-core-computers), the manufacturing process and platform is trusted and secure.

Make sure to use Surface products that support [Device Firmware Configuration Interface (DFCI)](https://learn.microsoft.com/en-us/mem/autopilot/dfci-management) for extra protection and security. Here is a [list of Surface products](https://learn.microsoft.com/en-us/surface/surface-manage-dfci-guide#dfci-policy-settings-reference-for-surface-devices) that support it.

* [How to use Device Firmware Configuration Interface (DFCI) for Surface Devices with Intune](https://techcommunity.microsoft.com/t5/intune-customer-success/how-to-use-device-firmware-configuration-interface-dfci-for/ba-p/3041293)

* Among other features, devices set up with DFCI can be set that boot from USB device(s) is disabled and there is no way to bypass the chip level security directly, not even CMOS clear can bypass it, because it uses non-volatile memory aka flash storage. It sets BIOS cert authentication, and the private key is behind the cloud edge inside Intune and not even Microsoft support can get that key.

* The list of Surface products supporting DFCI might not get updated quickly in that doc but fear not, this is an active project and all new surface devices have this built in, the docs team might be just a little laggy.

* Microsoft Surface devices use [Project Mu](https://microsoft.github.io/mu/) for the source code of their firmware.

* Surface devices can use certificates instead of password for UEFI. They don't have a reset switch like other devices either. You create and install your own certificate using [Surface Management Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=46703). You can build a config package that has the certificate in it and install it to the firmware, then the package can't be removed or changed without the signing cert authorizing the change, aka, cert auth, or you can just use DFCI as previously mentioned and not have to worry because the packages are signed with MS's private key and there is no PKI that you have to self host.

* Business class Surface devices have dedicated TPM chips.

<br>

> **Warning**
> It is important to be aware of [potential hardware backdoors](https://bios-pw.org/) that may compromise the security of your system. Some common OEMs, such as Compaq, Dell, Fujitsu, Hewlett-Packard (HP), Sony, and Samsung, with OEMs that use unmodified Insyde H20, or Phoenix firmwares utilize algorithms based on device serial numbers for password resets. These algorithms allow for master password removal from the firmware, potentially granting unauthorized access to the system. [Read more](https://docs.mootinc.com/Reference/Architecture/Hardware-Selection/#psm-mode)

<br>

### Protection against BYOVD (Bring Your Own Vulnerable Driver) attacks

Secured core PCs provide the hardware that is capable of protecting against BYOVD attacks. It is your responsibility to turn the features on, those include WDAC (Windows Defender Application Control), ASR (Attack Surface Reduction) rules, Dynamic/static root of trust, firmware that is extensible for revoking drivers.

For drivers not explicitly mentioned in the Microsoft Recommended Driver Block List, which are the more dynamic side of things, ASR is able to protect against BYOVD, ELAM (Early launch anti-malware), part of the MDAV is also able to do that, all because of the ISG (Intelligent Security Graph).

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/Red%20police%20light.gif"> What to do when there is an attack ?

### You can hire any of these teams

- [DART](https://www.microsoft.com/en-us/security/blog/2019/03/25/dart-the-microsoft-cybersecurity-team-we-hope-you-never-meet/) - The Microsoft Detection and Response Team
- [CRSP](https://www.microsoft.com/en-us/security/blog/2021/06/09/crsp-the-emergency-team-fighting-cyber-attacks-beside-customers/) - Global Compromise Recovery Security Practice Team - [including Ransomware](https://learn.microsoft.com/en-us/azure/security/fundamentals/ransomware-detect-respond#road-to-recovery)

<br>

### Color breakdown of security teams in organizations

- 🔴 Red - Pen Testers/White Hat Hackers
- 🔵 Blue - SOC/Data Science/Telemetry Analysis/SIEM Junkies
- 🟢 Green - Fixers, takes input from blue and red and builds the fixes that are needed for identified blind spots (blue) or vulnerability/risk (red)
- 🟡 Yellow - Tooling, SWE to build new stuff for all of the above to operate faster and more effectively

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/david%20star.gif"> For Penetration testing and benchmarking

How to properly perform a pentest and benchmark a system hardened by this repository and make it as close to the real-world scenario as possible:

* Use a physical machine if possible, it should have Windows 11 certified hardware.

* If you can't use a physical machine, use Hyper-V hypervisor. It properly passes the UEFI lock from the host to the guest VM. Your host (aka physical machine) must have Windows 11 certified hardware and meet all the hardware and UEFI security requirements explained in the Readme. VMs however are prone to side channel attacks, so don't use that attack vector in pentests if you want more realistic results.

* First apply the Harden Windows Security script and then use the [WDACConfig module](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) to deploy a suitable WDAC policy.

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/WhiteGhost.gif"> Any questions or suggestions?

Please open a new [issue](https://github.com/HotCakeX/Harden-Windows-Security/issues) or [discussion](https://github.com/HotCakeX/Harden-Windows-Security/discussions) in the repository.

<br>

[^1]: *For Personal users, this is true only when Harden Windows Security script is fully applied too, all categories of it. For other users such as Enterprises, Businesses, Governments, Military etc. this is true only if the rest of the [Enterprise-grade security products mentioned](#-what-about-other-enterprise-security-) are used as well.*

<br>
