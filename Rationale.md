# <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/585563111520600091.png"> Rationale

This document explains the rationale and purpose of this GitHub repository and its content. It describes how it mitigates various threats and how to adjust your expectations for different scenarios and environments.

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/Windows365.png"> Harden Windows Security PowerShell script

This is a general purpose [script](https://github.com/HotCakeX/Harden-Windows-Security), it's suitable to be used by everyone, as long as your device is not being managed by a domain controller or Azure Active Directory, because those devices are already controlled in different manner and different set of policies are applied to them.

Use Harden Windows Security script to secure your personal device. Your device will be secure against the majority of threats.

Harden Windows Security script uses the same security features built into your device and Windows operating system to fine-tune it towards the highest security and locked-down state.

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/Windows11.png"> Windows Defender Application Control

[Windows Defender Application Control (WDAC) resources](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction) are suitable for both personal users as well as enterprises, businesses and highly secure workstations.

When a proper WDAC policy is deployed on your device, it will be secure against 99.999% of the threats [¹](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Rationale.md#-for-personal-users-this-is-true-when-harden-windows-security-script-is-fully-applied-too-all-categories-of-it-for-other-users-such-as-enterprises-businesses-governments-military-etc-this-is-true-only-if-the-rest-of-the-enterprise-grade-security-products-mentioned-are-used-as-well), either from the Internet or physical. It's true that there is no absolute security, but then again there is nothing absolute in the universe either, everything, even the most fundamental physical laws, are and have been subject to change and conditions.

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

* [Key Vault](https://azure.microsoft.com/en-us/products/key-vault/) - Safeguard cryptographic keys and other secrets used by cloud apps and services

* [Microsoft Defender for Cloud](https://azure.microsoft.com/en-us/products/defender-for-cloud) - Protect multicloud and hybrid environments with integrated security from code to cloud

* [Confidential AI](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-ai) - Train your data Privately and Securely on the most advanced AI Super computers

* [Microsoft Defender for Identity](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-for-identity) - Protect your on-premises identities with cloud-powered intelligence.

* [Passwordless authentication options for Azure Active Directory](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-passwordless) - Multifactor and Passwordless Authentication, the most secure and convenient way of authentication.

* [PIM (PAM)](https://www.microsoft.com/en-us/security/business/security-101/what-is-privileged-access-management-pam) - Privileged Access Management

* [PAW](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-devices) - Privileged Access Workstation

* [SAW](https://www.microsoft.com/insidetrack/blog/improving-security-by-protecting-elevated-privilege-accounts-at-microsoft/) - Secure Admin Workstations

* [List of all Azure security serices for Enterprises, Businesses etc.](https://learn.microsoft.com/en-us/azure/security/fundamentals/services-technologies)

* [**Moot Security Management**](https://mootinc.com/) - Automate your Security Fabric. All in a few seconds. Create Top Secure PAWs and more with the same products mentioned above, automatically, using 1st party solutions. **Suitable for the most sensitive and important tasks.**

<br>

## <img width="40" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/673731848341553152.png"> Important Considerations

* Avoid using any 3rd party security solutions when using Harden Windows Security script or Windows Defender Application Control (WDAC). They are neither necessary nor compatible.

* Minimize your exposure to 3rd parties. You don’t need any 3rd party AV or EDR. Use 3rd party software only when there is no 1st party solution.

* Use Virtual machines for any questionable or unsafe software. Use Windows Sandbox or Hyper-V VM. Also consider using Virtual machines or Microsoft Defender Application Guard (MDAG) for browsing on highly secure workstations.

<br>
<br>
<br>
<br>

###### **¹** *For Personal users, this is true only when Harden Windows Security script is fully applied too, all categories of it. For other users such as Enterprises, Businesses, Governments, Military etc. This is true only if the rest of the [Enterprise-grade security products mentioned](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Rationale.md#-what-about-other-enterprise-security-) are used as well.*

<br>
