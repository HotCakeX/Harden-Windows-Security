# Only a Small Portion of The Windows OS Security Apparatus

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Only%20a%20Small%20Portion%20of%20The%20Windows%20OS%20Security%20Apparatus/Smaller%20version.png" alt="Only a Small Portion of The Windows OS Security Apparatus">

<br>

* [**Full Resolution Available Here**](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Only%20a%20Small%20Portion%20of%20The%20Windows%20OS%20Security%20Apparatus/Full%20Res.png) - Perfect For Desktop Background
* [**SVG Vectorized Version Available Here**](https://raw.githubusercontent.com/HotCakeX/.github/73d020c821f5c91e2cad877aea91601a183ebcc4/Pictures/Only%20a%20Small%20Portion%20of%20The%20Windows%20OS%20Security%20Apparatus/Full%20Res.svg)

<br>

> [!Tip]\
> Many of the features mentioned in the map above can be automatically deployed and configured via the [Harden Windows Security repository's](https://github.com/HotCakeX/Harden-Windows-Security) offerings.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## SUPERIORITY

### Intelligent Security Graph (ISG)

This cloud-based AI is based on trillions of signals collected from Windows endpoints and other data sources, and processed every 24 hours. As a result, the decision from the cloud can change.

* [Read More](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph)

<br>

### No 0-day/Unknown File Allowed (ASR)

This rule blocks untrusted or unknown executable files such as .exe, .dll, or .scr, from launching that can be risky, as it might not be initially clear if the files are malicious.

* [Read More](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-executable-files-from-running-unless-they-meet-a-prevalence-age-or-trusted-list-criterion)

<br>

### Rigorous Custom Exploit Protections

Exploit protection helps protect devices from malware that uses exploits to spread and infect other devices. Mitigation can be applied to either the operating system or to an individual app.

* [Read More](https://learn.microsoft.com/en-us/defender-endpoint/evaluate-exploit-protection)

* [Read More](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Harden-Windows-Security%20Module/Main%20files/Resources/ProcessMitigations.csv)

<br>

### Network Protection

Network protection helps protect devices from Internet-based events. Network protection is an attack surface reduction capability. It helps prevent employees from accessing dangerous domains through applications. Domains that host phishing scams, exploits, and other malicious content on the Internet are considered dangerous.

* [Read More](https://learn.microsoft.com/en-us/defender-endpoint/network-protection)

<br>

### Cloud Protection

Next-generation technologies in Microsoft Defender Antivirus provide near-instant, automated protection against new and emerging threats. To identify new threats dynamically, next-generation technologies work with large sets of interconnected data in the Microsoft Intelligent Security Graph and powerful artificial intelligence (AI) systems driven by advanced machine learning models. Cloud protection works together with Microsoft Defender Antivirus to deliver accurate, real-time, and intelligent protection.

* [Read More](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-defender-antivirus)

<br>

### Cloud-Based Remote Detonation And Analysis

Advanced cloud-based protection is provided for cases when Microsoft Defender Antivirus running on the endpoint needs more intelligence to verify the intent of a suspicious file.

After files are submitted to cloud protection, the submitted files can be scanned, **detonated**, and processed through big data analysis machine-learning models to reach a verdict.

* [Read More](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission?view=o365-worldwide#how-cloud-protection-and-sample-submission-work-together)

<br>

### Block At First Sight

Block at first sight is a threat protection feature of next-generation protection that detects new malware and blocks it within seconds.

* [Read More](https://learn.microsoft.com/en-us/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus)

<br>

### Intel Threat Detection Technology (TDT)

Intel TDT is a detection approach that can augment traditional file-based or behavior-based detection. This technology integration focuses on the CPU execution patterns that are characteristic of ransomware attacks. Intel TDT is available in a broad range of Intel hardware over multiple generations and will be available for consumers through Microsoft Defender Antivirus.

* [Read More](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/defending-against-ransomware-with-microsoft-defender-for/ba-p/3243941)

* [Read More](https://www.intel.com/content/www/us/en/architecture-and-technology/vpro/hardware-shield/threat-detection-technology.html)

<br>

### Remote Encryption Protection

Remote Encryption Protection in Microsoft Defender Antivirus detects and blocks attempts to replace local files with encrypted versions from another device.

* [Read More](https://learn.microsoft.com/en-us/windows/client-management/mdm/defender-csp#configurationbehavioralnetworkblocksremoteencryptionprotectionremoteencryptionprotectionconfiguredstate)

<br>

### Brute Force Protection

Brute-Force Protection in Microsoft Defender Antivirus detects and blocks attempts to forcibly sign in and initiate sessions.

* [Read More](https://learn.microsoft.com/en-us/windows/client-management/mdm/defender-csp#configurationbehavioralnetworkblocksbruteforceprotectionbruteforceprotectionconfiguredstate)

<br>

### Windows Updates Installed Within 24 Hours Of Release

Windows updates are extremely important. They always should be installed as fast as possible to stay secure and if a reboot is required, it should be done immediately. Threat actors can weaponize publicly disclosed vulnerabilities the same day their POC (Proof-Of-Concept) is released.

* [Read More](https://www.microsoft.com/en-us/security/blog/2023/04/18/nation-state-threat-actor-mint-sandstorm-refines-tradecraft-to-attack-high-value-targets/)

* [Read More](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update#configuredeadlinegraceperiod)

<br>

### Microsoft Defender Updates Installed Every 3 Hours

Regularly updating Microsoft Defender Antivirus is crucial for maintaining robust security on your Windows OS. These updates ensure that your system has the latest security intelligence, which is vital for identifying and mitigating the most recent threats. Cyber threats evolve rapidly, and outdated antivirus signatures leave your system vulnerable to new malware, viruses, and other security risks.

* [Read More](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#signatureupdateinterval)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## ULTIMATUM

### App Control for Business (WDAC)

Application control is a crucial line of defense for protecting computer systems given today's threat landscape, and it has an inherent advantage over traditional antivirus solutions. Specifically, application control moves away from an application trust model where all applications are assumed trustworthy to one where applications must earn trust in order to run.

* [Read More](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction)

* [**AppControl Manager**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager)

<br>

### Complete BYOVD Protection

This scenario involves removing the trust to any Kernel mode driver, whether they are vulnerable or not. It does not affect User-mode binaries or drivers. Any 3rd party software/hardware Kernel mode driver will need to be explicitly allowed. This scenario protects against all BYOVD scenarios and much more.

* [Read More](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection)

<br>

### Application Cross-Dependency Usage Control

Implements Sandboxing-like restrictions around the program's dependencies so that only the main executable(s) of the program can use its dependencies and any other executable will be blocked from using them.

* [Watch](https://youtu.be/cp7TaTNPZE0?si=2rhBTGdO76A5vQS6)

<br>

### Controlled Folder Access

Controlled folder access helps you protect valuable data from malicious apps and threats, such as ransomware.

Controlled folder access applies to many system folders and default locations, including folders such as Documents, Pictures, and Movies. You can add other folders to be protected, but you cannot remove the default folders in the default list.

* [Read More](https://learn.microsoft.com/en-us/defender-endpoint/customize-controlled-folders)

<br>

### Smart App Control

Smart App Control is a new app execution control feature that combines Microsoft’s app intelligence services and Windows' code integrity features to protect users from untrusted or potentially dangerous code. Smart App Control selectively allows apps and binaries to run only if they're likely to be safe. Microsoft's app intelligence services provide safety predictions for many popular apps. If the app intelligence service is unable to make a prediction, then Smart App Control will still allow an app to run if it is signed with a certificate issued by a certificate authority (CA) within the Trusted Root Program.

* [Read More](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/overview)

<br>

### Hyper-V & Windows Sandbox (Untrusted Software Usage)

Hyper-V is the most secure and one of the best, if not the best Type-1 hypervisor. It's available in Windows and can virtualize an OS.

Windows Sandbox provides a lightweight desktop environment to safely run applications in isolation. Software installed inside the Windows Sandbox environment remains "sandboxed" and runs separately from the host machine.

* [Read More](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview)

* [Read More](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v)

<br>

### Windows Defender Firewall (Rule Based)

Windows Firewall is a **Stateful Firewall**. It is a security feature that helps to protect your device by filtering network traffic that enters and exits your device. This traffic can be filtered based on several criteria, including source and destination IP address, IP protocol, or source and destination port number.

* [Read More](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/)

<br>

### Automated Firewall With AppID Tagging

Windows Firewall supports the use of App Control for Business AppID tags in policies. With this capability, you'll be able to scope your firewall rules to an application or a group of applications and rely on App Control policies to define those applications. The App Control AppID functionality adds an administrator defined tag to the given process token.

For example, you can easily use a policy that allows only files that come with Windows by default to be allowed to access the Internet while everything else will be blocked.

* [Read More](https://techcommunity.microsoft.com/t5/intune-customer-success/new-settings-in-microsoft-intune-to-enhance-windows-defender/bc-p/4030599)

<br>

### Win32 App Isolation

Win32 app isolation is a new security feature designed to be the default isolation standard on Windows clients. It is built on AppContainers and offers several added security features to help windows platform defend against attacks that leverage vulnerabilities in the application (this could be 3P libraries as well). To isolate their apps, application developers can update their applications using the tools provided by Microsoft.

* [Read More](https://blogs.windows.com/windowsdeveloper/2023/06/14/public-preview-improve-win32-app-security-via-app-isolation/)

* [Read More](https://github.com/microsoft/win32-app-isolation)

<br>

### VBS Enclaves

A Virtualization-based security (VBS) Enclave is a software-based trusted execution environment inside the address space of a host application. VBS Enclaves leverage underlying VBS technology to isolate the sensitive portion of an application in a secure partition of memory. VBS Enclaves enable isolation of sensitive workloads from both the host application and the rest of the system.

* [Read More](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves)

<br>

### UEFI Locked Settings (To Require Proof Of Physical Presence)

UEFI locked security measures are rooted in Proof of Physical Presence and they can't be disabled by modifying Group Policy, registry keys or other Administrative tasks.

The only way to disable UEFI locked security measures is to have physical access to the computer, reboot and access the UEFI settings, supply the credentials to access the UEFI, turn off Secure Boot, reboot the system and then you will be able to disable those security measures with Administrator privileges.

* [Read More](https://github.com/HotCakeX/Harden-Windows-Security?tab=readme-ov-file#device-guard)

<br>

### Early Launch AntiMalware (ELAM)

A security model in the kernel to better defend against malicious attacks on system-critical components. This security model extends the protected process infrastructure into a general-purpose model that can be used by 3rd party anti-malware vendors. The protected process infrastructure only allows trusted, signed code to load and has built-in defense against code injection attacks.

* [Read More](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Physical Security

## BitLocker

BitLocker is a Windows security feature that provides encryption for entire volumes, addressing the threats of data theft or exposure from lost, stolen, or inappropriately decommissioned devices.

* [Read More](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/)

<br>

### Startup Key (USB Flash Drive)

Requires a USB flash drive to be inserted into the computer to start the computer. The USB flash drive must contain the startup key for the encrypted drive. **This key is only a portion of the complete key required to perform a successful authentication. The other portion of the key is provided by the Startup PIN.**

* [Read More](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/faq#what-is-the-difference-between-a-tpm-owner-password--recovery-password--recovery-key--pin--enhanced-pin--and-startup-key)

* [Read More](https://github.com/HotCakeX/Harden-Windows-Security/wiki/BitLocker,-TPM-and-Pluton-%7C--What-Are-They-and-How-Do-They-Work)

<br>

### Secure Boot (PCR7 Binding)

Secure Boot blocks untrusted firmware and bootloaders (signed or unsigned) from being able to start on the system. By default, BitLocker provides integrity protection for Secure Boot by utilizing the TPM PCR 7 measurement. An unauthorized EFI firmware, EFI boot application, or bootloader can't run and acquire the BitLocker key.

* [Read More](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/countermeasures#protection-before-startup)

<br>

### TPM

A TPM is a microchip designed to provide basic security-related functions, primarily involving encryption keys. The TPM is installed on the motherboard of a computer, and it communicates with the rest of the system by using a hardware bus.

* [Read More](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/tpm-fundamentals)

<br>

### Startup PIN

In addition to the protection that the TPM provides, part of the encryption key is stored on a USB flash drive, and a PIN is required to authenticate the user to the TPM. This configuration provides multifactor authentication so that if the USB key is lost or stolen, it can't be used for access to the drive, because the PIN is also required. Preboot authentication with a PIN can mitigate an attack vector for devices that use a bootable eDrive because an exposed eDrive bus can allow an attacker to capture the BitLocker encryption key during startup.

* [Read More](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/countermeasures#preboot-authentication)

<br>

## Firmware Security

### System Management Mode (SMM) Protection

SMM code executes in the highest privilege level and is invisible to the OS. SMM protection is built on top of the Secure Launch technology and requires it to function. A hardware-enforced processor feature known as a supervisor SMI handler can monitor the SMM and make sure it doesn't access any part of the address space that it isn't supposed to. Windows measures SMI Handler's behavior and attest that no OS-owned memory has been tampered with.

* [Read More](https://learn.microsoft.com/en-us/windows/security/hardware-security/how-hardware-based-root-of-trust-helps-protect-windows#system-management-mode-smm-protection)

<Br>

### Static Root of Trust for Measurement (SRTM)

It is a hardware-based root of trust that helps ensure no unauthorized firmware or software (such as a bootkit) can start before the Windows bootloader. This hardware-based root of trust comes from the device's Secure Boot feature, which is part of the Unified Extensible Firmware Interface (UEFI). This technique of measuring the static early boot UEFI components is called the Static Root of Trust for Measurement (SRTM).

* [Read More](https://learn.microsoft.com/en-us/windows/security/hardware-security/how-hardware-based-root-of-trust-helps-protect-windows#static-root-of-trust-for-measurement-srtm)

<br>

### Secure Launch (DRTM)

The Dynamic Root of Trust for Measurement (DRTM) lets the system freely boot into untrusted code initially, but shortly after launches the system into a trusted state by taking control of all CPUs and forcing them down a well-known and measured code path. This has the benefit of allowing untrusted early UEFI code to boot the system, but then being able to securely transition into a trusted and measured state.

* [Read More](https://learn.microsoft.com/en-us/windows/security/hardware-security/how-hardware-based-root-of-trust-helps-protect-windows#secure-launchthe-dynamic-root-of-trust-for-measurement-drtm)

* [Read More](https://learn.microsoft.com/en-us/windows/security/hardware-security/system-guard-secure-launch-and-smm-protection)

<br>

### Secure Memory Overwrite

Secure MOR protects the MOR lock setting using a UEFI secure variable. This helps guard against advanced memory attacks.

* [Read More](https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/device-guard-requirements)

<br>

### TCG Storage Security Drive Password

This is a password for modern SSDs that can be set in the UEFI firmware. User is asked for this password during the boot process before the OS is loaded. The SSD itself can be encrypted by **BitLocker** and still require this additional password before the Startup PIN.

* [Read More](https://trustedcomputinggroup.org/commonly-asked-questions-answers-data-security-using-tcg-self-encrypting-drive-technology/)

<br>

### Mode Based Execution Control

MBEC virtualization provides an extra layer of protection from malware attacks. It enables hypervisors to more reliably and efficiently verify and enforce the integrity of kernel-level code.

* [Read More](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vsm)

<br>

### UEFI Password

It's a password that is set in the UEFI firmware. It is required to access the UEFI settings. This password can be used to prevent unauthorized changes to the UEFI settings.

* [Read More](https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/uefi-in-windows)

<br>

### UEFI Code ReadOnly

All UEFI memory that is marked executable is set to be read only. Memory marked writable must not be executable. Entries may not be left with neither of the attributes set, indicating memory that is both executable and writable.

* [Read More](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs)

<br>

### Kernel DMA Protection

Kernel Direct Memory Access (DMA) Protection is a Windows security feature that protects against external peripherals from gaining unauthorized access to memory. Windows uses the system Input/Output Memory Management Unit (IOMMU) to block external peripherals from starting and performing DMA, unless the drivers for these peripherals support memory isolation (such as DMA-remapping).

* [Read More](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)

<br>

### Pluton

Microsoft Pluton security processor is a chip-to-cloud security technology built with Zero Trust principles at the core. Microsoft Pluton provides hardware-based root of trust, secure identity, secure attestation, and cryptographic services. Pluton technology is a combination of a secure subsystem, which is part of the System on Chip (SoC) and Microsoft authored software that runs on this integrated secure subsystem.

It addresses security needs like booting an operating system securely even against firmware threats and storing sensitive data safely even against physical attacks.

* [Read More](https://learn.microsoft.com/en-us/windows/security/hardware-security/pluton/microsoft-pluton-security-processor)

* [Read More](https://learn.microsoft.com/en-us/windows/security/hardware-security/pluton/pluton-as-tpm)

<br>

### APIC Virtualization

APIC virtualization is a collection of features that can be used to support the virtualization of interrupts and the Advanced Programmable Interrupt Controller (APIC). When APIC virtualization is enabled, the processor emulates many accesses to the APIC, tracks the state of the virtual APIC, and delivers virtual interrupts — all in VMX non-root operation without a VM exit.

* [Read More](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/virtual-interrupts)

<br>

### Secure Boot

Secure Boot is a security standard developed by members of the PC industry to help ensure that a device boots using only software that's trusted by the original equipment manufacturer (OEM).

* [Read More](https://learn.microsoft.com/en-us/mem/intune/user-help/you-need-to-enable-secure-boot-windows)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## IDENTITY (In the Abstract Sense)

### Smart Screen

Microsoft Defender SmartScreen protects against phishing or malware websites and applications, and the downloading of potentially malicious files.

Microsoft Defender SmartScreen provide an early warning system against websites that might engage in phishing attacks or attempt to distribute malware through a socially engineered attack.

* [Read More](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/)

<br>

### Potentially Unwanted Application (PUA) Protection

Potentially unwanted applications (PUA) are a category of software that can cause your machine to run slowly, display unexpected ads, or at worst, install other software that might be unexpected or unwanted. PUA isn't considered a virus, malware, or other type of threat, but it might perform actions on endpoints that adversely affect endpoint performance or use. The term PUA can also refer to an application that has a poor reputation, as assessed by Microsoft Defender for Endpoint, due to certain kinds of undesirable behavior.

* [Read More](https://learn.microsoft.com/en-us/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus)

<br>

### Valid Signature Required For Elevation

Only elevate executable files that are signed and validated. This setting enforces public key infrastructure (PKI) signature checks for any interactive applications that request elevation of privilege. Enterprise administrators can control which applications are allowed to run by adding certificates to the Trusted Publishers certificate store on local computers.

* [Read More](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions#useraccountcontrol_onlyelevateexecutablefilesthataresignedandvalidated)

<br>

### Behavioral Analysis

Behavior monitoring (Analysis) is a critical detection and protection functionality of Microsoft Defender Antivirus.

Monitors process behavior to detect and analyze potential threats based on the behavior of applications, services, and files. Rather than relying solely on signature-based detection (which identifies known malware patterns), behavior monitoring focuses on observing how software behaves in real-time

* [Read More](https://learn.microsoft.com/en-us/defender-endpoint/behavior-monitor)

<br>

### Static Signature Analysis

Microsoft Defender's security definition updates are a critical component of the cybersecurity infrastructure, designed to continuously enhance protection against new malware and sophisticated attack techniques. These updates regularly refresh the definition files that are crucial for identifying spyware, viruses, and other potentially unwanted software.

* [Read More](https://www.microsoft.com/en-us/wdsi/defenderupdates)

<br>

### Personal Data Encryption (PDE)

PDE utilizes Windows Hello for Business to link data encryption keys with user credentials. When a user signs in to a device using Windows Hello for Business, decryption keys are released, and encrypted data is accessible to the user.
When a user logs off, decryption keys are discarded and data is inaccessible, even if another user signs into the device.

* [Read More](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/personal-data-encryption/)

<br>

### Enhanced Sign-in Security (ESS)

Windows Hello enables a user to authenticate using their biometrics or a PIN eliminating the need for a password. Biometric authentication uses facial recognition or fingerprint to prove a user's identity in a way that is secure, personal, and convenient. Enhanced Sign-in Security provides an additional level of security to biometric data by leveraging specialized hardware and software components, such as Virtualization Based Security (VBS) and Trusted Platform Module 2.0 to isolate and protect a user's authentication data and secure the channel by which that data is communicated.

* [Read More](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-enhanced-sign-in-security)

<br>

### Credential Guard

Credential Guard prevents credential theft attacks by protecting NTLM password hashes, Kerberos Ticket Granting Tickets (TGTs), and credentials stored by applications as domain credentials.

Credential Guard uses Virtualization-based security (VBS) to isolate secrets so that only privileged system software can access them. Unauthorized access to these secrets can lead to credential theft attacks like pass the hash and pass the ticket.

* [Read More](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)

<br>

### Admin-less

Most people run as full admins on their devices, which means apps and services have the same access to the kernel and other critical services as users. And the problem is that these apps and services can access critical resources without the user knowing. This is why Windows requires just in time administrative access to the kernel and other critical services as needed, not all the time, and certainly not by default. This makes it harder for an app to unexpectedly abuse admin privileges and secretly put malware or malicious code on Windows. When this feature is enabled, such as when an app needs special permissions like admin rights, you'll be asked for approval.

* [Read More](https://www.microsoft.com/en-us/security/blog/2024/05/20/new-windows-11-features-strengthen-security-to-address-evolving-cyberthreat-landscape/)

* [Watch](https://youtu.be/8T6ClX-y2AE?si=0otN2KrpfH2lf9oV&t=1269)

<br>

### Windows Hello Multi-Factor Authentication

Windows Hello for Business supports the use of a single credential (PIN and biometrics) for unlocking a device. Therefore, if any of those credentials are compromised (shoulder surfed), an attacker could gain access to the system.

Windows Hello for Business can be configured with multi-factor unlock, by extending Windows Hello with trusted signals. Administrators can configure devices to request a combination of factors and trusted signals to unlock them.

* [Read More](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/multifactor-unlock)

<br>

### Zero Trust DNS (ZTDNS)

ZTDNS integrates the Windows DNS client and the Windows Filtering Platform (WFP) to enable this domain-name-based lockdown. First, Windows is provisioned with a set of DoH or DoT capable Protective DNS servers; these are expected to only resolve allowed domain names. This provisioning may also contain a list of IP address subnets that should always be allowed (for endpoints without domain names), expected Protective DNS server certificate identities to properly validate the connection is to the expected server, or certificates to be used for client authentication.

* [Read More](https://techcommunity.microsoft.com/t5/networking-blog/announcing-zero-trust-dns-private-preview/ba-p/4110366)

* [Read More](https://techcommunity.microsoft.com/t5/networking-blog/deployment-considerations-for-windows-ztdns-client/ba-p/4113372)

<br>

### Advanced Intelligence-Based Phishing Protection

This feature is constantly learning from phishing attacks seen throughout the entire Microsoft security stack. It works alongside other Microsoft security products, to provide a layered approach to password security, especially for organizations early in their password-less authentication journey.

* [Read More](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/enhanced-phishing-protection)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Continue Reading

Head over to [the main page of the GitHub repository](https://github.com/HotCakeX/Harden-Windows-Security) to learn more about Windows Security and how to automate a lot of the features talked about on this page.

<br>
