# The Strength of Signed App Control Policies

<br>

<div align="center">

<img src="https://github.com/user-attachments/assets/37b36dfe-ce2c-494b-bdc6-e4a71f0ed9ff" alt="mad cats" />

</div>

<br>

<br>

Before delving into the topic, let's first clarify the role of an Administrator within the operating system. An Administrator is a user with the highest level of access to the OS, possessing the authority to make system-wide changes that impact all users.

**Administrators are responsible for managing system security**, modifying security settings, installing software and hardware, and accessing all files on the computer. Notably, an Administrator can seamlessly elevate privileges to SYSTEM, Managed Installer, or other access levels due to the absence of [security boundaries](https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria) between them. Equivalent roles in other operating systems include Root, SuperUser, and similar designations.

Implementing an Application Control policy requires Administrator privileges. Without these elevated permissions, it is impossible to deploy, remove, or alter any App Control policies.

Deploying an unsigned App Control policy leaves it vulnerable to removal or modification by any user with Administrator privileges. But what if you need your App Control policy to be so tamper-resistant that even an Administrator cannot alter or remove it? This is where signing comes into play.

App Control policies, authored in XML format, must be converted into .cip binary files before deployment. To enhance security and ensure tamper resistance, the .cip file can be signed with a code signing certificate prior to deployment. This signing process effectively fortifies the policy, making it impervious to unauthorized modifications or removal.

Signed App Control policies offer a formidable defense, they significantly hinder adversaries from achieving initial access to the system, a critical juncture in any attack. The importance of preventing initial access cannot be overstated. Once an attacker gains Administrator privileges, they inherently acquire the capability to manipulate the system.

For example, although a signed App Control policy cannot be removed, an attacker with Administrator rights could still deploy a new policy designed to block essential Endpoint Detection and Response (EDR) sensors or data collection agents. This could include tools like Azure Monitor Agent for Microsoft Sentinel or Microsoft Defender for Endpoint, effectively disrupting telemetry and impeding security monitoring.

Despite this potential for disruption, attackers are still constrained by the integrity of signed policies, which prohibit unauthorized programs from executing. Consequently, engineering robust defenses to prevent initial access, particularly access that elevates privileges to Administrator, remains paramount in securing modern systems.

<br>

## System Behavior After Deploying a Signed Application Control Policy

After a signed App Control policy .cip is copied to the EFI partition as part of the deployment process, we can see in [System Information](https://github.com/HotCakeX/Harden-Windows-Security/wiki/System-Information) that Application Control User-Mode is being enforced and when you try to install an application not permitted by the deployed policy, it will be successfully blocked.

At this point, a system restart is required. Since UEFI Secure Boot is enabled, the anti-tampering protection of the Signed App Control policy is activated, safeguarding the policy from any modifications.

Deploying a Signed App Control policy without restarting is the same as deploying Unsigned policies, because the Signed policy can be easily removed just like an Unsigned policy. So always make sure you restart at least once after deploying a Signed App Control policy.

<br>

## What If Someone Forcefully Deletes the Deployed App Control Policy File

* Deleting the .cip policy file from `C:\Windows\System32\CodeIntegrity\CiPolicies\Active` and then restarting the system multiple times won't have any effect at all on the status of App Control. It will continue to work, and enforcement status will be shown in System Information. This is how it protects itself against rogue administrators.

* Deleting the .cip policy file from the EFI partition located at `\EFI\Microsoft\Boot\CIPolicies\Active` and restarting the device will result in a boot failure. Before system restart, nothing happens, and it will remain active. This is another self-protection method of a Signed App Control policy. To recover from this state, the person will need to disable Secure Boot in the UEFI firmware settings. There are only 3 scenarios at this point:

   1. If, as suggested in the [Security Recommendations](https://github.com/HotCakeX/Harden-Windows-Security#security-recommendations), you set a strong password for the UEFI firmware of your hardware, they can't access the firmware. This security measure [alongside the rest of the Windows built-in security features](https://github.com/HotCakeX/Harden-Windows-Security) such as BitLocker device encryption will provide the Ultimate protection for a Windows device against threats, whether physical or originating from the Internet.

    2. If UEFI firmware is not password protected, the person can disable Secure Boot and/or TPM in UEFI firmware settings, they can even flash the entire UEFI firmware memory by physically abusing the device to get past the UEFI password, but since the device is BitLocker protected, **a total Lock Down will be triggered** and the person will need to provide the 48-digit recovery key of the OS drive in order to even complete the boot process into Windows lock screen. Assuming the person also has access to the Windows PIN, they will additionally need to provide 48-digit recovery password of any subsequent BitLocker protected drive(s) in order to access them (if the drive(s) aren't set to be auto-unlocked with the OS drive). If UEFI firmware has any unpatched vulnerability, [Device Guard features](https://github.com/HotCakeX/Harden-Windows-Security?tab=readme-ov-file#device-guard) and [Pluton](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/defending-against-ransomware-with-microsoft-defender-for/ba-p/3243941) will take care of it.

    3. Since steps 1 and 2 are impossible to bypass for a rogue person, there will be only one option left. To completely recycle the physical device, get rid of the inaccessible hardware such as SSD and then sell the remaining hardware parts. Either way, your data remains secure and inaccessible to any unauthorized person(s) at all times.

<details><summary>Screenshot of a message after forcefully deleting a Signed App Control policy from the EFI partition in a VM</summary>

<img src="https://user-images.githubusercontent.com/118815227/219513251-3722745f-1aa5-4b5c-b4b0-e1a928b786a1.png" alt="Screenshot of a message after forcefully deleting a Signed App Control policy from the EFI partition">

</details>

<br>

## What Happens When We Turn on Smart App Control

[Smart App Control](https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003) works side-by-side any signed or unsigned App Control policy because it is itself a special type of App Control policy. It will be in enforced mode and continue to do its job.

<br>

## Dual Boot OS Configurations

When you deploy a **Signed** App Control policy on a system that uses Secure Boot, it will be enforced on all of the OSes that boot on the physical machine, because the policy resides on the EFI partition and is not tied to any specific OS. That means if you perform a clean install of a second Windows OS or [natively boot a VHDX](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/deploy-windows-on-a-vhd--native-boot) (Hyper-V VM), the policy will apply to them as well.

<br>

## EFI Partition Size Limit

The [EFI partition](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/configure-uefigpt-based-hard-drive-partitions?view=windows-11#system-partition) typically has 200MB of space, which is generally more than sufficient for storing numerous signed App Control policies. These policies each usually only take up a few kilobytes of space on average. It's important to note that the size of the signed policy binary file (.cip) differs from the size of the original XML file. The .cip file is typically smaller than the XML file due to the parsing process used when generating the binary.

If you ever find that your EFI partition is running out of space, expanding it is always an option.

<br>

## TCG Self-Encrypting Drives (SEDs), OPAL, and Signed Policies

Modern enterprise-grade SSDs, particularly in the M.2 form factor from manufacturers like Samsung and Micron, commonly integrate at least the TCG OPAL 2.0 standard for self-encrypting drives (SEDs). This standard introduces a crucial security feature: Pre-Boot Authentication (PBA).

PBA allows for user authentication through a password prior to the system's UEFI (Unified Extensible Firmware Interface) becoming accessible, providing a layer of security that protects data before the operating system or UEFI is even loaded.

A TCG-compliant self-encrypting drive (SED) ensures that sensitive data remains inaccessible to unauthorized users at the point of authentication, by preventing data exposure in the pre-boot environment. This means that the authentication password is not stored in the UEFI variables, CMOS or dependent on the BIOS.

Upon powering up the device, the system presents a shadow PBA partition instead of the actual disk content. This dedicated partition, typically at least 128MB, houses the code responsible for unlocking the drive and allowing access to the original disk data. This partition essentially *shadows* the disk's content until proper authentication is performed.

Self-encrypting drives adhering to the TCG OPAL 2.0 standard implement a two-tiered key management system. The data encryption key (DEK) is responsible for encrypting the data stored on the drive, while the authentication key (a user-defined passphrase) is used to decrypt the DEK. One of the advantages of this layered approach is cryptographically secure disk erasure, because full disk erasure can be performed almost instantly by securely erasing the DEK.

This design also facilitates rapid response to security threats, allowing administrators to revoke compromised passphrases quickly. The seamless passphrase change allows administrators to change their passphrase without risking data loss, as the encryption remains tied to the DEK. This system allows for flexibility, enabling quick updates to authentication mechanisms without compromising the security or integrity of the stored data.

<br>

### What If Someone Steals the Laptop?

In high-security environments, it is advisable to use a self-encrypting drive that mandates a TCG Storage Security Drive Password before allowing access to any system components. This provides an additional physical layer of protection on top of BitLocker's existing security, which already includes triple-factor authentication (TPM, PIN, and Security Key stored on a USB drive). In this configuration, even if an attacker steals your laptop while it is shut down or in hibernation, they will encounter significant obstacles in accessing your data. The PIN is only half of the encryption key while the external key on the USB storage device is the other half. Together they form the full encryption key while the TPM supervises the entire process and gives the green light through attestation.

If the laptop is powered off or in hibernation, the attacker will be prompted for the pre-boot password before the system boots up. If the drive is removed and connected to another system that does not recognize TCG OPAL encryption, it will not boot. The drive will be inaccessible, with no option to initialize or bring the disk online through disk management tools.

If the attacker connects the drive to a compatible system, the drive will still be protected by the same pre-boot authentication, effectively preventing unauthorized access. The integrity of the drive's TCG password is not affected by tampering methods, such as resetting the CMOS or removing the CMOS battery, as the password is stored independently of UEFI or BIOS settings.

In the rare case that an attacker bypasses the TCG OPAL protection, BitLocker's multi-layered protection mechanisms provide an additional line of defense. The attacker would still need to circumvent the following:

1. The USB flash drive used to unlock the OS boot mechanism.

2. The pre-boot PIN, which can be 20-characters alphanumeric passphrase, including spaces and symbols.

3. The TPM: The SSD must be connected to the same machine due to the tight coupling with the Trusted Platform Module (TPM).

If any one of these factors is not satisfied, the attacker would be forced to provide a 48-character recovery password to unlock the boot process, further complicating their efforts.

<br>

> [!NOTE]\
> BitLocker employs software-based encryption using the `XTS-AES-256` algorithm. This approach is distinct from the hardware encryption provided by TCG OPAL. Alternatively, BitLocker can leverage TCG OPAL's hardware encryption directly. However, we intentionally maintain these as separate layers to enhance security.

<br>

### What if Laptop Was Turned On or in Sleep Mode When It Was Stolen?

Attacker may attempt to exfiltrate sensitive data directly from the system's memory. This type of attack, also known as an in-memory attack, is a serious concern, as data such as encryption keys or authentication credentials may reside in RAM while the system is active. However, modern CPUs have built-in Total Memory Encryption (TME) capabilities to mitigate this risk. TME encrypts the contents of memory at runtime using industry-standard AES-XTS algorithms, as defined by NIST, ensuring that all data stored in RAM is encrypted while the system is running, providing data protection in transit just like what TLS does for network connections. This means that even if an attacker gains physical access to the laptop's memory, they will not be able to retrieve unencrypted data or keys, as everything in memory is automatically encrypted at all times.

<br>

### Backup Strategies

While these robust security mechanisms such as TCG OPAL encryption and BitLocker offer a formidable defense against unauthorized access, you're still responsible to maintain regular backups of your data, even more than before. Take advantage of cloud-based solutions such as OneDrive for Business, SharePoint, or offsite backups to ensure your data remains safe and recoverable, even in the event of hardware theft or failure.

By leveraging these layered security measures, organizations can ensure their data remains encrypted and protected, significantly reducing the risk of unauthorized access and data loss.

<br>

> [!NOTE]\
> While TCG OPAL self-encrypting drives (SEDs) are often associated with enterprise and corporate client environments, this should not discourage individual users or small businesses from considering them. If your security requirements demand stronger encryption and protection, don't let the "enterprise" label limit your options.

<br>

The following chart is organized by the order of access available to an attacker. The outermost layer is at the top, and as we move downward, each layer must be breached before the attacker can progress to the next.

<br>

| Difficulty 1-10 | Offensive Action | Defensive Action |
|:--------:|:----:|:----:|
| 10 | Attempting to read the PBA encryption key or BitLocker encryption key from memory during runtime | Total Memory Encryption safeguards data in transit, making it inaccessible |
| 10 | Attempting to boot the laptop | TCG Storage Password (PBA) is required before the system can start |
| 10 | Clearing CMOS, removing the CMOS battery, or depriving the system of power | TCG Storage Password (PBA) remains unaffected and required. Additionally, this action breaks the compatibility between Secure Boot, TPM, and BitLocker's TPM key protector, causing BitLocker to prompt for the 48-character recovery password |
| 10 | Reconnecting the SED to another (incompatible) device | The drive won't be recognized, either during boot or within the OS (whether Windows or Linux) |
| 10 | Reconnecting the SED to another (compatible) device | Requires the TCG Storage Password (PBA) for authentication |
| 10 | Attempting to reset the UEFI password via CMOS reset or external buttons | This action breaks the trust between TPM and BitLocker key protectors, causing BitLocker to prompt for the 48-character recovery password. The TCG Storage Password (PBA) remains unaffected and still required |
| 10 | Attempting to modify UEFI settings, such as disabling Secure Boot, TPM, or any other configuration | UEFI settings can be set to Read-Only due to the deployment of the signed App Control policy, preventing changes even after multiple reboots |
| 10 | Attempting BitLocker pre-boot authentication | Requires triple-factor authentication: Pre-boot PIN, TPM, and a security key on a USB drive |
| 10 | Booting a live OS from USB and attempting to remove the Signed App Control policy by deleting/formatting the EFI partition or removing the individual CIP file | While the policy will be removed and App Control disabled, the attacker must still bypass BitLocker. The EFI partition is not encrypted by BitLocker but is protected by TCG OPAL encryption, which is assumed to have been bypassed at this point in chart. This action also triggers BitLocker to prompt for the 48-character recovery password due to Secure Boot |
| 10| Trying to guess the PIN | Activates the TPM's anti-hammering mechanism, causing each subsequent failed PIN attempt to experience progressively longer delays, as the TPM enforces increasing time intervals between attempts (which is only 1 part of the triple authentication) |
| 9 | Attacker attempts to exfiltrate data from non-OS drives | Each drive is BitLocker-encrypted and requires a unique 48-character recovery password to access |
| 8 | After bypassing all previous protections and layers, attacker reaches the Windows lock screen | Additional anti-hammering features and policies, implemented through the Harden Windows Security project, limit incorrect PIN attempts to three within a 24-hour period. A fourth failed attempt within this timeframe triggers a total lockdown, requiring the 48-character BitLocker recovery password to regain access |
| 8 | Attacker attempts to perform an administrative task | No local administrator account exists; the device is managed remotely via Microsoft Entra ID, and the local user only has Standard privileges |
| 8 | Attacker attempts to run unauthorized software | Blocked by the Signed App Control policy (Unless the policy was removed previously from the EFI partition) |
| 9 | Attacker attempts to execute any type of malware early in the boot process | Blocked by the Signed App Control policy, which executes earlier in the boot sequence (Unless the policy was removed previously from the EFI partition) |
| 9 | Attacker attempts to remove the signed app control policy | Makes the OS unbootable (Unless the policy was removed previously from the EFI partition) |

<br>

## Summary

The protection of initial access and root/superuser/administrator privileges is fundamental to system security. Without securing these high-level access points, other security measures become secondary. These privileged roles are essential for any configurable system, as they enable the management and customization of hardware and security settings. However, there are consumer-level systems such as the [Xbox Series X/S](https://www.youtube.com/watch?v=quLa6kzzra0) that do not have these highly-privileged accounts. These are designed as secure *black boxes*, not only to protect the user from malware but also to safeguard the hardware from user intervention, creating a vastly different threat model.

In contrast, on conventional computer systems, root/administrator privileges are necessary to maintain control over system security. Threat actors recognize the value of gaining these privileges, as it allows them to manipulate system security to their advantage. However, with Windows' multi-layered security infrastructure, which integrates both hardware and software protections, we can effectively thwart these efforts. Each defense layer can be made increasingly difficult and time-consuming for attackers to bypass, creating an almost insurmountable challenge. As cyber threats continue to evolve and adversaries grow more sophisticated, systems must adapt to provide robust, tamper-resistant defenses described in this article.

<br>

> [!TIP]\
> Continue reading:
>
> * [Penetration Testing and Benchmarking](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Rationale.md#-for-penetration-testing-and-benchmarking)
>
> * [Deploying Signed App Control policies](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-App-Control-Policy)
>
> * [Creating Code Signing Certificate via AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Build-New-Certificate)
>
> * [Only a Small Portion of The Windows OS Security Apparatus](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Only-a-Small-Portion-of-The-Windows-OS-Security-Apparatus)
>
> * [RuntimeEncryption of Memory With Intel® Total Memory Encryption - Multi-Key](https://www.intel.com/content/dam/www/central-libraries/us/en/documents/2022-10/intel-total-memory-encryption-multi-key-whitepaper.pdf)
>
> * [TCG Storage Opal Integration Guidelines](https://trustedcomputinggroup.org/wp-content/uploads/TCG_Storage_ReferenceDocument_Opal_Integration_Guidelines_v1.00_r1.00.pdf)
>
> * [Trusted Computing Group and NVM Express Joint White Paper: TCG Storage, Opal, and NVMe](https://trustedcomputinggroup.org/wp-content/uploads/TCGandNVMe_Joint_White_Paper-TCG_Storage_Opal_and_NVMe_FINAL.pdf)
>
> * [All other TCG articles related to OPAL](https://trustedcomputinggroup.org/resources/?search=OPAL&)
>
> * [An example of a CPU supporting Total Memory Encryption - Multi Key - Intel 14700k](https://www.intel.com/content/www/us/en/products/sku/236783/intel-core-i7-processor-14700k-33m-cache-up-to-5-60-ghz/specifications.html)
>

<br>
