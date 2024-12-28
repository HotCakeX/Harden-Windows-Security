# The Strength of Signed App Control Policies

<br>

<div align="center">

![image](https://github.com/user-attachments/assets/37b36dfe-ce2c-494b-bdc6-e4a71f0ed9ff)

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

### Activation Process

After a signed App Control policy .cip is copied to the EFI partition as part of the deployment process, we can see in [System Information](https://github.com/HotCakeX/Harden-Windows-Security/wiki/System-Information) that Application Control User-Mode is being enforced and when you try to install an application not permitted by the deployed policy, it will be successfully blocked.

At this point, we need to restart the system. since we are using UEFI Secure Boot, the Anti Tampering protection of the Signed policy kicks in and starts protecting App Control policy against any tampering.

Deploying a Signed App Control policy without restarting is the same as deploying Unsigned policies, because the Signed policy can be easily removed just like an Unsigned policy. So always make sure you restart at least once after deploying a Signed App Control policy.

<br>

### If Someone Forcefully Deletes the Deployed App Control Policy File

* Deleting the .cip policy file from `C:\Windows\System32\CodeIntegrity\CiPolicies\Active` and then restarting the system multiple times won't have any effect at all on the status of App Control. It will continue to work, and enforcement status will be shown in System Information. This is how it protects itself against rogue administrators.

* Deleting the .cip policy file from the EFI partition located at `\EFI\Microsoft\Boot\CIPolicies\Active` and restarting the device will result in a boot failure. Before system restart, nothing happens and it will remain active. This is another self-protection method of a Signed App Control policy. To recover from this state, the person will need to disable Secure Boot in the UEFI firmware settings. There are only 3 scenarios at this point:

   1. If, as suggested in the [Security Recommendations](https://github.com/HotCakeX/Harden-Windows-Security#security-recommendations), you set a strong password for the UEFI firmware of your hardware, they can't access the firmware. This security measure [alongside the rest of the Windows built-in security features](https://github.com/HotCakeX/Harden-Windows-Security) such as BitLocker device encryption will provide the Ultimate protection for a Windows device against threats, whether physical or originating from the Internet.

    2. If UEFI firmware is not password protected, the person can disable Secure Boot and/or TPM in UEFI firmware settings, they can even flash the entire UEFI firmware memory by physically abusing the device to get past the UEFI password, but since the device is BitLocker protected, **a total Lock Down will be triggered** and the person will need to provide the 48-digit recovery key of the OS drive in order to even complete the boot process into Windows lock screen. Assuming the person also has access to the Windows PIN, they will additionally need to provide 48-digit recovery password of any subsequent BitLocker protected drive(s) in order to access them (if the drive(s) aren't set to be auto-unlocked with the OS drive). **This is more than Security-In-Depth.** If UEFI firmware has any unpatched vulnerability, Device Guard features will take care of it.

    3. Since steps 1 and 2 are impossible to bypass for a rogue person, there will be only one option left. To completely recycle the physical device, get rid of the inaccessible hardware such as SSD and then sell the remaining hardware parts. Either way, your data remains secure and inaccessible to any unauthorized person(s) at all times.

<details><summary>Screenshot of a message after forcefully deleting a Signed App Control policy from the EFI partition in a VM</summary>

<img src="https://user-images.githubusercontent.com/118815227/219513251-3722745f-1aa5-4b5c-b4b0-e1a928b786a1.png" alt="Screenshot of a message after forcefully deleting a Signed App Control policy from the EFI partition">

</details>

<br>

### What Happens When We Turn On Smart App Control

Smart App Control works side-by-side any signed or unsigned App Control policy because it is itself a special type of App Control policy. It will be in enforced mode and continue to do its job.

<br>

### Dual boot OS configurations

When you deploy a **Signed** App Control policy on a system that uses Secure Boot, it will be enforced on all of the OSes that boot on the physical machine, because the policy resides on the EFI partition and is not tied to any specific OS. That means if you perform a clean install of a second Windows OS or natively boot a VHDX (Hyper-V VM), the policy will apply to them as well.

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

<br>
