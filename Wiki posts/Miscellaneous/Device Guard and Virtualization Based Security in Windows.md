# Device Guard<a href="#device-guard">![DeviceGuardIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/DeviceGuard.png)</a>

<p align="center"><img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Bing%20AI%20generated/_7b1941d2-cc77-4423-b4d9-76986bdc3680.jpg" alt="An AI generated picture of a cat girl working in a server farm" width="600"></p>

<br>

**Most of the Device Guard and Virtualization-Based Security features are Automatically enabled by default** on capable and modern hardware. The rest of them will be enabled and configured to the most secure state after you apply the **Microsoft Security Baselines 23H2 or later**.

The [Harden Windows Security Module](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden%E2%80%90Windows%E2%80%90Security%E2%80%90Module) has a feature that is accessible through `confirm-SystemCompliance` cmdlet. It will let you scan your system and verify the implementations of the Device Guard policies.

* [**Check out Secured-Core PC requirements**](https://www.microsoft.com/en-us/windows/business/windows-11-secured-core-computers).

<br>

## About UEFI Lock

UEFI locked security measures are rooted in **Proof of Physical Presence** and they can't be disabled by modifying Group Policy, registry keys or other Administrative tasks.

The only way to disable UEFI locked security measures is to have physical access to the computer, reboot and access the UEFI settings, supply the credentials to access the UEFI, turn off Secure Boot, reboot the system and then you will be able to disable those security measures with Administrator privileges.

<br>

## Device Guard Controls and Policies

- [Virtualization-Based Security + UEFI Lock](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceguard?WT.mc_id=Portal-fx#enablevirtualizationbasedsecurity)

    - [Validate enabled Windows Defender Device Guard hardware-based security features](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity#validate-enabled-vbs-and-memory-integrity-features)

- [Secure boot (without requiring DMA protection) for Virtualization-Based Security](https://learn.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceguard?WT.mc_id=Portal-fx#requireplatformsecurityfeatures)

    - This is in accordance with [Microsoft's recommendation](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity#use-registry-keys-to-enable-memory-integrity). This option provides Secure Boot with as much protection as is supported by a given computer’s hardware. A computer with input/output memory management units (IOMMUs) will have Secure Boot with DMA protection. A computer without IOMMUs will simply have Secure Boot enabled.
    - Secure boot has 2 parts, part 1 is enforced using the Group Policy by this module, but for part 2, you need to [enable Secure Boot in your UEFI firmware settings](https://support.microsoft.com/en-us/windows/windows-11-and-secure-boot-a8ff1202-c0d9-42f5-940f-843abef64fad) **if** it's not enabled by default (which is the case on older hardware).
    - [(Kernel) DMA protection hardware requirements](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-kernel-dma-protection)

- Virtualization-based protection of Code Integrity + UEFI Lock <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-VirtualizationBasedTechnology?WT.mc_id=Portal-fx#hypervisorenforcedcodeintegrity)

- [Require UEFI Memory Attributes Table (MAT)](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-VirtualizationBasedTechnology?WT.mc_id=Portal-fx#requireuefimemoryattributestable)

- [Windows Defender Credential Guard + UEFI Lock](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage#enable-virtualization-based-security-and-windows-defender-credential-guard) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceguard?WT.mc_id=Portal-fx#lsacfgflags)

    - [Windows Defender Device Guard and Windows Defender Credential Guard hardware readiness tool](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/dg-readiness-tool)
    - [Windows Defender Credential Guard requirements](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-requirements)

- [System Guard Secure Launch and SMM protection (Firmware Protection)](https://learn.microsoft.com/en-us/windows/security/hardware-security/system-guard-secure-launch-and-smm-protection#group-policy) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceguard?WT.mc_id=Portal-fx#configuresystemguardlaunch)

    - [How to verify System Guard Secure Launch is configured and running](https://learn.microsoft.com/en-us/windows/security/hardware-security/system-guard-secure-launch-and-smm-protection#how-to-verify-system-guard-secure-launch-is-configured-and-running)

- [Kernel Mode Hardware Enforced Stack Protection](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/windows-11-version-22h2-security-baseline/ba-p/3632520)

- [Local Security Authority](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) (LSA) process Protection + UEFI Lock <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-lsa#configurelsaprotectedprocess)

<br>

## [Device Protection in Windows Security Gives You One of These 4 Hardware Scores](https://support.microsoft.com/en-us/windows/device-protection-in-windows-security-afa11526-de57-b1c5-599f-3a4c6a61c5e2)

<ol>
<li>Standard hardware security not supported</li>
 <ul>
 <li>This means that your device does not meet at least one of the requirements of Standard Hardware Security.</li>
 </ul>
<li>Your device meets the requirements for Standard Hardware Security. </li>
 <ul>
 <li><a href="https://support.microsoft.com/en-us/topic/what-is-tpm-705f241d-025d-4470-80c5-4feeb24fa1ee">TPM 2.0</a></li>
 <li><a href="https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot">Secure boot</a></li>
 <li><a href="https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention">DEP</a></li>
 <li><a href="https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/unified-extensible-firmware-interface">UEFI MAT</a></li>
 </ul>
<li>Your device meets the requirements for Enhanced Hardware Security</li>
 <ul>
 <li><a href="https://support.microsoft.com/en-us/topic/what-is-tpm-705f241d-025d-4470-80c5-4feeb24fa1ee">TPM 2.0</a></li>
 <li><a href="https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot">Secure boot</a></li>
 <li><a href="https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention">DEP</a></li>
 <li><a href="https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/unified-extensible-firmware-interface">UEFI MAT</a></li>
 <li><a href="https://support.microsoft.com/en-us/windows/core-isolation-e30ed737-17d8-42f3-a2a9-87521df09b78">Memory Integrity</a></li>
 </ul>
<li>Your device has all Secured-core PC features enabled</li>
 <ul>
 <li><a href="https://support.microsoft.com/en-us/topic/what-is-tpm-705f241d-025d-4470-80c5-4feeb24fa1ee">TPM 2.0</a></li>
 <li><a href="https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot">Secure boot</a></li>
 <li><a href="https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention">DEP</a></li>
 <li><a href="https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/unified-extensible-firmware-interface">UEFI MAT</a></li>
 <li><a href="https://support.microsoft.com/en-us/windows/core-isolation-e30ed737-17d8-42f3-a2a9-87521df09b78">Memory Integrity</a></li>
 <li><a href="https://www.microsoft.com/en-us/security/blog/2020/11/12/system-management-mode-deep-dive-how-smm-isolation-hardens-the-platform/">System Management Mode (SMM)</a></li>
 </ul>
</ol>

<br>

## Additional Resources

* [Memory integrity and VBS enablement](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-hvci-enablement)

<br>
