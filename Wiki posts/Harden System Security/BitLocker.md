# BitLocker | Harden System Security

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/0180bc6ace1ea086653cc405f142d1aada424150/Pictures/Readme%20Categories/BitLocker%20Settings/BitLocker%20Settings.svg" alt="BitLocker Settings - Harden Windows Security" width="550"></p>

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [The app](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security) sets up and configures BitLocker [using official documentation](https://learn.microsoft.com/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings), with the most secure configuration and military grade encryption algorithm, XTS-AES-256, to protect the confidentiality and integrity of all information at rest. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/bitlocker-csp#encryptionmethodbydrivetype) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/bitlocker-csp#systemdrivesrequirestartupauthentication)

    - It offers 2 security levels for OS drive encryption: **Enhanced** and **Normal**.

    - In **Normal** security level, the OS drive is encrypted with TPM and Startup PIN. This provides very high security for your data, especially with a PIN that's long, complicated (uppercase and lowercase letters, symbols, numbers, spaces) and isn't the same as your Windows Hello PIN.

    - In **Enhanced** security level, the OS drive is encrypted with TPM and Startup PIN and Startup key. This provides the highest level of protection by offering Multifactor Authentication. You will need to enter your PIN and also plug in a flash drive, containing a special BitLocker key, into your device in order to unlock it. [Continue reading more about it here](https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/countermeasures#preboot-authentication).

    - Once the OS drive is encrypted, for every other non-OS drive, there will be prompts for confirmation before encrypting it. The encryption will use the same algorithm as the OS drive and uses [Auto-unlock key protector](https://learn.microsoft.com/powershell/module/bitlocker/enable-bitlockerautounlock). Removable flash drives are skipped.

    - The recovery information of all of the drives are saved in a single well-formatted text file in the root of the OS drive `C:\BitLocker-Recovery-Info-All-Drives.txt`. It's **very important to keep it in a safe and reachable place as soon as possible, e.g., in OneDrive's Personal Vault which requires additional authentication to access.** See [here](https://www.microsoft.com/en-us/microsoft-365/onedrive/personal-vault) and [here](https://support.microsoft.com/en-us/office/protect-your-onedrive-files-in-personal-vault-6540ef37-e9bf-4121-a773-56f98dce78c4) for more info. You can use it to unlock your drives if you ever forget your PIN, lose your Startup key (USB Flash Drive) or TPM no longer has the correct authorization (E.g., after a firmware change).

    - TPM has [special anti-hammering logic](https://learn.microsoft.com/windows/security/information-protection/tpm/tpm-fundamentals) which prevents malicious user from guessing the authorization data indefinitely. [Microsoft defines that maximum number of failed attempts](https://learn.microsoft.com/archive/blogs/dubaisec/tpm-lockout) in Windows is 32 and every single failed attempt is forgotten after 2 hours. This means that every continuous two hours of powered on (and successfully booted) operation without an event which increases the counter will cause the counter to decrease by 1. You can view all the details using this [PowerShell command](https://learn.microsoft.com/powershell/module/trustedplatformmodule/get-tpm): `Get-TPM`.

    - Check out <a href="#lock-screen">Lock Screen</a> category for more info about the recovery password and the 2nd anti-hammering mechanism.

    - BitLocker will bring you a [real security](https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/countermeasures#attacker-with-skill-and-lengthy-physical-access) against the theft of your device if you strictly abide by the following basic rules:

        - As soon as you have finished working, either Hibernate or shut Windows down and allow for every shadow of information to disappear from RAM within 2 minutes. **This practice is recommended in High-Risk Environments.**

        - Do not mix 3rd party encryption software and tools with BitLocker. BitLocker creates a secure end-to-end encrypted ecosystem for your device and its peripherals, this secure ecosystem is backed by things such as software, Virtualization Technology, TPM 2.0 and UEFI firmware, BitLocker protects your data and entire device against **real-life attacks and threats**. You can encrypt your external SSDs and flash drives with BitLocker too.

<br>

> [!IMPORTANT]\
> [AMD Zen 2 and 3 CPUs have a vulnerability in them](https://github.com/HotCakeX/Harden-Windows-Security/issues/63), if you use one of them, make sure your BitLocker Startup PIN is at least 16 characters long [*(max is 20)*](https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-group-policy-settings#configure-minimum-pin-length-for-startup).

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables or disables [DMA protection from BitLocker Countermeasures](https://learn.microsoft.com/windows/security/information-protection/bitlocker/bitlocker-countermeasures#protecting-thunderbolt-and-other-dma-ports) based on the status of [Kernel DMA protection](https://learn.microsoft.com/windows/security/information-protection/kernel-dma-protection-for-thunderbolt). Kernel DMA Protection is [not compatible](https://learn.microsoft.com/windows/security/information-protection/kernel-dma-protection-for-thunderbolt#system-compatibility) with other BitLocker DMA attacks countermeasures. It is recommended to disable the BitLocker DMA attacks countermeasures if the system supports Kernel DMA Protection ([The Harden System Security App](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security) does that exactly). Kernel DMA Protection provides higher security bar for the system over the BitLocker DMA attack countermeasures, while maintaining usability of external peripherals. You can check the status of Kernel DMA protection [using this official guide](https://learn.microsoft.com/windows/security/information-protection/kernel-dma-protection-for-thunderbolt#how-to-check-if-kernel-dma-protection-is-enabled). <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-dataprotection#allowdirectmemoryaccess)

    - [Kernel DMA Protection (Memory Access Protection) for OEMs](https://learn.microsoft.com/windows-hardware/design/device-experiences/oem-kernel-dma-protection) page shows the requirements for Kernel DMA Protection. for Intel CPUs, support for requirements such as VT-X and VT-D can be found in each CPU's respective product page. e.g. [Intel i7 13700K](https://ark.intel.com/content/www/us/en/ark/products/230500/intel-core-i713700k-processor-30m-cache-up-to-5-40-ghz.html)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Disallows standard (non-Administrator) users from changing the BitLocker Startup PIN or password <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/bitlocker-csp#systemdrivesdisallowstandarduserscanchangepin)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Requires you to choose a PIN that contains at least 10 characters](https://learn.microsoft.com/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings#configure-minimum-pin-length-for-startup) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/bitlocker-csp#systemdrivesminimumpinlength)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> (Only on Physical machines) Enables Hibernate and adds Hibernate to Start menu's power options. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-power#allowhibernate)

    - Devices that support [Modern Standby](https://learn.microsoft.com/windows-hardware/design/device-experiences/modern-standby) have the most security because [(S1-S3) power states](https://learn.microsoft.com/windows-hardware/drivers/kernel/system-power-states) which belong to the [legacy sleep modes](https://learn.microsoft.com/windows-hardware/design/device-experiences/modern-standby-vs-s3) are not available. In Modern Standby, security components remain vigilant and the OS stays protected. Applying Microsoft Security Baselines also automatically disables the legacy (S1-S3) sleep states.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> [Sets Hibernate to full](https://learn.microsoft.com/windows/win32/power/system-power-states#hibernation-file-types)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Disallows access to Bitlocker-protected removable data drives from earlier versions of Windows.](https://learn.microsoft.com/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings#allow-access-to-bitlocker-protected-removable-data-drives-from-earlier-versions-of-windows)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Allow network connectivity during connected-modern-standby (only when plugged in). Keeps the Operating System and Microsoft Defender up to date while the device is Modern Standby capable and is plugged in (meaning it's not on battery). <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-power#acconnectivityinstandby_2)

<br>

Refer to this [official documentation about the countermeasures of BitLocker](https://learn.microsoft.com/windows/security/information-protection/bitlocker/bitlocker-countermeasures)

<br>

## BitLocker Management

<img src="https://raw.githubusercontent.com/HotCakeX/.github/b70cfc85f491ca1e80bd00df62bfebeb0f3b7d5b/Pictures/APNGs/Harden%20System%20Security/HardenSystemSecurity_BitLockerManagementDemo.apng" alt="BitLocker management in Harden System Security" />

<br>

### Full Drive Encryption

You can enable BitLocker encryption for the **Operating System (OS) drive**, **fixed drives**, and **removable drives** via a guided, safety-first workflow. All messages and UI elements related to BitLocker are localized for the languages supported by the app. BitLocker management is implemented in the low-level **ComManager** component of Harden System Security.

### Add or Modify Key Protectors

A step-by-step workflow allows you to add and modify a variety of key protectors for BitLocker-protected volumes, making key management straightforward and auditable.

### Suspend BitLocker Encryption

Need to update firmware or perform maintenance? Use the Suspend feature to temporarily suspend BitLocker protection on the OS drive. You may optionally specify the number of restarts after which protection will be automatically resumed.

### Resume BitLocker Encryption

Quickly resume protection for drives whose BitLocker state was previously suspended.

### Backup BitLocker Key Protectors

Back up recovery passwords and key protector details for your drives so you have access to the required 48-character recovery keys when needed.

After enabling BitLocker for a drive or adding a new Key Protector, the Export button will light up briefly, giving you a subtle reminder that it's best to export the data and back them up so you don't forget that.

<br>

![ExportButtonLightup](https://github.com/user-attachments/assets/54fb97bb-51fb-4dcd-a1a8-7527c41dc2ff)

> [!TIP]
> Because BitLocker operations can be consequential, every action requires explicit confirmation before proceeding. Additionally, the preselected (focused) button in each confirmation dialog is **Cancel** to further reduce the chance of accidental acceptance.

<br>
