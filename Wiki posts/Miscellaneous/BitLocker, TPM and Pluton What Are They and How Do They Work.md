# BitLocker, TPM and Pluton

<div align="center">
<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/dsadasdas.jpg" alt="AI generated photo of a girl - BitLocker, TPM and Pluton What Are They and How Do They Work" width="700">
</div>

## Introduction

The optimal kind of security measure is imperceptible to the user during deployment and usage. Whenever there is a potential delay or difficulty due to a security feature, there is a high probability that users will attempt to circumvent security. This situation is particularly prevalent for data protection, and that is a scenario that organizations need to prevent. Whether intending to encrypt entire volumes, removable devices, or [individual files](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/personal-data-encryption/), Windows satisfies these requirements by providing streamlined, usable solutions. BitLocker Device Encryption safeguards the system by seamlessly implementing device-wide data encryption.

<br>

## BitLocker and Virtual Hard Disks such as VHDX

When using [VHDX native boot](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/deploy-windows-on-a-vhd--native-boot), you can employ BitLocker to encrypt the drives that reside in it, they will be equally secure. In the native VHDX boot scenario, the decryption keys are still retained in the TPM, precluding an offline attack against the stored data. BitLocker still operates the same as it does on a normal installed system.

<br>

## A Discourse on the Modes and Methods of Protection from Physical Intrusions

### BitLocker With TPM

[BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/BitLocker/BitLocker-group-policy-settings#reference-configure-tpm-platform-validation-profile-for-native-uefi-firmware-configurations) with TPM only, uses [PCRs](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/BitLocker/BitLocker-group-policy-settings#about-the-platform-configuration-register-pcr), if the hashes are the same the decryption key is released. With TPM only mode, a threat actor can access the secret data when it is released and can obtain the decryption key when the TPM releases it automatically.

### BitLocker With TPM and Startup Key

With a Startup PIN, a PIN is required before the secret material is released. This thwarts a jumper cable attack where a threat actor can directly access the secret material from the TPM. Therefore, the only security benefit a PIN would provide during the boot sequence is a physical attack prevention.

If you are a threat actor and the system lacks a Startup PIN, the disk remains encrypted even when you boot it to the logon screen where authentication is required via Windows Hello credential providers. Conversely, when you use a Startup PIN and enter it correctly, the disk stays encrypted until you authenticate at the logon screen.

When BitLocker is activated, the disk is constantly encrypted. It is irrelevant whether you utilize a Startup PIN, or you operate in TPM only mode or you employ a smart card to unlock it. However, a Startup PIN is invariably recommended as a deterrent mechanism against physical attacks.

<br>

## The Power of BitLocker and TPM Against Offline and Side Channel Attacks

Now there is the in-band versus out of band security system paradigm we need to discuss. For instance, Windows login screen is in-band and TPM is out of band.

The TPM is used to deter side channel attacks while login screen is to deter brute force/cryptographic attacks. Windows Hello, which is a very robust system, is TPM backed just like BitLocker.

BitLocker is to prevent offline attacks primarily, secondarily it is to prevent data loss. If you can alter the Windows operating system files while it is offline, it has no means to protect itself. That is why BitLocker exists to impede tampering while the system is offline. Most people assume it is used for data loss prevention; in reality the primary defense capability is tampering with OS files.

I can guarantee breaching into any operating system that has an unencrypted disk, and I don’t have to use any zero days or exploit code.

BitLocker is a transparent drive encryption technology operating below the file system level and BitLocker encrypted disks always remain encrypted even after Windows Hello authentication and unlocking the OS.

<br>

## How Do The BitLocker Key Protectors Work?

BitLocker key protectors safeguard the encryption key, which encrypts and decrypts the data on the disk. BitLocker provides various key protectors and allows using multiple key protectors simultaneously. However, some key protectors must be combined with other key protectors to attain the required level of security.

Suppose you want your BitLocker encrypted drive to demand a PIN at Startup, need TPM for verification, and also necessitate a USB flash drive to be plugged in. In [this document](https://learn.microsoft.com/en-us/powershell/module/bitlocker/add-bitlockerkeyprotector), you can see there is a `-StartupKeyProtector` option for the USB flash drive, `-TPMProtector` option for TPM, and a `-Pin` option for the PIN.

Using those parameters individually will not mandate all 3 key protectors to be used concurrently. It will only oblige one of them to be used. So you will have to either enter the PIN, have the disk connected to the same computer (TPM) or have the USB flash drive plugged in, but all 3 of them are not enforced.

If you want to enforce a multifactor authentication, you need to use the following command

```powershell
Add-BitLockerKeyProtector -MountPoint C: -TpmAndPinAndStartupKeyProtector
```

This time, all 3 key protectors are essential to unlock the drive. You will have to enter the PIN, have the disk connected to the same computer (TPM), and have the USB flash drive plugged in.

<br>

## How To Properly Configure BitLocker Key Protectors

As we've already discussed before, having TPM alone is not enough to protect the system from physical attacks. TPM must be coupled with other factors to provide strong deterrence against physical attacks. So when configuring policies, either in Intune or Group Policy, you should disable the TPM only mode.

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Secure%20BitLocker%20key%20protectors%20group%20policy.png" alt="Secure BitLocker key protectors group policy">

<br>

In the image above:

* Red is the insecure method
* Pinks are the more secure methods
* Green is the most secure method

Depending on your organization's or personal needs you can disallow the rest of them and only keep one.

The same settings can be found in Intune as well

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Secure%20Bitlocker%20key%20protector%20policies%20in%20Intune%20portal.png" alt="Secure BitLocker key protector policies in Intune portal">

<br>

A few seconds after enrolling the device in Intune, you will see a notification

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Intune%20encrolled%20device%20Bitlocker%20notification%20for%20encryotion.png" alt="Intune encrolled device BitLocker notification for encryption">

</div>

<br>

After clicking on the notification and accepting the next prompt, you will see this window allowing you to choose a key protector. As you can see, the `Let BitLocker Automatically Unlock My Drive` option is grayed out because it would use only the TPM key protector and we disabled that in Intune/Group Policy.

<br>

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/TPM%20only%20key%20protector%20grayed%20out%20as%20a%20result%20of%20the%20policy%20enforcements.png" alt="TPM only key protector grayed out as a result of the policy enforcements">

</div>

<br>

<br>

## Pluton, The Ultimate Security Chip

One of the most formidable technologies that is impervious to tampering, jumper cable or other vulnerabilities is [the Pluton chip](https://www.microsoft.com/en-us/security/blog/2020/11/17/meet-the-microsoft-pluton-processor-the-security-chip-designed-for-the-future-of-windows-pcs/). The same technology that has been employed in Xbox to stop even the [most sophisticated physical attacks.](https://www.youtube.com/watch?v=quLa6kzzra0)

Pluton is a dedicated physical chip that runs on [Azure sphere](https://azure.microsoft.com/en-us/products/azure-sphere/) architecture. It is very much out of band and is technically physically on the same die as the CPU, but the CPU has no control over it at all because it has its own dedicated self-maintaining operating system.

A firmware based TPM is reliant on the CPU to emulate it, Pluton is not dependent on the CPU to emulate it or run it. Pluton is completely self-sufficient which implies that it is out of band. dTPM (discrete TPMs) are usually more susceptible than fTPMs (Firmware based TPMs).

Pluton addresses security needs like booting an operating system securely even against firmware threats and storing sensitive data safely even against physical attacks.

<br>

## Conclusion

We learned how important it is to use BitLocker and protect our data at rest. The [Harden Windows Security repository](https://github.com/HotCakeX/Harden-Windows-Security) employs BitLocker to encrypt the operating system drive and optionally any other drives that user chooses to. It utilizes the most secure configuration and military grade encryption algorithm, XTS-AES-256, TPM 2.0 and Start-up PIN.

<br>

## Continue Reading

* [Overview of BitLocker device encryption](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-device-encryption-overview-windows-10)
* [BitLocker FAQ](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/BitLocker/faq)
* [Personal Data Encryption (PDE)](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/personal-data-encryption/)

<br>
