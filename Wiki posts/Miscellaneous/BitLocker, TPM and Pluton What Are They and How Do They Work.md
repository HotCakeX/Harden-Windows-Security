# BitLocker, TPM and Pluton

<div align="center">
<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/dsadasdas.jpg" alt="AI generated photo of a girl - BitLocker, TPM and Pluton What Are They and How Do They Work" width="700">
</div>

# Introduction

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

Now there is the in-band versus out of band security system paradigm we need to discuss.

Windows login screen is in-band, the TPM is out of band.

The TPM is used to deter side channel attacks, and login screen is to deter brute force/cryptographic attacks. Windows Hello is a very robust system, and it is TPM backed, BitLocker is also TPM backed. BitLocker is to prevent offline attacks primarily, secondarily it is to prevent data loss.

If you can alter the Windows operating system files while it is offline, it has no means to protect itself. That is why BitLocker exists, it impedes tampering while the system is offline. Most people assume it is used for data loss prevention; in reality the primary defense capability is tampering with OS files.

I can guarantee breach into any operating system that has an unencrypted disk, and I don’t have to use any zero days or exploit code.

BitLocker encrypted disk remains encrypted even after Windows Hello authentication. BitLocker is a transparent drive encryption technology operating below the file system level. Drive encryption is always on even after you unlock the OS so your data is always encrypted.

<br>

## Pluton, The Ultimate Security Chip

One of the most formidable technologies that is impervious to tampering, jumper cable or other vulnerabilities is [the Pluton chip](https://www.microsoft.com/en-us/security/blog/2020/11/17/meet-the-microsoft-pluton-processor-the-security-chip-designed-for-the-future-of-windows-pcs/). The same technology that has been employed in Xbox to stop even the [most sophisticated physical attacks.](https://www.youtube.com/watch?v=quLa6kzzra0)

Pluton is a dedicated physical chip that runs on [Azure sphere](https://azure.microsoft.com/en-us/products/azure-sphere/) architecture. It is very much out of band, it is technically physically on the same die as the CPU, but the CPU has no control over it at all. It has its own dedicated self-maintaining operating system.

A firmware based TPM is reliant on the CPU to emulate it, pluton is not dependent on the CPU to emulate it or run it. Pluton is completely self-sufficient. Which implies that it is out of band. dTPM (discrete TPMs) are usually more susceptible than fTPMs (Firmware based TPMs).

Pluton addresses security needs like booting an operating system securely even against firmware threats and storing sensitive data safely even against physical attacks.

<br>

## Conclusion

We learned how important it is to use BitLocker and protect our data at rest. The [Harden Windows Security repository](https://github.com/HotCakeX/Harden-Windows-Security) employs BitLocker to encrypt the operation system drive and optionally any other drives that user chooses to. It utilizes the most secure configuration and military grade encryption algorithm, XTS-AES-256, TPM 2.0 and Start-up PIN.

<br>

## Continue Reading

* [Overview of BitLocker device encryption](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-device-encryption-overview-windows-10)
* [BitLocker FAQ](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/BitLocker/faq)
* [Personal Data Encryption (PDE)](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/personal-data-encryption/)

<br>
