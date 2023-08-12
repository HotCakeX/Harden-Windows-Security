# Things to do when clean installing Windows

There are certain tasks that need to be performed for a proper Windows clean installation

## Clear the TPM

Preparing for a clean installation in this way helps ensure that the new operating system can fully deploy any TPM-based functionality that it includes, such as attestation.

* [Clear all the keys from the TPM](https://learn.microsoft.com/en-us/windows/security/information-protection/tpm/initialize-and-configure-ownership-of-the-tpm#clear-all-the-keys-from-the-tpm)

* [How Windows uses the Trusted Platform Module](https://learn.microsoft.com/en-us/windows/security/information-protection/tpm/how-windows-uses-the-tpm)

<br>

**Clear the TPM from the UEFI settings and and not from inside the Windows**

[Read more about TPM 2.0 specifications](https://trustedcomputinggroup.org/wp-content/uploads/PC-Client-Specific-Platform-TPM-Profile-for-TPM-2p0-v1p05p_r14_pub.pdf)

<br>

## Format/Delete the following partitions

* Format/delete your C drive
* Format/delete the EFI partition
* Format/delete the Recovery partition

Let Windows recreate them during clean installation process

<br>

## How to create a bootable USB drive without 3rd party tools

[Refer to this Wiki post](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Bootable-USB-flash-drive-with-no-3rd-party-tools)

<br>
