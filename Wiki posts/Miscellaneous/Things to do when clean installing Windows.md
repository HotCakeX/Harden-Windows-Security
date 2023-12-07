# Things to do when clean installing Windows

There are certain tasks that need to be performed for a proper Windows clean installation. Not all of the items below apply to all hardware.

<br>

## BitLocker

Suspend the protection of the OS drive and make sure you have the recovery password of all other non-OS drives so that you will be able to unlock them after clean installation of the OS.

<br>

## Intel VMD Drivers (Varies by device)

If you use a modern hardware that uses Intel® Volume Management Device (Intel® VMD) technology, you will need to download the VMD drivers on a flash drive and load them during Windows OS installation so that the OS installer will be able to detect the internal SSD and its partitions. You can download the VMD drivers from your hardware manufacturer's website.

* [How to Enable Intel® VMD Capable Platforms for RAID or Intel® Optane™ Memory Configuration with the Intel® RST Driver](https://www.intel.com/content/www/us/en/support/articles/000057787/memory-and-storage/intel-optane-memory.html)

<br>

## Clear the TPM (Varies by device)

Not all devices have this capability in the UEFI. If your UEFI has the option to clear the TPM, use it prior to clean installation of the OS.

* [Clear all the keys from the TPM](https://learn.microsoft.com/en-us/windows/security/information-protection/tpm/initialize-and-configure-ownership-of-the-tpm#clear-all-the-keys-from-the-tpm)

* [How Windows uses the Trusted Platform Module](https://learn.microsoft.com/en-us/windows/security/information-protection/tpm/how-windows-uses-the-tpm)

* [Read more about TPM 2.0 specifications](https://trustedcomputinggroup.org/wp-content/uploads/PC-Client-Specific-Platform-TPM-Profile-for-TPM-2p0-v1p05p_r14_pub.pdf)

<br>

## Format/Delete the following partitions

* Format/delete your C drive
* Format/delete the EFI partition
* Format/delete the Recovery partition

Let Windows recreate them during clean installation process

<br>

<br>

## How to create a bootable USB drive without 3rd party tools

[Refer to this Wiki post](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Bootable-USB-flash-drive-with-no-3rd-party-tools)

<br>
