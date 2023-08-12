# Steps to create Bootable USB flash drive with no 3rd party tools

1. Plug in a USB flash drive that has at least 8GB capacity.

2. Delete all partitions on the USB flash drive either using Disk Management [¹](https://learn.microsoft.com/en-us/windows-server/storage/disk-management/overview-of-disk-management) [²](https://support.microsoft.com/en-us/windows/help-in-disk-management-ad88ba19-f0d3-0809-7889-830f63e94405) or using Windows Settings => System => Storage => Advanced Storage Settings => Disks & Volumes

3. Using either of the methods above, create a 1GB `FAT32` partition, let's name it `BOOT`🟨

4. Create a 2nd partition on the USB flash drive with the rest of the remaining unused space, formatted as `NTFS`, let's name this one `DATA`🟩

5. Mount your Windows ISO file by double clicking on it.

6. Select all and Copy everything from Windows ISO file to the `NTFS` partition (DATA partition🟩)

7. Copy everything from Windows ISO file, except for the "sources" folder, to the `FAT32` partition (BOOT partition🟨)

8. Create a new folder in the `FAT32` partition (BOOT partition🟨), and name it `sources`

9. copy the `boot.wim` from the "sources" folder inside the Windows ISO file to the newly created "sources" folder in the FAT32 partition (BOOT partition🟨).

10. That's it, your USB flash drive is ready and bootable.
