# Bootable Drive Maker | Harden System Security

<br>

The **Bootable Drive Maker** is a utility integrated into [the Harden System Security app](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security) under the Extras section. It provides a reliable and streamlined way to create bootable Windows installation media from ISO files. Whether you want granular control over your USB drive's partitions or prefer a fully automated setup, this tool caters to both needs while also offering standard ISO extraction capabilities.

## How It Works

Creating a bootable Windows installation drive typically requires specific formatting to support modern UEFI systems while circumventing the 4GB file size limit of FAT32 for the `install.wim` file. The Bootable Drive Maker handles this by utilizing a dual-partition layout (a BOOT partition and a DATA partition) or by automatically preparing the physical disk for you. 

**Supported Operations:** 

1. Creating bootable media via Manual Partitioning
2. Creating bootable media via Automatic Partitioning
3. Extracting ISO contents to a local directory.

<br>

## Selecting a Windows ISO

To begin, you need a valid Windows ISO file.

* **Download Link:** A convenient shortcut is provided in the UI to directly download the official Windows 11 ISO files from Microsoft.
* **Browse Button:** Click the Browse button to open a file picker and select your `.iso` file. 
* **ISO Details:** Once loaded, the app instantly reads and displays the size of the selected ISO file. You can right-click the arrow next to the Browse button to view the exact path or clear the selection.

<br>

## Creating a Bootable Drive

The tool offers two distinct modes for preparing your USB drive. You can switch between them using the selector bar. 

### Manual Partitioning

Use this mode if you have already partitioned your USB drive or want to select specific existing partitions manually.
* **BOOT Partition:** Select the partition designated for boot files. This must be a FAT32 partition (Minimum 2GB, Maximum 32GB).
* **DATA Partition:** Select the partition where the heavy Windows installation files (like `install.wim`) will reside. This should be formatted as NTFS (Minimum 8GB).
* *Note:* Use the **Refresh Drives** button to ensure your newly plugged-in or formatted partitions appear in the drop-down menus.

### Automatic Partitioning

Use this mode for a completely hands-off experience. **Warning: This will erase all data on the selected physical disk.**
* **Select Target Drive:** Choose the physical disk you wish to convert into a bootable drive from the drop-down list.
* **Format Remaining Space:** By default, the app creates the necessary BOOT and DATA partitions. You can check the box to format any remaining unallocated space on the drive into a third partition.
* **File System Selection:** If formatting the remaining space, you can choose your preferred file system for that extra partition (`exFAT`, `NTFS`, or `FAT32`).

Once your settings are configured, click **Create Bootable Drive** to begin the process. The app displays a live progress bar and status text so you can monitor the copy and configuration operations.

<br>

## ISO Extraction

If you simply need the contents of an ISO file without making a bootable drive, you can use the built-in Extraction feature.

* **Select Destination:** Browse and select a target directory on your computer where the ISO contents should be extracted.
* **Extract:** Click the **Extract ISO** button. The app will securely and internally mount the ISO, copy all internal files and folders to your chosen directory, and display the real-time extraction progress.
