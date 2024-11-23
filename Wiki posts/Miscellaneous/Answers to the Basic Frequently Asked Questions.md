# Answers to the Basic Frequently Asked Questions

This document has answers to the most basic frequently asked questions about this repository.

<br>

## From 1 to 10 How Difficult Is It to Use the Harden Windows Security Module?

1 - **Very Easy**

<br>

## What Do I Need to Do to Use Harden Windows Security Module?

1. Press Start button.
2. Type `PowerShell`, find it and open it.
3. Copy & Paste the following line in the PowerShell command line that is opened and press enter.
4. Wait for the App to start.

```powershell
(irm 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security.ps1')+'P'|iex
```

<br>

## How to Install PowerShell?

* [Install PowerShell from Microsoft Store](https://www.microsoft.com/store/productid/9MZ1SNWT0N5D) (easiest way)
* [Installing PowerShell on Windows](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows)

<br>

## But I Never Used PowerShell Before

Then let this be your initiation. You don't need to know anything about PowerShell to use the Harden Windows Security application/module.

<br>

## Do I Need to Use the Harden Windows Security Module Only on New Windows Installation?

No, you can use it any time.

<br>

## Do I Need to Install a 3rd Party Antivirus or Security Software?

Absolutely not.

Every security feature needed is already available in Windows. After Installing the Harden Windows Security Module, run PowerShell as Admin and use the command `Protect-WindowsSecurity` to activate them.

[Here is a more technical explanation](https://github.com/HotCakeX/Harden-Windows-Security/issues/103#issuecomment-1707940307)

<br>

## But I Already Have an Antivirus, What Should I Do?

Uninstall it by going to Windows Settings -> Apps -> Installed Apps -> Search for your Antivirus software's name and Uninstall it.

<br>

## What's the First Thing to Do After Reinstalling or Resetting Windows?

* Check and install any updates from Windows Update
* Check and install any updates in Microsoft Store
* Install and run the Harden Windows Security Module

<br>

## I Have Windows Home Edition, How to Upgrade to Pro?

* [Refer to this article](https://support.microsoft.com/en-us/windows/upgrade-windows-home-to-windows-pro-ef34d520-e73f-3198-c525-d1a218cc2818)

<br>

## How to Backup My Files in Windows?

* [Back up your Windows PC](https://support.microsoft.com/en-us/windows/back-up-your-windows-pc-87a81f8a-78fa-456e-b521-ac0560e32338)

* [How to back up your files in Windows](https://www.microsoft.com/en-us/windows/learning-center/back-up-files)

<br>

## What Categories Do You Recommend to Run?

Use the default predefined preset in the Harden Windows Security GUI, it is tuned for optimal and balanced security.
Presets allow for easy and quick selection of categories and sub-categories.

<br>

## How Often Do I Need to Apply the Hardening Measures?

Only 1 time.

<br>

## Should I Enable Smart App Control?

Yes, it's a very capable automated AI-driven security feature.

<br>

## Does It Affect My Gaming Performance or FPS?

No. Because Modern hardware are built for Windows security features such as Virtualization Based Security, BitLocker etc. They expect these advanced security features to be turned on and running on a secure system.

Only very old and unsupported hardware *might* experience degraded performance when using modern security features.

<br>

## What If I Want to Revert the Changes?

Use the Unprotect tab in the Harden Windows Security GUI (Graphical User Interface) to undo all the protections.

<br>

## Can You Alter The Requirements?

No. The [requirements](https://github.com/HotCakeX/Harden-Windows-Security#requirements-) are very basic and minimum, they are even less than what's required by Windows 11 minimum hardware.

<br>

## How to Prepare for a Firmware Update

Modern devices receive firmware updates as capsules through Windows Update, similar to other system updates. Before restarting your system to apply the firmware update, ensure the following steps are completed to avoid potential issues:

### Backup Your BitLocker Recovery Keys

It's crucial to back up your BitLocker recovery keys before updating the firmware. Use the Harden Windows Security Module to simplify this process. The 48-character recovery key for your OS drive will be required to boot your system after the firmware update is applied.

### Ensure Internet Connectivity After the Update

Once the firmware update is installed, you will need an active Internet connection to reset your Windows Hello credentials. This process involves signing into your Microsoft account and authorizing the login using the Microsoft Authenticator app.

The Harden Windows Security Module's Lock Screen category does not allow unauthorized people to change network settings on lock screen before logging in. Ensure your current Wi-Fi network is saved on the device and accessible post-update.

### Manage VPN Configurations

If you use VPN software with a kill switch or settings that require user interaction to connect at startup, disable these features before initiating the update.

### Recovery Options if Internet Connectivity Fails

If you're unable to connect to the Internet due to missed preparations, you have several recovery options. These require accessing the Windows Recovery Environment (WinRE) and launching a command prompt (CMD):

#### Backup Your Files

Launch a program like Notepad or Task Manager, then navigate to File -> Open to access a file browser. This allows you to copy important files from the OS drive to another location and if you ever decide to perform a clean OS installation, you won't lose any files.

#### Enable the Built-in Administrator Account

Launch `regedit.exe` to enable the built-in Administrator account in WinRE. After restarting your device, log in as the Administrator to resolve issues (e.g., enabling clean boot or uninstalling VPN software).

Once the recovery steps are complete, use `lusrmgr.msc` to disable the built-in Administrator account for security reasons.

> [!TIP]\
> To enable the built-in Administrator account with a blank password from WinRE:
>
> Locate the OS drive by using the `CD ..` command to move to the root directory, and `Dir` to list drive contents.
>
> Switch drives using their letter (e.g., `D:`, `F:`). Identify the OS drive and note its letter.
>
> Open the Command Prompt and type `regedit`.
>
> In the Registry Editor, select `HKEY_LOCAL_MACHINE`, then navigate to File -> Load Hive.
>
> Load the hive from the path: `OS Drive Letter:\Windows\System32\Config\SAM`.
>
> Provide a name for the hive, e.g., `Hive`.
>
> Navigate to `HKEY_LOCAL_MACHINE\Hive\SAM\Domains\Account\Users\000001F4` and locate the binary value `F`.
>
> Modify the 8th-row, 1st-column value from `11` to `10` to enable the Administrator account.
>
> Save changes.
>
> Unload the hive by selecting `Hive` under `HKEY_LOCAL_MACHINE` and choosing File -> Unload Hive.
>
> Restart your device.
>
> The built-in Administrator account will appear on the login screen.
>

<br>

## Have More Questions?

Ask away by opening [a new Discussion](https://github.com/HotCakeX/Harden-Windows-Security/discussions)

<br>
