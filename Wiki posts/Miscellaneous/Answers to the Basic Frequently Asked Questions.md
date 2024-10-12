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

## What’s the First Thing to Do After Reinstalling or Resetting Windows?

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

## Have More Questions?

Ask away by opening [a new Discussion](https://github.com/HotCakeX/Harden-Windows-Security/discussions)

<br>
