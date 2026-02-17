# Windows Firewall | Harden System Security

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/d6960a261913f979526c0fac7901effa4b72d813/Pictures/Readme%20Categories/Windows%20Firewall/Windows%20Firewall.svg" alt="Windows Firewall - Harden Windows Security GitHub repository" width="500"></p>

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Sets the Network Location of all connections to Public; [Public network means less trust to other network devices](https://support.microsoft.com/en-us/windows/make-a-wi-fi-network-public-or-private-in-windows-0460117d-8d3e-a7ac-f003-7a0da607448d).

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Makes sure Windows Firewall is enabled for all profiles (which is the default) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/firewall-csp#mdmstorepublicprofileenablefirewall) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/firewall-csp#mdmstoreprivateprofileenablefirewall) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/firewall-csp#mdmstoredomainprofileenablefirewall)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables notifications in all 3 profile types to be displayed to the user when an application is blocked from listening on a port. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/firewall-csp#mdmstoredomainprofiledisableinboundnotifications) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/firewall-csp#mdmstoreprivateprofiledisableinboundnotifications) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/firewall-csp#mdmstorepublicprofiledisableinboundnotifications)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables Windows Firewall logging for Domain, Private and Public profiles, sets the log file size for each of them to the max `32.767 MB`. Defines separate log files for each of the firewall profiles. Logs only dropped packets for Private and Public profiles, Logs both dropped and successful packets for Domain profile. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/firewall-csp#mdmstoredomainprofileenablelogdroppedpackets) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/firewall-csp#mdmstoredomainprofilelogfilepath) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/firewall-csp#mdmstoredomainprofilelogmaxfilesize) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/firewall-csp#mdmstoreprivateprofileenablelogdroppedpackets) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/firewall-csp#mdmstoreprivateprofilelogfilepath) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/firewall-csp#mdmstoreprivateprofilelogmaxfilesize) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/firewall-csp#mdmstorepublicprofileenablelogdroppedpackets) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/firewall-csp#mdmstorepublicprofilelogfilepath) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/firewall-csp#mdmstorepublicprofilelogmaxfilesize)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Disables [Multicast DNS (mDNS) UDP-in Firewall Rules for all 3 Firewall profiles](https://techcommunity.microsoft.com/t5/networking-blog/mdns-in-the-enterprise/ba-p/3275777), This might interfere with Miracast screen sharing, which relies on the Public profile, and homes where the Private profile is not selected, but it does add an extra measure of security in public places, like a coffee shop.
    - The domain name `.local` which is used in mDNS (Multicast DNS) [is a special-use domain name reserved by the Internet Engineering Task Force (IETF)](https://en.wikipedia.org/wiki/.local) so that it may not be installed as a top-level domain in the Domain Name System (DNS) of the Internet.

<br>

## Management <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/refs/heads/main/Harden%20System%20Security/Assets/External/FirewallManagement.png" alt="Firewall Management Tab Icon" width="30" />

The **Management** tab provides an interface for creating, viewing, and deleting Windows Firewall rules created by the Harden System Security app. This feature is designed to give you granular control over network traffic for specific applications and directories.

### User Interface Guide

#### Configure button

Before creating rules, use this menu to set your preferences or view the defaults to confirm they are what you desire.

* **Direction**: Choose `Inbound`, `Outbound`, or `Both`. This will determine whether the rule applies to incoming traffic, outgoing traffic, or both.

* **Action**: Choose to `Allow` or `Block` the connection.

* **Select Programs**: Browse for specific `.exe` file(s).

* **Select Folders**: Browse for folder(s). The app will recursively scan the selected folders and any sub-folders in them and detect all `.exe` files.

#### Managing Selections

Any file you select is added to a pending list. To view or modify this list:

1. Right-click (or Tap & Hold) the **Configure** button.

2. A context menu will appear showing the selected files. You can review the list, remove individual items from it or click **Clear** to remove all selections.

#### Create button

Once you have configured your settings and selected your files, click or tap on the **Create** button. The app will iterate through every file in your pending list and create a firewall rule for each one based on your selected direction and action. After rules have been created, the ListView at the bottom will be refreshed to display the latest status of the Firewall rules created by this app.

#### Block Dual-Use Programs in Firewall button

It is located within the flyout of the **Create** button. This specialized function proactively blocks network access for high-risk dual-use system binaries often abused by attackers for downloading payloads or exfiltrating data. When you use this button, an inbound and outbound rule with the action set to **Block** will be created for every one of the programs in the list below:

<details>
<summary><strong>View Full List of Blocked Dual-Use Programs</strong></summary>

```text
C:\Windows\System32\bitsadmin.exe
C:\Windows\System32\certreq.exe
C:\Windows\System32\certutil.exe
C:\Windows\System32\cmstp.exe
C:\Windows\System32\cmd.exe
C:\Windows\System32\cscript.exe
C:\Windows\System32\forfiles.exe
C:\Windows\hh.exe
C:\Windows\System32\mshta.exe
C:\Windows\System32\msiexec.exe
C:\Windows\System32\netsh.exe
C:\Windows\System32\presentationhost.exe
C:\Windows\System32\reg.exe
C:\Windows\System32\regsvr32.exe
C:\Windows\System32\rundll32.exe
C:\Windows\System32\schtasks.exe
C:\Windows\System32\wscript.exe
C:\Windows\System32\wmic.exe
C:\Windows\System32\xwizard.exe
C:\Windows\SysWOW64\bitsadmin.exe
C:\Windows\SysWOW64\certreq.exe
C:\Windows\SysWOW64\certutil.exe
C:\Windows\SysWOW64\cmstp.exe
C:\Windows\SysWOW64\cmd.exe
C:\Windows\SysWOW64\cscript.exe
C:\Windows\SysWOW64\forfiles.exe
C:\Windows\SysWOW64\hh.exe
C:\Windows\SysWOW64\mshta.exe
C:\Windows\SysWOW64\msiexec.exe
C:\Windows\SysWOW64\netsh.exe
C:\Windows\SysWOW64\presentationhost.exe
C:\Windows\SysWOW64\reg.exe
C:\Windows\SysWOW64\regsvr32.exe
C:\Windows\SysWOW64\rundll32.exe
C:\Windows\SysWOW64\schtasks.exe
C:\Windows\SysWOW64\wscript.exe
C:\Windows\SysWOW64\wmic.exe
C:\Windows\SysWOW64\xwizard.exe
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```
</details>

#### Retrieve Firewall Rules button

Click or tap on this button to load the current state of rules managed by this application. You will be able to search through them or sort them based on different available properties. You can also **right-click** or **tap & hold** on one or more rules and delete them if you wish.

> [!NOTE]
>
> * All firewall rules created by this application are stored in the **Group Policy** store rather than the standard local store.
> * **Persistence**: These rules are not affected by local rule merges, ensuring your security configurations remain active.
> * **Organization**: All rules are tagged with the `HardenSystemSecurity` group, making them easy to identify and manage exclusively through this application without cluttering the default Windows Firewall list.

<br>

#### Extras Button

* This button offers additional features you could use. Except for the 2 export options, the rest display a confirmation dialog before proceeding with the action to prevent accidental clicks/taps:

    * Export Local Rules: Back up your current local firewall configuration to a `.wfw` file for safekeeping or migration.

    * Export GPO Rules: Export firewall rules enforced by Group Policy Objects to a `.wfw` file for backup.

    * Import Local Rules: Restore a previously saved configuration to your local firewall policy (replaces existing rules) by selecting a `.wfw` file.

    * Import GPO Rules: Load a saved configuration into the Group Policy firewall store (replaces existing rules) by selecting a `.wfw` file.

    * Restore Defaults: Reset the local firewall configuration to the original Windows default state, removing all custom rules.

    * Delete All Rules: Completely wipe the local firewall policy, removing every rule including the default OS rules.

<br>
