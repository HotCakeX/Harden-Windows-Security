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

## Management

Use this tab to manage Windows Firewall rules created by the Harden System Security app, create new rules and so much more:

- Browse for individual files to allow or block through Windows Firewall, controlling whether they can make network connections.

- Browse for folders to allow or block all executable files within them, including executables in all subfolders.

  - This is very useful if you install a new application that contains multiple executables, as you can simply select the installation folder to allow or block all of them at once quickly.

- List all of the Firewall rule created by the Harden System Security app.

- Delete any Firewall rules created by the Harden System Security app.

- Copy one or more Firewall rule to clipboard.

- Search through the Firewall rules and sort them.

<br>

### Dual-Use Program Blocking via Windows Firewall

You can now block network access through Windows Firewall for high-risk dual-use binaries to reduce abuse for malicious downloads or data exfiltration. This implements the requested feature in [#706](https://github.com/HotCakeX/Harden-Windows-Security/issues/706). The full list of these programs is available in the [Windows Firewall page in the wiki](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Windows-Firewall).

> [!NOTE]\
> All of the Windows Firewall rules are created in the Group Policy store instead of the regular local store so they are not affected by the local rules merges and they have more flexibility. All of rules created by the Harden System Security app are part of the `HardenSystemSecurity` group, so you can easily identify them.

### User Interface Guide

* **Configure**: Use this button to adjust the configurations that will be applied when you use the **Create** button. Here you can select the direction (inbound/outbound) and action (allow/block) of the firewall rules that you will create. You can also browse for executable files or browse for folders to recursively scan for executable files.

   * Any executable file that is detected will be added to a list that is visible when you right-click or tap and hold on the **Configure button** so you can adjust the selected files by removing them one by one or clearing the full list.

* **Create**: Use this button to create Windows Firewall rules based on the configurations you set in the **Configure** button. Once you click this button, all of the executable files that are in the list will have Windows Firewall rules created for them.

* **Block Dual-Use programs in Firewall**: Use this button to block network access for high-risk dual-use binaries through Windows Firewall. This will create outbound and inbound rules, with edge traversal set to block, for the following programs:

<details>
<summary>List of Dual-Use programs</summary>

```
C:\Windows\System32\bitsadmin.exe
C:\Windows\System32\certreq.exe
C:\Windows\System32\certutil.exe
C:\Windows\System32\cmstp.exe
C:\Windows\System32\cmd.exe
C:\Windows\System32\cscript.exe
C:\Windows\System32\forfiles.exe
C:\Windows\System32\hh.exe
C:\Windows\System32\mshta.exe
C:\Windows\System32\msiexec.exe
C:\Windows\System32\netsh.exe
C:\Windows\System32\powershell.exe
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
C:\Windows\SysWOW64\powershell.exe
C:\Windows\SysWOW64\presentationhost.exe
C:\Windows\SysWOW64\reg.exe
C:\Windows\SysWOW64\regsvr32.exe
C:\Windows\SysWOW64\rundll32.exe
C:\Windows\SysWOW64\schtasks.exe
C:\Windows\SysWOW64\wscript.exe
C:\Windows\SysWOW64\wmic.exe
C:\Windows\SysWOW64\xwizard.exe
```
</details>

* **Retrieve Firewall Rules**: Use this button to list all of the Windows Firewall rules that were created by the Harden System Security app.

<br>
