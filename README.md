
<h1 align="center">
  <br>
  <a href="https://github.com/HotCakeX/Harden-Windows-Security"><img src="https://github.com/HotCakeX/Harden-Windows-Security/blob/main/png-donut-2.png" alt="Avatar" width="200"></a>
  <br />
  <br>
  Harden Windows Security
  <br>
</h1>

<h4 align="center">Harden Windows 11 safely, securely and without breaking anything</h4>



<p align="center">
	
	
  <a href="https://www.powershellgallery.com/packages/Harden-Windows-Security/">
    <img src="https://img.shields.io/powershellgallery/v/Harden-Windows-Security?style=for-the-badge"
         alt="PowerShell Gallery">
  </a>
	
	
  <a href="https://www.powershellgallery.com/packages/Harden-Windows-Security/">
    <img src="https://img.shields.io/powershellgallery/dt/Harden-Windows-Security?style=for-the-badge"
         alt="PowerShell Gallery Downloads count">
  </a>
 
</p>

<p align="center">
  <a href="#hardening-Categories">Hardening Categories</a> •
  <a href="#how-to-use">How To Use</a> •
  <a href="#features">Features</a> •
  <a href="#related">Related</a> •
  <a href="#support">Support</a> •
  <a href="#security-reccomendations">Security Reccomendations</a> •
  <a href="#resources">Resources</a> •
  <a href="#license">License</a>


</p>


<h1> <br> </h1>
</br>

> __Warning__  <h5>Windows by default is secure and safe, this script does not imply nor claim otherwise. just like anything, you have to use it wisely and don't compromise yourself with reckless behavior and bad user configuration; Nothing is foolproof. this script only uses the tools and features that have already been implemented by Microsoft in Windows OS to fine-tune it towards the highest security and locked-down state, using well-documented, supported, often recommended and official methods. continue reading for comprehensive info.</h5>

 </br>


## Hardening Categories

From Top to bottom in order:

* Commands that require Administrator Privileges (click on each of these to see in-depth info)
  - <a href="#Windows-Security-aka-Defender">Windows Security aka Defender</a>
  - <a href="#Attack-surface-reduction-rules">Attack surface reduction rules</a>
  - <a href="#Bitlocker-Settings">Bitlocker Settings</a>
  - <a href="#TLS-Security">TLS Security</a>
  - <a href="#Lock-Screen">Lock Screen</a>
  - <a href="#User-Account-Control">UAC (User Account Control)</a>
  - <a href="#Device-Guard">Device Guard</a>
  - <a href="#Windows-Firewall">Windows Firewall</a>
  - <a href="#Optional-Windows-Features">Optional Windows Features</a>
  - <a href="#Windows-Networking">Windows Networking</a>
  - <a href="#Miscellaneous-Configurations">Miscellaneous Configurations</a>
  - <a href="#Certificate-Checking-Commands">Certificate Checking Commands</a>
  - <a href="#Country-IP-Blocking">Country IP Blocking</a>
  

* Commands that don't require Administrator Privileges
  - <a href="#Non-Admin-Commands">Non-Admin Commands that only affect the current user and do not make machine-wide changes</a>



## How To Use

To run the script:

```PowerShell
# Download the latest version of the script to the current user folder
irm -Uri "https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security.ps1" -OutFile "Harden-Windows-Security.ps1"

# set execution policy temporarily to bypass for the current PowerShell session only
Set-ExecutionPolicy Bypass -Scope Process

# run the script
.\Harden-Windows-Security.ps1

# delete the script file from computer
remove-Item .\Harden-Windows-Security.ps1

```

> **Note**
> if there are multiple Windows user accounts in your computer, it's recommended to run this script in each of them, without administrator privileges, because Non-admin commands only apply to the current user and are not machine wide.

> **Note**
> The script asks for confirmation, in the PowerShell console, before running each hardening category, so you can selectively run (or don't run) each of them.


> **Note**
> Things with **#TopSecurity** tag can break functionalities or cause difficulties so this script does NOT enable them by default. press Control + F and search for #TopSecurity in the script to find those commands and how to enable them if you want. 


## Features:

- Always up-to-date and works with latest build of Windows (Currently Windows 11 - compatible and fully tested a Lot on stable and Insider Dev builds)
- Doesn't break anything
- Doesn't remove or disable Windows functionlities against Microsoft's recommendation
- Above each command there are comments that explain what it does, why it's there, provide extra important information about it and links to additional resources for better understanding
- When a hardening command is no longer necessary because it's applied by default by Microsoft on new builds of Windows, it will also be removed from this script in order to prevent any problems and because it won't be necessary anymore.
- The script can be run infinite number of times, it's made in a way that it won't make any duplicate changes at all.



<h1> <br> </h1>


## Windows Security aka Defender
Enables additional security features of Windows Security (Defender) to further secure the OS.
You can refer to [this official documentation](https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps) for full details.

## Attack surface reduction rules
Reducing your attack surface means protecting your devices and network, which leaves attackers with fewer ways to perform attacks. Configuring attack surface reduction rules in Windows can help!

Attack surface reduction rules target certain software behaviors, such as:

- Launching executable files and scripts that attempt to download or run files
- Running obfuscated or otherwise suspicious scripts
- Performing behaviors that apps don't usually initiate during normal day-to-day work

Such software behaviors are sometimes seen in legitimate applications. However, these behaviors are often considered risky because they are commonly abused by attackers through malware. Attack surface reduction rules can constrain software-based risky behaviors and help keep your organization safe.

You can find more info [here](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction?view=o365-worldwide) and [ASR Reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide)

## Bitlocker Settings 
This script sets up and configures Bitlocker, [using official documentation](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings), with the most secure configuration and Military Grade encryption algorithm, XTS-AES-256, TPM 2.0 and start-up PIN.

BitLocker software will bring you a real security against the theft of your computer if you strictly abide by the following basic rule:
 As soon as you have finished working, completly shut Windows down and allow for every shadow of information to disappear
(from RAM, disk caches) within 2 minutes. **this practice is recommended in high-risk environments.**

Refer to this [official documentation about the countermeasures of Bitlocker](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-countermeasures)

Bitlocker uses SecureBoot and TPM 2.0 among other advanced features, performs pre-boot checks to verify the OS hasn't been corrupted/tampered with a bootkit. Third party encryption software and tools should Not be used because they break this secure chain of trust which, flows from the firmware (UEFI) to Windows bootloader and then to BitLocker. it is critical for this chain of trust to exist in order to prevent an entire category of attack against Windows systems. This is not theoretical, this stops real-life attacks.

## TLS Security
Refer to [this documentation](https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-) for more info about TLS and Schannel in Windows. this script disables TLS 1 and TLS 1.1 security protocols that only exist for backward compatibility. all modern software should and do use TLS 1.2 and TLS 1.3.

Changes made by the script only affect things that use schannel: that includes Edge, IIS web server, built-in inbox Windows apps and some other programs supplied by Microsoft, but not 3rd party software that use [portable stacks](https://en.wikipedia.org/wiki/Comparison_of_TLS_implementations#Portability_concerns) like Java, nodejs, python or php.

if you want to read more: [Demystifying Schannel](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/demystifying-schannel/ba-p/259233)

  

## Lock Screen
This part includes commands like Automatically locking computer after X seconds, which is set to 120 seconds (2 minutes) in this script, you can change that to any value you like.

there are also other commands in the script, of course each of them have comments above them that provide explanation,
one of them is "Require CTRL+ALT+DEL on the lock screen", the reason and logic behind it is:

A malicious user might install malware that looks like the standard sign-in dialog box for the Windows operating system, and capture a user's password. The attacker can then sign in to the compromised account with whatever level of user rights that user has.

[More info here](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-do-not-require-ctrl-alt-del#reference)

## User Account Control

Here is [the official reference](https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#registry-key-settings) for the commands used in this section of the script, User Account Control Group Policy and registry key settings.

## Device Guard
Since Device Guard and Virtualization-Based Security features are by default enabled automatically on capable and modern hardware, this script only double-checks their status and if needed, fully enables them to the highest level. you can find all the information on that [in this official documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity). one of the notable commands used in this category is ensuring that UEFI lock is enabled for VBS features.

## Windows Firewall
This category makes sure Windows Firewall is enabled for all profiles (which is the default)

additionally, [blocks LOLbins (Living Off The Land Binaries)](https://lolbas-project.github.io/) from making Internet connections.

LOLBins are Microsoft-signed files, meaning they are either native to the Operating System (OS) and come pre-installed,
or are available from Microsoft (i.e. a Microsoft program or add-on).
Despite being legitimate (and well-intentioned) files,
these binaries can be exploited by an attacker and used in an attack.

This script uses built-in Firewall cmdlet to block those binaries in Windows Firewall.

you can completely skip this category when running the script and choose N (for No) when prompted for input for this category, in PowerShell console.

## Optional Windows Features

This script disables some rarely used features in Windows optional features, those are as follows:
- PowerShell v2; because it's old and doesn't support [AMSI](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/#antimalware-scan-interface-integration)
- Work Folders client; not used when your computer is not part of a domain or enterprise network
- Internet Printing Client; used in combination with IIS web server, [old feature](https://learn.microsoft.com/en-us/troubleshoot/windows-server/printing/manage-connect-printers-use-web-browser), can be disabled without causing problems further down the road
- Windows Media Player (legacy); isn't needed anymore, Windows 11 has modern media player app.

Also enables these useful optional features:
- Windows Defender Application Guard; which is a safe environment to open untrusted websites
- Windows Sandbox; install, test and use programs in a disposable virtual operation system, completely separate from your main OS
- Hyper-V; the best and a hybrid hypervisor (Type 1 and Type 2) to run virtual machines on
- Virtual Machine Platform; required for Android subsystem or WSA (Windows subsystem for Android). if it's disabled, it will be automatically enabled either way when you try to install WSA from Store app

## Windows Networking
These are configurations that are typically recommended in high-risk environments but also can be applied for home users.
such as:
- [Disabling NetBIOS over TCP/IP](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-netbt-interfaces-interface-netbiosoptions) on all network interfaces
- Disabling the LLMNR protocol
- Disabling [LMHOSTS lookup protocol](https://www.crowe.com/cybersecurity-watch/netbios-llmnr-giving-away-credentials) on all network adapters
- and more, comments as always provided above each command in the script.


## Miscellaneous Configurations
Sets Early launch antimalware engine's status to 8 which is Good only.
the default value is 3, which allows good, unknown and 'bad but critical'.
that is the default value, because setting it to 8 can prevent your computer from booting if
the driver it relies on is critical but at the same time unknown or bad.

as mentioned earlier, this script sets it to 8, so only drivers verified by Microsoft to be Good can boot.

[some background](https://learn.microsoft.com/en-us/windows/compatibility/early-launch-antimalware):

By being launched first by the kernel, ELAM is ensured to be launched before any third-party software, and is therefore able to detect malware in the boot process and prevent it from initializing.

ELAM drivers must be specially signed by Microsoft to ensure they are started by the Windows kernel early in the boot process. To get the signature, ELAM drivers must pass a set of certification tests to verify performance and other behavior

other commands included in this category:
- Disabling location service system-wide. websites and apps won't be able to use your precise location, however they will still be able to detect your location using your IP address.
- Enabling Mandatory ASLR, [more info here](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-exploit-protection?view=o365-worldwide). it might cause problem for some unofficial 3rd party portable programs, such as Photoshop portable, Telegram portable etc. the command and ways to add exception for such programs are provided in the script file.
- Enable Hibernate and Disable Sleep, this feature is only recommended for very high-risk environments.
This is to prevent an **Attacker with skill and lengthy physical access to your computer**

Attack Scenario: Targeted attack with plenty of time; this attacker will open the case, will solder, and will use sophisticated hardware or software.
Of course [Bitlocker and configurations](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-countermeasures#attacker-with-skill-and-lengthy-physical-access) made by this script will protect you against that.
- Enable Windows update and Edge browser to download and install updates on any network, metered or not; because the updates are important and should not be suppressed, that's what bad actors would want.
## Certificate Checking Commands
In this category, the script runs [sigcheck64.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck) live from [Sysinternals ](https://learn.microsoft.com/en-us/sysinternals/), then lists valid certificates not rooted to the Microsoft Certificate Trust List in the User and Machine stores. unless you use Windows insider build, all the certificates that will be listed should be treated as dangerous and removed from your system immediately. however, if you are a Windows Insider user, like me, there will be certificates listed that belong to Microsoft and pre-public build of Windows that you use, so they are OK and should not be removed. some of those safe Windows-Insider-build related certificates that should be left alone are:
* Microsoft ECC Development Root Certificate Authority 2018
* Microsoft Development Root Certificate Authority 2014


## Country IP Blocking
The script fetches the newest range of [IPv4](https://www.ipdeny.com/ipblocks/) and [IPv6](https://www.ipdeny.com/ipv6/ipaddresses/blocks/) addresses for terrorist and terrorist supporting countries such as Russia, Iran, China and North Korea, then creates 2 rules (inbound and outbound) for each country in Windows firewall, completely blocking connections to and from those countries.



## Non-Admin Commands

In order to run commands in this category, you don't need administrator privileges, because no system-wide configuration is made. changes in this category only apply to the user account that is running the current PowerShell session:
- Show known file extensions in File explorer
- Disable websites accessing local language list - good for privacy
- Turn off safe search in Windows search, will enable +18 content to appear in searches; essentially toggles the button in: Windows settings > privacy and security > search permissions > safe search
- Enable Clipboard History and sync with Microsoft Account
- Create custom views for Windows Event Viewer to help you keep tabs on important security events
- Turn on text suggestions when typing on the physical keyboard

<h1> <br> </h1>


## Related

[PowerShell Gallery](https://www.powershellgallery.com/packages/Harden-Windows-Security/) - Also available in PowerShell Gallery


## Support

<a href="https://github.com/HotCakeX/Harden-Windows-Security/discussions">
🎯 if you have any questions, requests, suggestions etc. about this script, please open a new discussion on Github
</a>

<br />


## Security Reccomendations

* Use the latest version of the PowerShell, easiest and fastest way to install it is using <a href="https://www.microsoft.com/store/productId/9MZ1SNWT0N5D">Microsoft Store</a> but also available on <a href="https://github.com/PowerShell/PowerShell/releases">Github</a>.
* When you decide to install a program or app in Windows, first use the Microsoft Store and <a href="https://github.com/microsoft/winget-cli">Winget</a>, somebody created a nice web interface for interacting with Winget CLI <a href="https://winstall.app/">here</a>. if the program or app you are looking for isn't available in there, then download it from its official website.
* Use Secure DNS; Windows 11 natively supports <a href="https://learn.microsoft.com/en-us/windows-server/networking/dns/doh-client-support">DNS over HTTPS</a> and <a href="https://techcommunity.microsoft.com/t5/networking-blog/dns-over-tls-available-to-windows-insiders/ba-p/3565859">DNS over TLS</a>.
* Only use Microsoft Edge for browser; it's De-googled, available by default on Windows OS, has tightly integrated valuable Security features such as <a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-application-guard/md-app-guard-overview">Windows Defender Application Guard</a>, <a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-smartscreen/microsoft-defender-smartscreen-overview">Windows Defender SmartScreen</a>, <a href="https://support.microsoft.com/en-us/microsoft-edge/enhance-your-security-on-the-web-with-microsoft-edge-b8199f13-b21b-4a08-a806-daed31a1929d">Hardware Enforced Stack Protection</a>, <a href="https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exploit-protection-reference?view=o365-worldwide#arbitrary-code-guard">Arbitrary Code Guard (ACG)<a/>, <a href="https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exploit-protection-reference?view=o365-worldwide#control-flow-guard-cfg">Control Flow Guard (CFG)</a>, <a href="https://learn.microsoft.com/en-us/microsoft-edge/web-platform/tracking-prevention">Tracking Prevention</a> and <a href="https://support.microsoft.com/en-us/topic/use-the-microsoft-edge-secure-network-to-protect-your-browsing-885472e2-7847-4d89-befb-c80d3dda6318">Trusted built-in VPN from Cloudflare</a> just to name a few.
* Always enable 2FA (Two Factor Authentication) on websites, apps and services that you use. preferably, use Microsoft Authenticator app which has backup and restore feature so you never lose access to your TOTPs (Time-Based One-Time Passwords) even if you lose your phone. available for <a href="https://play.google.com/store/apps/details?id=com.azure.authenticator&gl=US">Android</a> and <a href="https://apps.apple.com/us/app/microsoft-authenticator/id983156458">IOS</a>. you can also use Microsoft Authenticator on Windows 11 (PC, Laptop or Tablet) using <a href="https://apps.microsoft.com/store/detail/windows-subsystem-for-android%E2%84%A2-with-amazon-appstore/9P3395VX91NR?hl=en-us&gl=us">Windows Subsystem for Android (WSA)</a> and access your authenticator codes without the need to use your phone (again thanks to the secure automatic backup/restore feature). use an open-source and trusted Android store such as <a href="https://auroraoss.com/">Aurora Store</a> to <a href="https://github.com/whyorean/AuroraStore">install</a> and keep it up-to-date.
* More Security Recommendations coming soon...


## Resources

- [Microsoft Learn](https://learn.microsoft.com/en-us/) - Technical Documentation
- [ADMX](https://admx.help/) - Group Policy Administrative Templates Catalog
- [GPS](https://gpsearch.azurewebsites.net/) - Group Policy Search
- [Germany Intelligence Agency - BND](https://www.bsi.bund.de/EN/Service-Navi/Publikationen/publikationen_node.html) - Federal Office for Information Security
- [Microsoft Tech Community](https://techcommunity.microsoft.com/) - Official blogs and documentations
- [Microsoft Security baselines](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines) - Security baselines from Microsoft


## License

MIT License

---

> [Microsoft Tech Community Profile](https://techcommunity.microsoft.com/t5/user/viewprofilepage/user-id/310193) &nbsp;&middot;&nbsp;
> GitHub [@HotCakeX](https://github.com/HotCakeX) &nbsp;&middot;&nbsp;
> Steam [@HotCakeX](https://steamcommunity.com/id/HotCakeX) &nbsp;&middot;&nbsp;
> Xbox: [@HottCakeX](https://account.xbox.com/en-US/Profile?Gamertag=HottCakeX)

