<a name="readme-top"></a>

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
  <a href="#Trust">Trust</a> •
  <a href="#support">Support</a> •
  <a href="#security-recommendations">Security Recommendations</a> •
  <a href="#resources">Resources</a> •
  <a href="#license">License</a> •
  <a href="https://github.com/HotCakeX/Harden-Windows-Security/wiki">Wiki</a>

</p>


<h1> <br> </h1>
</br>

> __Warning__  Windows by default is secure and safe, this script does not imply nor claim otherwise. just like anything, you have to use it wisely and don't compromise yourself with reckless behavior and bad user configuration; Nothing is foolproof. this script only uses the tools and features that have already been implemented by Microsoft in Windows OS to fine-tune it towards the highest security and locked-down state, using well-documented, supported, often recommended and official methods. continue reading for comprehensive info.

 </br>


## Hardening Categories<a href="#hardening-Categories">![HardeningCategoriesIcon]</a>

<a name="menu-back-to-top"></a>
From Top to bottom in order:

* Commands that require Administrator Privileges (click/tap on each of these to see in-depth info)
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

<p align="right"><a href="#readme-top">💡(back to top)</a></p>

## How To Use<a href="#how-to-use">![HowToUseIcon]</a>

> __Warning__ Make sure your hardware (Tablet, Laptop, PC, Phone) meets the [Windows 11 hardware requirements](https://www.microsoft.com/en-in/windows/windows-11-specifications?r=1). this script will NOT work as intended if your hardware doesn't support or use TPM 2.0, Secure Boot or Virtualization Technology (For Intel based CPUs it's called: VT-X and VT-D, VT-D is Intel's Virtualization Technology for Directed I/O). even if your CPU isn't at least Intel 8th Gen (or its AMD equivalent), you should still have the options in your UEFI firmware to turn on virtualization Technology, TPM 2.0 and Secure Boot. currently, Windows 11 allows some older than 8th Gen Intel CPUs (or their AMD equivalents) only on insider builds. you will miss a lot of new feautres, benefits and new security technologies that are only available on new hardware.
<br>
</br>

* This script requires `PowerShell 7.3`. the easiest and fastest way to install the latest version of PowerShell is using <a href="https://www.microsoft.com/store/productId/9MZ1SNWT0N5D">Microsoft Store</a> but also available on <a href="https://github.com/PowerShell/PowerShell/releases">Github</a>.

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
> Things with **#TopSecurity** tag can break functionalities or cause difficulties so this script does NOT enable them by default. press `Control + F` and search for `#TopSecurity` in this page or in the script to find those commands and how to enable them if you want. 

<p align="right"><a href="#readme-top">💡(back to top)</a></p>

## Features:<a href="#features">![FeaturesIcon]</a>

- Always up-to-date and works with latest build of Windows (Currently Windows 11 - compatible and rigorously tested on stable and Insider Dev builds)
- Doesn't break anything
- All of the links and sources are official from Microsoft websites, straight from the source. no bias, no misinformation and no old obsolete methods, that's why there are no links to 3rd party news websites, made up blogs or articles.

<details><summary>With the following exceptions</summary>
	
| Count| Link                          | Reason                                                     |
|:----:|:-----------------------------:|:----------------------------------------------------------:|
| 1    | Intel website                 | i7 13700k product page                                     |
| 2    | Wikipedia                     | providing further information for the reader               |
| 3    | gpsearch.azurewebsites.net    | showing how certain registry keys of GPolicies were found  |
| 1    | non-official Github Wiki page | providing further information for the reader about TLS     |
| 2    | Security.Stackexchange Q&A    | providing logic and reasoning for certain actions          |
| 1    | state.gov                     | List of State Sponsors of Terrorism                        |

</details>    

- Doesn't remove or disable Windows functionalities against Microsoft's recommendation
- This Readme page is used as the reference for all of the commands used in the script. the order in which they appear here is the same as the one in the script file.
- When a hardening command is no longer necessary because it's applied by default by Microsoft on new builds of Windows, it will also be removed from this script in order to prevent any problems and because it won't be necessary anymore.
- The script can be run infinite number of times, it's made in a way that it won't make any duplicate changes at all.
- Running this script makes your PC compliant with Secured-core PC specifications (providing that you use a modern hardware that supports the latest Windows security features). [See what makes a Secured-core PC](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-highly-secure#what-makes-a-secured-core-pc). <a href="#Device-Guard">Check Device Guard category for more details.</a>
  - [Secured-core](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-highly-secure) – recommended for the most sensitive systems and industries like financial, healthcare, and government agencies. Builds on the previous layers and leverages advanced processor capabilities to provide protection from firmware attacks.


<p align="right"><a href="#readme-top">💡(back to top)</a></p>

<h1> <br> </h1>


## Windows Security aka Defender<a href="#Windows-Security-aka-Defender">![WindowsDefenderIcon]</a>
- Enables **additional** security features of Windows Security (Defender), You can refer to [this official document](https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps) for full details.

- This script makes sure [Cloud Security Scan](https://support.microsoft.com/en-us/topic/what-is-a-cloud-security-scan-75112696-7660-4450-9194-d717f72a8ad8) and [Block At First Sight](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus?view=o365-worldwide#turn-on-block-at-first-sight-with-group-policy) are enabled to the highest possible security states available, **Zero Tolerance Cloud Block level**. you need to be aware that this means actions like downloading and opening an unknown file WILL make Windows Security send samples of it to the Cloud for more advanced analysis and it can take a maximum of 60 seconds (this script sets it to max) from the time you try to open that unknown file to the time when it will be opened (if deemed safe), so you will have to wait. all of these security measure are in place by default in Windows to some extent and happen automatically without the need to run this script, but this script **maxes them out and sets them to the highest possible levels** at the cost of 🔻convenience and usability.🔺it's always a trade-off.


  - Here is an example of the notification you will see in Windows 11 if that happens. 
  
  <p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Windows%20Security%20Cloud%20Analysis.png" alt="Windows Security Cloud Scan Notification" width="200"></p>
  
  
 


- Enables file hash computation; [designed](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps#-enablefilehashcomputation) to allow admins to force the anti-malware solution to "compute file hashes for every executable file that is scanned if it wasn't previously computed" to "improve blocking for custom indicators in Microsoft Defender Advanced Threat Protection (Microsoft Defender ATP).

- Clears Quarantined items after 5 days instead of the default behavior of keeping them indefinitely.

- Lets Windows Defender use up to 70% of the CPU instead of the default 50%, during scans.

- Allows Windows Defender to download security updates even on a metered connection.

- Enables Windows Defender to scan network drives, restore points, Emails and removable drives during a full scan, so it will take a while to finish a full scan if you have lots of those Items.

- Sets the Signature Update Interval to every 3 hours instead of automatically.
  - [Change logs for security intelligence updates](https://www.microsoft.com/en-us/wdsi/definitions/antimalware-definition-release-notes)
  - [Configure and validate Microsoft Defender Antivirus network connections](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-network-connections-microsoft-defender-antivirus?view=o365-worldwide)
  - [Security intelligence updates for Microsoft Defender Antivirus and other Microsoft antimalware](https://www.microsoft.com/en-us/wdsi/defenderupdates)
  - [Microsoft Safety Scanner](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/safety-scanner-download?view=o365-worldwide)

- Forces Windows Defender to check for new virus and spyware definitions before it runs a scan.

- Makes Windows Defender run [catch-up scans](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps#-disablecatchupquickscan) for scheduled quick scans. A computer can miss a scheduled scan, usually because the computer is off at the scheduled time, but now after the computer misses two scheduled quick scans, Windows Defender runs a catch-up scan the next time someone logs onto the computer.

- Enables [Network Protection of Windows Defender](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/network-protection?view=o365-worldwide) (Requires Windows Pro or Enterprise editions)

- Makes sure [Async Inspection for Network protection](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/network-protection?view=o365-worldwide#optimizing-network-protection-performance) of Windows Defender is turned on - Network protection now has a performance optimization that allows Block mode to start asynchronously inspecting long connections after they're validated and allowed by SmartScreen, which might provide a potential reduction in the cost that inspection has on bandwidth and can also help with app compatibility problems.

- 🟢 [Smart App Control:](https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003) Smart App Control adds significant protection from new and emerging threats by blocking apps that are malicious or untrusted. Smart App Control also helps to block potentially unwanted apps, which are apps that may cause your device to run slowly, display unexpected ads, offer extra software you didn't want, or do other things you don't expect.
  - Smart App Control is User-Mode [Windows Defender Application Control policy (WDAC)](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control-design-guide) for non-enterprise consumers. you can see its status in [`System Information`](https://support.microsoft.com/en-us/windows/view-your-system-info-a965a8f2-0773-1d65-472a-1e747c9ebe00) and enable it manually from Windows Security (Defender) app's GUI. it is very important for Windows and Windows Defender intelligence updates to be always new in order for Smart App Control to work properly as it relies on live intelligence and definition data from the cloud and other sources to make a Smart decision about programs and files it encounters.
  - Smart App Control uses [ISG (Intelligent Security Graph)](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/use-windows-defender-application-control-with-intelligent-security-graph#how-does-wdac-work-with-the-isg). The ISG isn't a "list" of apps. Rather, it uses the same vast security intelligence and machine learning analytics that power Microsoft Defender SmartScreen and Microsoft Defender Antivirus to help classify applications as having "known good", "known bad", or "unknown" reputation. This cloud-based AI is based on trillions of signals collected from Windows endpoints and other data sources, and processed every 24 hours. As a result, the decision from the cloud can change.
  -  Smart App Control can block a program entirely from running or only [some parts of it](https://support.microsoft.com/en-us/topic/smart-app-control-has-blocked-part-of-this-app-0729fff1-48bf-4b25-aa97-632fe55ccca2) in which case your app or program will continue working just fine most of the time. It's improved a lot since it was introduced, and it continues doing so. It's got so smart now that I enable it on new OS installations immediately after updating.
  - Smart App Control enforces the [Microsoft Recommended Driver Block rules](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules) and the [Microsoft Recommended Block Rules](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)
  - The script [enables Smart App Control](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control#wdac-and-smart-app-control), it will ask for confirmation before enabling it.
  - Once you turn Smart App Control off, it can't be turned on without resetting or reinstalling Windows.

- 🟣 There is another Security feature, for Ransomware Protection, that's been in Windows for a while and it's called [Controlled Folder Access](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-controlled-folders). **This script does not enable it. the default state is disabled.**
  - [Protect important folders with controlled folder access](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/controlled-folders): Controlled folder access helps protect your valuable data from malicious apps and threats, such as ransomware. Controlled folder access protects your data by checking apps against a list of known, trusted apps.
  - If it blocks a program from accessing one of your folders it protects, and you absolutely trust that program, then you can add it to exclusion list using Windows Security (Defender) GUI or PowerShell. you can also query the list of allowed apps using PowerShell (commands below). with these commands, you can backup your personalized list of allowed apps, that are relevant to your system, and restore them in case you clean install your Windows.


```PowerShell
# Add multiple programs to the exclusion list of Controlled Folder Access
Set-MpPreference -ControlledFolderAccessAllowedApplications 'C:\Program Files\App\app.exe','C:\Program Files\App2\app2.exe'
```


```PowerShell

# Get the list of all allowed apps
$(get-MpPreference).ControlledFolderAccessAllowedApplications
```


<p align="right"><a href="#menu-back-to-top">💡(back to categories)</a></p>

## Attack surface reduction rules<a href="#Attack-surface-reduction-rules">![ASRrulesIcon]</a>
[Reducing your attack surface](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction) means protecting your devices and network, which leaves attackers with fewer ways to perform attacks. Configuring attack surface reduction rules in Windows can help!

[Attack surface reduction rules](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide) target certain software behaviors, such as:

 - Launching executable files and scripts that attempt to download or run files
 - Running obfuscated or otherwise suspicious scripts
 - Performing behaviors that apps don't usually initiate during normal day-to-day work

Such software behaviors are sometimes seen in legitimate applications. However, these behaviors are often considered risky because they are commonly abused by attackers through malware. Attack surface reduction rules can constrain software-based risky behaviors and help keep your organization safe.


This script enables [all 16 available Attack Surface Reduction rules shown in the official chart](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#asr-rule-to-guid-matrix), You can manually turn off any of them by changing them from `Enabled` to `AuditMode` or `Disabled` in the script.

<p align="right"><a href="#menu-back-to-top">💡(back to categories)</a></p>

## Bitlocker Settings<a href="#Bitlocker-Settings">![BitlockerIcon]</a>

- This script sets up and configures Bitlocker, for OS drive and all other drives on the device (including any connected USB storage devices) [using official documentation](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings), with the most secure configuration and Military Grade encryption algorithm, **XTS-AES-256, TPM 2.0 and start-up PIN**. 

- You will be asked to enter a Startup PIN when activating Bitlocker for the first time. make sure the PIN you enter is at least 6 digits. since this script enables Enhanced Startup PIN, you can use characters including uppercase and lowercase letters, symbols, numbers, and spaces. make sure the Bitlocker PIN that you choose is not the same as your Windows Hello PIN.

- Once you run this script for the first time, there will be a text file containing the 48-digit recovery password for each encrypted drive that will be saved in itself, with the names like `Drive C recovery password.txt`. it is 🔻very important to keep it in a safe and reachable place, e.g. in OneDrive's Personal Vault which requires authentication to access. see [Here](https://www.microsoft.com/en-us/microsoft-365/onedrive/personal-vault) and [Here](https://support.microsoft.com/en-us/office/protect-your-onedrive-files-in-personal-vault-6540ef37-e9bf-4121-a773-56f98dce78c4) for more info about OneDrive's Personal Vault🔺

  - Check out <a href="#Lock-Screen">Lock Screen</a> category for more info about the recovery password.

  - Also check out <a href="#Miscellaneous-Configurations">Miscellaneous Configurations</a> category for more info about how Bitlocker protects your device and data against an Attacker with skill and lengthy physical access, which is **worst-case scenario**.
  - To have even more security than what the script provides, you can utilize a [Startup key in addition to the other 3 key protectors](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-countermeasures#pre-boot-authentication) (TPM, Startup PIN and Recovery password). with this method, part of the encryption key is stored on a USB flash drive, and a PIN is required to authenticate the user to the TPM. This configuration **provides multifactor authentication** so that if the USB key is lost or stolen, it can't be used for access to the drive, because the correct PIN is also required.




- BitLocker will bring you a real security against the theft of your device if you strictly abide by the following basic rules:
   - As soon as you have finished working, either Hibernate or shut Windows down and allow for every shadow of information to disappear from RAM within 2 minutes. **🔺this practice is recommended in High-Risk Environments.🔻**

  - Do not mix 3rd party encryption software and tools with Bitlocker. Bitlocker creates a secure end-to-end encrypted ecosystem for your device and its peripherals, this secure ecosystem is backed by things such as software, Virtualization Technology, TPM 2.0 and UEFI firmware, Bitlocker protects your data and entire device against **real-life attacks and threats**. You can encrypt your external SSDs and flash drives with Bitlocker too.


Refer to this [official documentation about the countermeasures of Bitlocker](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-countermeasures)

- Enables or disables [DMA protection from Bitlocker Countermeasures](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-countermeasures#protecting-thunderbolt-and-other-dma-ports) based [on the status](https://github.com/MicrosoftDocs/windows-itpro-docs/issues/6878#issuecomment-742429128) of [Kernel DMA protection](https://learn.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt). Kernel DMA Protection is [not compatible](https://learn.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt#system-compatibility) with other BitLocker DMA attacks countermeasures. It is recommended to [disable the BitLocker DMA](https://gpsearch.azurewebsites.net/#13639) attacks countermeasures if the system supports Kernel DMA Protection (this script does that exactly). Kernel DMA Protection provides higher security bar for the system over the BitLocker DMA attack countermeasures, while maintaining usability of external peripherals. you can check the status of Kernel DMA protection [using this official guide](https://learn.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt#how-to-check-if-kernel-dma-protection-is-enabled).
  - [Kernel DMA Protection (Memory Access Protection) for OEMs](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-kernel-dma-protection) page shows the requirements for Kernel DMA Protection. for Intel CPUs, support for requirements such as VT-X and VT-D can be found in each CPU's respective product page. e.g. [Intel i7 13700K](https://ark.intel.com/content/www/us/en/ark/products/230500/intel-core-i713700k-processor-30m-cache-up-to-5-40-ghz.html)

- Disallow standard (Non-Administrator) users from changing the Bitlocker Startup PIN or password

- [Allow Enhanced PINs for startup](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings#allow-enhanced-pins-for-startup)

<p align="right"><a href="#menu-back-to-top">💡(back to categories)</a></p>

## TLS Security<a href="#TLS-Security">![TLSIcon]</a>
This script disables TLS 1 and TLS 1.1 security protocols that only **exist for backward compatibility**. all modern software should and do use `TLS 1.2` and `TLS 1.3`.

Changes made by the script only affect things that use [Schannel SSP](https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-): that includes Edge, IIS web server, built-in inbox Windows apps and some other programs supplied by Microsoft, but not 3rd party software that use [portable stacks](https://en.wikipedia.org/wiki/Comparison_of_TLS_implementations#Portability_concerns) like Java, nodejs, python or php.

if you want to read more: [Demystifying Schannel](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/demystifying-schannel/ba-p/259233)

- Enables `TLS_CHACHA20_POLY1305_SHA256` cipher Suite which is [available but not enabled](https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-11) by default in Windows 11, and sets its priority to highest.

- Enables the following secure Diffie-Hellman based key exchange algorithms which are available in Windows 11 but not enabled by default, [according to this Microsoft Document](https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-11): `"TLS_DHE_RSA_WITH_AES_256_CBC_SHA"`,`"TLS_DHE_RSA_WITH_AES_128_CBC_SHA"`,`"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"`

- Disables `NULL` ciphers that are **only available for backward compatibility**:`"TLS_RSA_WITH_NULL_SHA256"`,`"TLS_RSA_WITH_NULL_SHA"`,`"TLS_PSK_WITH_NULL_SHA384"`,`"TLS_PSK_WITH_NULL_SHA256"`

- Disables [MD5 Hashing Algorithm](https://security.stackexchange.com/questions/52461/how-weak-is-md5-as-a-password-hashing-function) that is **only available for backward compatibility**

- Disables the following [weak cipher suites](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices) that are **only available for backward compatibility**: `"TLS_RSA_WITH_AES_256_GCM_SHA384"`,`"TLS_RSA_WITH_AES_128_GCM_SHA256"`,`"TLS_RSA_WITH_AES_256_CBC_SHA256"`,`"TLS_RSA_WITH_AES_128_CBC_SHA256"`,`"TLS_RSA_WITH_AES_256_CBC_SHA"`,`"TLS_RSA_WITH_AES_128_CBC_SHA"`,`"TLS_PSK_WITH_AES_256_GCM_SHA384"`,`"TLS_PSK_WITH_AES_128_GCM_SHA256"`,`"TLS_PSK_WITH_AES_256_CBC_SHA384"`,`"TLS_PSK_WITH_AES_128_CBC_SHA256"`

- Disables the following [weak ciphers](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices) that are **only available for backward compatibility**: `"DES 56-bit"`,`"RC2 40-bit"`,`"RC2 56-bit"`,`"RC2 128-bit"`,`"RC4 40-bit"`,`"RC4 56-bit"`,`"RC4 64-bit"`,`"RC4 128-bit"`,`"3DES 168-bit (Triple DES 168)"`

<p align="right"><a href="#menu-back-to-top">💡(back to categories)</a></p>

## Lock Screen<a href="#Lock-Screen">![LockScreenIcon]</a>

- [Automatically locks device after X seconds of inactivity](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-machine-inactivity-limit) (just like mobile phones), which is set to 120 seconds (2 minutes) in this script, you can change that to any value you like.

- [Require `CTRL+ALT+DEL` on the lock screen](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-do-not-require-ctrl-alt-del), the reason and logic behind it is:

  - A malicious user might install malware that looks like the standard sign-in dialog box for the Windows operating system and capture a user's password. The attacker can then sign into the compromised account with whatever level of user rights that user has.

- Enables a [security feature](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-machine-account-lockout-threshold) that sets a threshold (6 in this script) for the number of failed sign-in attempts that causes the device to be locked by using BitLocker. This threshold means, if the specified maximum number of failed sign-in attempts is exceeded, the device will invalidate the Trusted Platform Module (TPM) protector and any other protector except the 48-digit recovery password, and then reboot. During Device Lockout mode, the computer or device only boots into the touch-enabled Windows Recovery Environment (WinRE) until an authorized user enters the recovery password to restore full access.
  - This Script (<a href="#Bitlocker-Settings">in the Bitlocker category</a>) automatically saves the 48-digit recovery password of each drive in itself, the location of it will also be visible on the PowerShell console when you run it. it is 🔻very important to keep it in a safe and reachable place, e.g. in OneDrive's Personal Vault which requires authentication to access. see [Here](https://www.microsoft.com/en-us/microsoft-365/onedrive/personal-vault) and [Here](https://support.microsoft.com/en-us/office/protect-your-onedrive-files-in-personal-vault-6540ef37-e9bf-4121-a773-56f98dce78c4) for more info about OneDrive's Personal Vault🔺

- [Hides email address of the Microsoft account on lock screen](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-display-user-information-when-the-session-is-locked), if your device is in a trusted place like at home then this isn't necessary.

- [Don't display username at sign-in](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-dont-display-username-at-sign-in); If a user signs in as Other user, the full name of the user isn't displayed during sign-in. In the same context, if users type their email address and password at the sign-in screen and press Enter, the displayed text "Other user" remains unchanged, and is no longer replaced by the user's first and last name, as in previous versions of Windows 10. Additionally,if users enter their domain user name and password and click Submit, their full name isn't shown until the Start screen displays.
  - [Useful](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-dont-display-username-at-sign-in#best-practices) If you have devices that store sensitive data, with monitors displayed in unsecured locations, or if you have devices with sensitive data that are remotely accessed, revealing logged on user's full names or domain account names

- [Don't display last signed-in](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-do-not-display-last-user-name); This security policy setting determines whether the name of the last user to sign in to the device is displayed on the Secure Desktop. If this policy is enabled, the full name of the last user to successfully sign in isn't displayed on the Secure Desktop, nor is the user's sign-in tile displayed. Additionally, if the Switch user feature is used, the full name and sign-in tile aren't displayed. The sign-in screen requests a qualified domain account name (or local user name) and password. 
  - Users will need to manually enter username and password/Pin to sign in. **it can cause annoyance, so disabled in this script**. this feature however can be useful to enable if you live in 🔻High-Risk Environments🔺 and you don't want Anyone to get Any information about your device when it's locked and you're not around. if you want to enable it, change its value to 1. 🔻#TopSecurity🔺

- [Don't Display Network Selection UI on Lock Screen](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowslogon#dontdisplaynetworkselectionui) (like WIFI Icon); This setting allows you to control whether anyone can interact with available networks UI on the logon screen. once enabled, the devicees's network connectivity state cannot be changed without signing into Windows. suitable for🔻High-Risk Environments🔺

<p align="right"><a href="#menu-back-to-top">💡(back to categories)</a></p>

## User Account Control<a href="#User-Account-Control">![UACIcon]</a>

Here is [the official reference](https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#registry-key-settings) for the commands used in this section of the script, User Account Control Group Policy and registry key settings.

- Makes all prompts for elevation to use [secure desktop](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation#reference) which presents the sign-in UI and restricts functionality and access to the system until the sign-in requirements are satisfied. The secure desktop's primary difference from the user desktop is that only trusted processes running as SYSTEM are allowed to run here (that is, nothing is running at the user's privilege level). The path to get to the secure desktop from the user desktop must also be trusted through the entire chain.

- Introduces (but Not enables, because [it can cause inconvenience](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-only-elevate-executables-that-are-signed-and-validated#potential-impact)) a feature that [Enforces cryptographic signatures on any interactive application](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-only-elevate-executables-that-are-signed-and-validated) that requests elevation of privilege. it can prevent certain programs from running or prompting for UAC. 🔻#TopSecurity🔺

- Introduces (but Not enables) an option to [automatically deny all UAC prompts on Standard accounts](https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users). suitable for forcing log out of Standard account and logging in Admin account to perform administrator actions, or switching to Admin account to perform elevated tasks. 🔻#TopSecurity🔺


<p align="right"><a href="#menu-back-to-top">💡(back to categories)</a></p>

## Device Guard<a href="#Device-Guard">![DeviceGuardIcon]</a>

**Most of the Device Guard and Virtualization-Based Security features are Automatically enabled by default** on capable and modern hardware, this script only checks their status and if needed, enables UEFI lock for them and also proceeds with enabling [**full Secured-Core PC requirements**:](https://www.microsoft.com/en-us/windows/business/windows-11-secured-core-computers)
- [Makes sure Virtualization-Based Security is Enabled](https://learn.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity)
  - [Validate enabled Windows Defender Device Guard hardware-based security features](https://learn.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity#validate-enabled-windows-defender-device-guard-hardware-based-security-features)
- [Requires Secure boot and DMA protection for Virtualization-Based Security](https://learn.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt)
- Turns on UEFI lock for Virtualization-Based Security
- Makes sure Virtualization-based protection of Code Integrity policies is Enabled
- Turns on UEFI lock for virtualization-based protection of Code Integrity policies
- [Require UEFI Memory Attributes Table](https://github.com/microsoft/MSLab/blob/master/Scenarios/DeviceGuard/VBS/readme.md)
- [Enables Windows Defender Credential Guard with UEFI Lock](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage#enable-virtualization-based-security-and-windows-defender-credential-guard)
  - [Windows Defender Device Guard and Windows Defender Credential Guard hardware readiness tool](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/dg-readiness-tool)
  - [Windows Defender Credential Guard requirements](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-requirements)
- [Enables System Guard Secure Launch and SMM protection](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/system-guard-secure-launch-and-smm-protection#registry)
  - [How to verify System Guard Secure Launch is configured and running](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/system-guard-secure-launch-and-smm-protection#how-to-verify-system-guard-secure-launch-is-configured-and-running)
- [Kernel Mode Hardware Enforced Stack Protection](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/windows-11-version-22h2-security-baseline/ba-p/3632520)

<br>
<br>
<br>

#### [Device protection in Windows Security gives you one of these 4 hardware scores:](https://support.microsoft.com/en-us/windows/device-protection-in-windows-security-afa11526-de57-b1c5-599f-3a4c6a61c5e2)
<ol>
<li>Standard hardware security not supported</li>
	<ul>
	<li>This means that your device does not meet at least one of the requirements of Standard Hardware Security.</li>
	</ul>
<li>Your device meets the requirements for Standard Hardware Security. </li>
	<ul>
	<li><a href="https://support.microsoft.com/en-us/topic/what-is-tpm-705f241d-025d-4470-80c5-4feeb24fa1ee">TPM 2.0</a></li>
	<li><a href="https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot">Secure boot</a></li>
	<li><a href="https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention">DEP</a></li>
	<li><a href="https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/unified-extensible-firmware-interface">UEFI MAT</a></li>
	</ul>
<li>Your device meets the requirements for Enhanced Hardware Security</li>
	<ul>
	<li><a href="https://support.microsoft.com/en-us/topic/what-is-tpm-705f241d-025d-4470-80c5-4feeb24fa1ee">TPM 2.0</a></li>
	<li><a href="https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot">Secure boot</a></li>
	<li><a href="https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention">DEP</a></li>
	<li><a href="https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/unified-extensible-firmware-interface">UEFI MAT</a></li>
	<li><a href="https://support.microsoft.com/en-us/windows/core-isolation-e30ed737-17d8-42f3-a2a9-87521df09b78">Memory Integrity</a></li>
	</ul>
<li>Your device has all Secured-core PC features enabled</li>
	<ul>
	<li><a href="https://support.microsoft.com/en-us/topic/what-is-tpm-705f241d-025d-4470-80c5-4feeb24fa1ee">TPM 2.0</a></li>
	<li><a href="https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot">Secure boot</a></li>
	<li><a href="https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention">DEP</a></li>
	<li><a href="https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/unified-extensible-firmware-interface">UEFI MAT</a></li>
	<li><a href="https://support.microsoft.com/en-us/windows/core-isolation-e30ed737-17d8-42f3-a2a9-87521df09b78">Memory Integrity</a></li>
	<li><a href="https://www.microsoft.com/en-us/security/blog/2020/11/12/system-management-mode-deep-dive-how-smm-isolation-hardens-the-platform/">System Management Mode (SMM)</a></li>
	</ul>
</ol>


<p align="right"><a href="#menu-back-to-top">💡(back to categories)</a></p>

## Windows Firewall<a href="#Windows-Firewall">![FirewallIcon]</a>
- Makes sure Windows Firewall is enabled for all profiles (which is the default)

- Sets inbound and outbound default actions for Domain Firewall Profile to Block; because this script is Not intended to be used on devices that are part of a domain or controlled by an Active Directory Domain Controller, since they will have their own policies and policy management systems in place.

- Enables Windows Firewall logging for Private and Public profiles, sets the log file size to max `32.767 MB`, logs only dropped packets.

- Disables [Multicast DNS (mDNS) UDP-in Firewall Rules for all 3 Firewall profiles](https://techcommunity.microsoft.com/t5/networking-blog/mdns-in-the-enterprise/ba-p/3275777), This might interfere with Miracast screen sharing, which relies on the Public profile, and homes where the Private profile is not selected, but it does add an extra measure of security in public places, like a coffee shop.
  - The domain name `.local` which is used in mDNS (Multicast DNS) [is a special-use domain name reserved by the Internet Engineering Task Force (IETF)](https://en.wikipedia.org/wiki/.local) so that **it may not be installed as a top-level domain in the Domain Name System (DNS) of the Internet.**



<p align="right"><a href="#menu-back-to-top">💡(back to categories)</a></p>

## Optional Windows Features<a href="#Optional-Windows-Features">![OptionalFeaturesIcon]</a>

- This script disables some rarely used features in [Windows optional features](https://learn.microsoft.com/en-us/windows/application-management/add-apps-and-features#use-windows-powershell-to-disable-specific-features):
  - PowerShell v2; because it's old and doesn't support [AMSI](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/#antimalware-scan-interface-integration)
  - Work Folders client; not used when your computer is not part of a domain or enterprise network
  - Internet Printing Client; used in combination with IIS web server, [old feature](https://learn.microsoft.com/en-us/troubleshoot/windows-server/printing/manage-connect-printers-use-web-browser), can be disabled without causing problems further down the road
  - Windows Media Player (legacy); isn't needed anymore, Windows 11 has a modern media player app.

- Also enables these optional features:
  - [Windows Defender Application Guard](https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-application-guard/md-app-guard-overview); which is a safe Environment to open untrusted websites
  - [Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-sandbox/windows-sandbox-overview); install, test and use programs in a disposable virtual operation system, completely separate from your  main OS
  - Hyper-V; the best and a hybrid hypervisor (Type 1 and Type 2) to run virtual machines on. [check out this Hyper-V Wiki page](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Hyper-V)
  - Virtual Machine Platform; required for [Android subsystem or WSA (Windows subsystem for Android)](https://learn.microsoft.com/en-us/windows/android/wsa/). if it's disabled, it will be automatically enabled either way when you try to install WSA from Store app

<p align="right"><a href="#menu-back-to-top">💡(back to categories)</a></p>

## Windows Networking<a href="#Windows-Networking">![NetworkingIcon]</a>
These are configurations that are typically 🔺recommended in High-Risk Environments🔻 but also can be applied for home users

- [Disabling NetBIOS over TCP/IP](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-netbt-interfaces-interface-netbiosoptions) on all network interfaces, virtual and physical. This command needs to run every time after installing a new VPN software or network adapater.
- Disabling the LLMNR protocol [(Link Local Multicast Name Resolution)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-llmnrp/eed7fe96-9013-4dec-b14f-5abf85545385) because it's only [useful for networks that do not have a Domain Name System (DNS) server](https://learn.microsoft.com/en-us/previous-versions//bb878128(v=technet.10)?redirectedfrom=MSDN) and Microsoft themselves are [ramping down NetBIOS name resolution and LLMNR.](https://techcommunity.microsoft.com/t5/networking-blog/aligning-on-mdns-ramping-down-netbios-name-resolution-and-llmnr/ba-p/3290816)

- Disabling [LMHOSTS lookup protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbte/bec3913a-c359-4e6f-8c7e-40c2f43f546b#gt_5f0744c1-5105-4e4a-b71c-b9c7ecaed910) on all network adapters, legacy feature that's not used anymore.
- Setting the Network Location of all connections to Public; [Public network means less trust to other network devices](https://support.microsoft.com/en-us/windows/make-a-wi-fi-network-public-or-private-in-windows-0460117d-8d3e-a7ac-f003-7a0da607448d).
- Disable [Printing over HTTP](https://learn.microsoft.com/en-us/troubleshoot/windows-server/printing/manage-connect-printers-use-web-browser) because HTTP is not encrypted and it's an old feature that's not used anymore.
- [Turns off downloading of print drivers over HTTP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-connectivity#connectivity-disabledownloadingofprintdriversoverhttp) because HTTP is not encrypted and that method isn't used anymore. [This is the recommended and secure way of downloading printer drivers in Windows 11](https://support.microsoft.com/en-us/windows/download-printer-drivers-in-windows-da9b1460-7299-4cc3-e974-33cf99d86880).
- Disables [IP Source Routing](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd349797(v=ws.10)#disableipsourcerouting); Source routing allows a computer that sends a packet to specify the route that the packet takes. Attackers can use source routed packets to obscure their identity and location.
  - After applying this and restarting your device, `Source Routing Behavior` in `netsh int IPv4 show global` shows `Drop` instead of the default `dontforward` value (in [Windows 11 dev build 25272](https://blogs.windows.com/windows-insider/2023/01/05/announcing-windows-11-insider-preview-build-25272/)).

- Allows the device to [ignore NetBIOS name release requests.](https://support.microsoft.com/en-us/topic/security-configuration-guidance-support-ea9aef24-347f-15fa-b94f-36f967907f2f) This setting is a good preventive measure for denial of service attacks against name servers and other very important server roles.



<p align="right"><a href="#menu-back-to-top">💡(back to categories)</a></p>

## Miscellaneous Configurations<a href="#Miscellaneous-Configurations">![MiscellaneousIcon]</a>
- Sets [Early launch antimalware](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-driver-requirements) engine's status to `8` which is **Good only.** The [default value](https://gpsearch.azurewebsites.net/#7437) is `3`, which allows good, unknown and 'bad but critical'. that is the default value, because setting it to `8` [can prevent your computer from booting](https://learn.microsoft.com/en-us/windows/compatibility/early-launch-antimalware#mitigation) if the driver it relies on is critical but at the same time unknown or bad.

  - By being launched first by the kernel, ELAM is ensured to be launched before any third-party software and is therefore able to detect malware in the boot process and prevent it from initializing. ELAM drivers must be specially signed by Microsoft to ensure they are started by the Windows kernel early in the boot process.

- Disabling location service system wide. websites and apps won't be able to use your precise location, however they will still be able to detect your location using your IP address.

- Enables Hibernate, [sets it to full](https://learn.microsoft.com/en-us/windows/win32/power/system-power-states#hibernation-file-types), adds Hibernate to Start menu's power options and disables Sleep. this feature is only 🔺recommended for High-Risk Environments.🔻
This is to prevent an 🔺**Attacker with skill and lengthy physical access to your computer**🔻**which is the Worst-case Scenario**

  - Attack Scenario: Targeted attack with plenty of time; this attacker will open the case, will solder, and will use sophisticated hardware or software. Of course, [Bitlocker and configurations](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-countermeasures#attacker-with-skill-and-lengthy-physical-access) applied by this script will protect you against that.
  - [Power states S1-S3 will be disabled](https://learn.microsoft.com/en-us/windows/win32/power/system-power-states#sleep-state-s1-s3) in order to completely disable Sleep, doing so also removes the Sleep option from Start menu and even using commands to put the computer to sleep won't work. [2 registry keys](https://gpsearch.azurewebsites.net/#2166) are required to be used to disable Sleep. You will have to restart your device for the changes to take effect.

- Enabling [Mandatory ASLR,](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-exploit-protection?view=o365-worldwide) 🔻It might cause compatibility issues🔺 for some unofficial 3rd party portable programs, such as Photoshop portable, Telegram portable etc. or some software installers.
  - You can add Mandatory ASLR override for a trusted program using the PowerShell command below or in the Program Settings section of Exploit Protection in Windows Security (Defender) app.
  - `Set-ProcessMitigation -Name "C:\TrustedApp.exe" -Disable ForceRelocateImages`
  - [There are more options for Exploit Protection](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-exploit-protection?view=o365-worldwide) but enabling them requires extensive reviewing by users because mixing them up can cause a lot of compatibility issues.

- Enables [`svchost.exe` mitigations.](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-servicecontrolmanager) built-in system services hosted in `svchost.exe` processes will have stricter security policies enabled on them. These stricter security policies include a policy requiring all binaries loaded in these processes to be signed by Microsoft, and a policy disallowing dynamically generated code.
  - Requires Business (e.g. [Windows 11 pro for Workstations](https://www.microsoft.com/en-us/windows/business/windows-11-pro-workstations)), [Enterprise](https://www.microsoft.com/en-us/microsoft-365/windows/windows-11-enterprise) or [Education](https://www.microsoft.com/en-us/education/products/windows) Windows licenses

- Turns on Enhanced mode search for Windows indexer. the default is classic mode. 
  - this causes some UI elements in the search settings in Windows settings to become unavailable for Standard user accounts to view, because it will be a managed feature by an Administrator.

- [Enforce the Administrator role for adding printer drivers](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/devices-prevent-users-from-installing-printer-drivers)

- Enables [SMB/LDAP Signing](https://techcommunity.microsoft.com/t5/storage-at-microsoft/configure-smb-signing-with-confidence/ba-p/2418102)
- Enables [SMB Encryption](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security) (the status of `(get-SmbServerConfiguration).EncryptData` was `$False` when tested on [Windows 11 dev build 25272](https://blogs.windows.com/windows-insider/2023/01/05/announcing-windows-11-insider-preview-build-25272/), this script sets it to `$True`)

- Enable Windows update and Edge browser to download and install updates on any network, metered or not; because the updates are important and should not be suppressed, **that's what bad actors would want.**

- Enables "notify me when a restart is required to finish updating" in Windows Update, responsible for the toggle in Windows settings => Windows Update => Advanced options

- [Enables all Windows users to use Hyper-V and Windows Sandbox](https://learn.microsoft.com/en-us/archive/blogs/virtual_pc_guy/why-do-you-have-to-elevate-powershell-to-use-hyper-v-cmdlets) by adding all Windows users to the "Hyper-V Administrators" security group, by default only Administrators can use Hyper-V or Windows Sandbox. 

- Changes Windows time sync interval from the default every 7 days to every 4 days (= every 345600 seconds)

- Enables UEFI Lock for Local Security Authority (LSA) process Protection. [it is turned on by default on new Windows 11 installations](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#automatic-enablement) but not with UEFI Lock. When this setting is used with UEFI lock and Secure Boot, additional protection is achieved because disabling its registry key will have no effect.
  - when this feature is on, a new option called "Local Security Authority Protection" appears in Windows Security GUI => Device Security => Core Isolation



<p align="right"><a href="#menu-back-to-top">💡(back to categories)</a></p>

## Certificate Checking Commands<a href="#Certificate-Checking-Commands">![CertificateIcon]</a>
In this category, the script runs [sigcheck64.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck) live from [Sysinternals ](https://learn.microsoft.com/en-us/sysinternals/), then lists valid certificates not rooted to the Microsoft Certificate Trust List in the User and Machine stores. unless you use Windows insider build, all the certificates that will be listed should be treated as dangerous and removed from your system immediately. however, if you are a Windows Insider user, like me, there will be certificates listed that belong to Microsoft and pre-public build of Windows that you use, so they are OK and should not be removed. some of those safe Windows-Insider-build related certificates that should be left alone are:
* Microsoft ECC Development Root Certificate Authority 2018
* Microsoft Development Root Certificate Authority 2014

<p align="right"><a href="#menu-back-to-top">💡(back to categories)</a></p>

## Country IP Blocking<a href="#Country-IP-Blocking">![CountryIPBlockingIcon]</a>
The script fetches the newest range of [IPv4](https://www.ipdeny.com/ipblocks/) and [IPv6](https://www.ipdeny.com/ipv6/ipaddresses/blocks/) addresses of [State Sponsors of Terrorism](https://www.state.gov/state-sponsors-of-terrorism/) then creates 2 rules (inbound and outbound) for each country in Windows firewall, completely blocking connections to and from those countries.

Once you have those Firewall rules added, you can [use this method](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Event-Viewer#how-to-identify-which-windows-firewall-rule-is-responsible-for-a-blocked-packets) to see if any of the blocked connections were from/to those countries.

<p align="right"><a href="#menu-back-to-top">💡(back to categories)</a></p>

## Non-Admin Commands<a href="#non-admin-commands">![NonAdminIcon]</a>

In order to run commands in this category, you don't need administrator privileges, because no system-wide configuration is made. changes in this category only apply to the user account that is running the current PowerShell session:
- Show known file extensions in File explorer
- Show hidden files, folders and drives (toggles the control panel folder options item)
- Disable websites accessing local language list - good for privacy
- Turn off safe search in Windows search, will enable +18 content to appear in searches; essentially toggles the button in: Windows settings > privacy and security > search permissions > safe search
- prevent showing notifications in Lock screen - this is the same as toggling the button in Windows settings > system > notifications > show notifications in the lock screen
- Enable Clipboard History and sync with Microsoft Account
- Create custom views for Windows Event Viewer to help you keep tabs on important security events: attack surface reduction rules events, controlled folder access events, exploit protection events, network protection events, MSI and Scripts for WDAC Auditing events, Sudden Shut down events and Code Integrity Operational events. 
- Turn on text suggestions when typing on the physical keyboard
- Turn on "Multilingual text suggestions" for the current user, toggles the option in Windows settings
- Turn off sticky key shortcut of pressing shift key 5 times fast


<h1> <br> </h1>

<p align="right"><a href="#menu-back-to-top">💡(back to categories)</a></p>

## Related<a href="#related">![RelatedIcon]</a>

[PowerShell Gallery](https://www.powershellgallery.com/packages/Harden-Windows-Security/) - Also available in PowerShell Gallery

## Trust<a href="#trust">![TrustIcon]</a>

How can you 100% trust this script and know that nothing shady is going on?
- The script is in plain-text, nothing hidden
- Change log history is present on GitHub
- You can open the file in [Visual Studio Code](https://code.visualstudio.com/)/[Visual Studio Code Web](https://vscode.dev/), which is the best and view the script in a nice easy to read environment, I've included a lot of spacing in the script file for this purpose
- You can learn PowerShell which is super easy, multiplatform, and useful for the future, Microsoft Learn website teaches you everything, then you will understand everything in the script is safe, or you can ask someone that you trust and knows PowerShell to verify the script for you




<p align="right"><a href="#readme-top">💡(back to top)</a></p>

## Support<a href="#support">![SupportIcon]</a>

<a href="https://github.com/HotCakeX/Harden-Windows-Security/discussions">
🎯 if you have any questions, requests, suggestions etc. about this script, please open a new discussion on Github
</a>
<br>
<br>
<br />

<p align="right"><a href="#readme-top">💡(back to top)</a></p>

## Security Recommendations<a href="#security-recommendations">![SecurityRecommendationIcon]</a>

* Always download your operation system from [official Microsoft websites](https://www.microsoft.com/en-us/software-download). right now, Windows 11 is the latest version of Windows, its ISO file can be downloaded from this [official Microsoft server](https://www.microsoft.com/en-us/software-download/windows11). One of the the worst things you can do to your own security and privacy is downloading your OS, which is the root of all the active and passive security measures, **from a 3rd party website** **claiming** they have the official unmodified files. there are countless bad things that can happen as the result of it such as threat actors embedding malware or backdoors inside the customized OS, or pre-installing customized root CA certificates in your OS so that they can perform TLS termination and view all of your HTTPS and encrypted Internet data in plain clear text, **even if you use VPN.** having a poisoned and compromised certificate store is the end-game for you, and _that's just the tip of the iceberg._
  - Refer to [Wiki](https://github.com/HotCakeX/Harden-Windows-Security/wiki) to see [how to create Bootable USB flash drive with no 3rd party tools](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Bootable-USB-flash-drive-with-no-3rd-party-tools)
* Whenever you want to install a program or app, first use the [Microsoft Store](https://apps.microsoft.com/store/apps) or <a href="https://github.com/microsoft/winget-cli">Winget</a>, if the program or app you are looking for isn't available in there, then download it from its official website. _somebody created a nice web interface for interacting with Winget CLI <a href="https://winstall.app/">here</a>._ using Winget or Microsoft store provides many benefits:
  - Microsoft store UWP apps are secure in nature, digitally signed, in [MSIX format](https://learn.microsoft.com/en-us/windows/msix/overview). that means, installing and uninstalling them is guaranteed and there won't be any leftover after uninstall. 
  - Microsoft store has Win32 apps too, they are traditional `.exe` installers that we are all familiar with. the store has library feature that makes it easy to find apps you previous installed.
  - both Microsoft and Winget check the hash of the files by default, if a program or file is tampered, they will warn you and block the installation, whereas when you manually download a program from a website, you will have to manually verify the file hash with the hash shown in the website, If Any.
* Use Secure DNS; Windows 11 natively supports <a href="https://learn.microsoft.com/en-us/windows-server/networking/dns/doh-client-support">DNS over HTTPS</a> and <a href="https://techcommunity.microsoft.com/t5/networking-blog/dns-over-tls-available-to-windows-insiders/ba-p/3565859">DNS over TLS</a>.
  - I've created a PowerShell module to use a **DNS over HTTPS server that doesn't have a stable IP address**, on Windows 11, [feel free to check it out](https://github.com/HotCakeX/Set-DynamicIPDoHServer).
* Only use Microsoft Edge for browser; It has [the Highest-rated protection against phishing and malware](https://learn.microsoft.com/en-us/deployedge/ms-edge-security-for-business#highest-rated-protection-against-phishing-and-malware), it's De-googled, available by default on Windows OS, has tightly integrated valuable Security features such as <a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-application-guard/md-app-guard-overview">Windows Defender Application Guard</a>, <a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-smartscreen/microsoft-defender-smartscreen-overview">Windows Defender SmartScreen</a>, <a href="https://support.microsoft.com/en-us/microsoft-edge/enhance-your-security-on-the-web-with-microsoft-edge-b8199f13-b21b-4a08-a806-daed31a1929d">Hardware Enforced Stack Protection</a>, <a href="https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exploit-protection-reference?view=o365-worldwide#arbitrary-code-guard">Arbitrary Code Guard (ACG)<a/>, <a href="https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exploit-protection-reference?view=o365-worldwide#control-flow-guard-cfg">Control Flow Guard (CFG)</a>, <a href="https://learn.microsoft.com/en-us/microsoft-edge/web-platform/tracking-prevention">Tracking Prevention</a> and <a href="https://support.microsoft.com/en-us/topic/use-the-microsoft-edge-secure-network-to-protect-your-browsing-885472e2-7847-4d89-befb-c80d3dda6318">Trusted built-in VPN from Cloudflare</a> just to name a few.
* [Always enable Two-Factor/Multi-Factor Authentication](https://support.microsoft.com/en-us/office/the-keys-to-the-kingdom-securing-your-devices-and-accounts-a925f8ad-af7e-40d8-9ce4-60ea1cac2ba4) on websites, apps and services that you use. preferably, use [Microsoft Authenticator app](https://support.microsoft.com/en-us/account-billing/download-and-install-the-microsoft-authenticator-app-351498fc-850a-45da-b7b6-27e523b8702a) which has backup and restore feature, so you never lose access to your TOTPs (Time-Based One-Time Passwords) even if you lose your phone. available for <a href="https://play.google.com/store/apps/details?id=com.azure.authenticator&gl=US">Android</a> and <a href="https://apps.apple.com/us/app/microsoft-authenticator/id983156458">IOS</a>. you can also use Microsoft Authenticator on Windows 11 (PC, Laptop or Tablet) using <a href="https://apps.microsoft.com/store/detail/windows-subsystem-for-android%E2%84%A2-with-amazon-appstore/9P3395VX91NR?hl=en-us&gl=us">Windows Subsystem for Android (WSA)</a> and access your authenticator codes without the need to use your phone (again thanks to the secure automatic backup/restore feature). use an open-source and trusted Android store such as <a href="https://auroraoss.com/">Aurora Store</a> to <a href="https://github.com/whyorean/AuroraStore">install</a> and keep it up to date.
* Make sure OneDrive backup for important folders (Desktop/Documents/Pictures) is enabled. it is fast, secure and works in any network condition and since it's x64 (64-bit), it can handle a Lot of small and large files simultaneously.
* If you live in a western country, NATO country, European country or Australia, do not use VPNs. **your local ISP (Internet service provider) is a lot more trust worthy than the remote VPN server's ISP.** using VPN **only** takes the trust from your own local ISP and puts it in the hands of the remote ISP that the VPN server uses for its Internet, Nothing else. period. Do not fall for the fake advertisements of VPN companies, you never know who is behind the VPN provider, what their political views are, their background, where their allegiance lie. the permissive civilized western world could allow a state sponor of terrorism or some other hostile country to create a VPN company and gather intelligence and collect bulk data for mining, tracking etc. this has happened before and one of [the most recent](https://www.techradar.com/news/iran-officials-linked-to-canada-based-free-vpn-provider) revealations is about a [VPN provider called Betternet](https://archive.ph/xOVeY), ran by [IRGC terrorists and their families abroad](https://twitter.com/lisa_loo_who/status/1567984903312257025). stay Vigilant and Smart. 
	
	
* More Security Recommendations coming soon...

<p align="right"><a href="#readme-top">💡(back to top)</a></p>

## Resources<a href="#resources">![ResourcesIcon]</a>

- [Microsoft.com](https://microsoft.com)
  - [Force firmware code to be measured and attested by Secure Launch](https://www.microsoft.com/en-us/security/blog/2020/09/01/force-firmware-code-to-be-measured-and-attested-by-secure-launch-on-windows-10/)
- [Microsoft Learn](https://learn.microsoft.com/en-us/) - Technical Documentation
  - [Secure Launch—the Dynamic Root of Trust for Measurement (DRTM)](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/how-hardware-based-root-of-trust-helps-protect-windows#secure-launchthe-dynamic-root-of-trust-for-measurement-drtm)
- [Germany Intelligence Agency - BND](https://www.bsi.bund.de/EN/Service-Navi/Publikationen/publikationen_node.html) - Federal Office for Information Security
  - [Analysis of Device Guard](https://www.bsi.bund.de/EN/Service-Navi/Publikationen/Studien/SiSyPHuS_Win10/AP7/SiSyPHuS_AP7_node.html)
  - [Device Guard Differential Analysis](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Cyber-Sicherheit/SiSyPHus/E20172000_BSI_Win10_DGABGL_Win10_v_1_0.pdf?__blob=publicationFile&v=3)
- [Microsoft Tech Community](https://techcommunity.microsoft.com/) - Official blogs and documentations
- [Microsoft Security baselines](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines) - Security baselines from Microsoft
- [Microsoft Security Response Center (MSRC)](https://www.youtube.com/@microsoftsecurityresponsec2390)
  - [BlueHat Seattle 2019 || Guarding Against Physical Attacks: The Xbox One Story](https://www.youtube.com/watch?v=quLa6kzzra0)
  - [Security Update Guide:](https://msrc.microsoft.com/update-guide) The Microsoft Security Response Center (MSRC) investigates all reports of security vulnerabilities affecting Microsoft products and services, and provides the information here as part of the ongoing effort to help you manage security risks and help keep your systems protected.
  - [Microsoft Security Response Center Blog](https://msrc-blog.microsoft.com/)


<p align="right"><a href="#readme-top">💡(back to top)</a></p>

## License<a href="#license">![LicenseFreeIcon]</a>

Not Applicable, No license. because the only mission of this GitHub repository and script is to give all Windows users accurate, up to date and correct information about how to stay secure and safe in dangerous environments, and to stay not one, but Many steps, ahead of threat actors.

---

> [Microsoft Tech Community Profile](https://techcommunity.microsoft.com/t5/user/viewprofilepage/user-id/310193) &nbsp;&middot;&nbsp;
> GitHub [@HotCakeX](https://github.com/HotCakeX) &nbsp;&middot;&nbsp;
> Steam [@HotCakeX](https://steamcommunity.com/id/HotCakeX) &nbsp;&middot;&nbsp;
> Xbox: [@HottCakeX](https://account.xbox.com/en-US/Profile?Gamertag=HottCakeX)

	
---
	
<a href="#readme-top">   ![AUIcon]  ![USAIcon]  ![EUIcon]  ![NATOIcon]  ![UKicon]  ![IsraelIcon]</a>
	
	

[USAIcon]: images/USA.png	
[NATOIcon]: images/NATO.png
[UKicon]: images/UK.png	
[AUIcon]: images/AU.png	
[IsraelIcon]: images/Israel.png	
[EUIcon]: images/EU.png
	
	
	
[HardeningCategoriesIcon]: images/HardeningCategories.png
[FeaturesIcon]: images/Features.png	
[HowToUseIcon]: images/HowToUse.png
[LicenseFreeIcon]: images/LicenseFree.png
[ResourcesIcon]: images/Resources.png
[SecurityRecommendationIcon]: images/SecurityRecommendation.png
[SupportIcon]: images/Support.png
[RelatedIcon]: images/Related.png	
[TrustIcon]: images/Trust.png
[NonAdminIcon]: images/NonAdmin.png
[CountryIPBlockingIcon]: images/CountryIPBlocking.png
[NetworkingIcon]: images/Networking.png
[OptionalFeaturesIcon]: images/OptionalFeatures.png
[FirewallIcon]: images/Firewall.png
[ASRrulesIcon]: images/ASRrules.png
[DeviceGuardIcon]: images/DeviceGuard.png
[MiscellaneousIcon]: images/MiscellaneousCommands.png
[LockScreenIcon]: images/LockScreen.png
[CertificateIcon]: images/Certificate.png
[BitlockerIcon]: images/Bitlocker.png
[UACIcon]: images/UAC.png
[TLSIcon]: images/TLS.png
[WindowsDefenderIcon]: images/WindowsDefender.png
