
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

> __Warning__  <h3>Windows by default is secure and safe, this script does not imply nor claim otherwise. just like anything, you have to use it wisely and don't compromise yourself with reckless behavior and bad user configuration; Nothing is foolproof. this script only uses the tools and features that have already been implemented by Microsoft in Windows OS to fine-tune it towards the highest security and locked-down state, using well-documented, supported, often recommended and official methods.</h3>

 </br>


## Hardening Categories

From Top to bottom in order:

* Commands that require Administrator Privileges
  - Windows Security aka Defender
  - Attack surface reduction rules
  - Bitlocker Settings 
  - TLS Security
  - Lock Screen
  - UAC (User Account Control)
  - Device Guard
  - Windows Firewall
  - Optional Windows Features
  - Windows Networking
  - Miscellaneous Configurations
  - Certificate Checking Commands
  - Country IP Blocking
  

* Commands that don't require Administrator Privileges
  - Non-Admin Commands that only affect the current user and do not make machine-wide changes.



## How To Use

To run the script:

```PowerShell
# Download the latest version of the script to the current user folder
iwr -Uri "https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security.ps1" -OutFile "Harden-Windows-Security.ps1"

# set execution policy temporarily to bypass for the current PowerShell session only
Set-ExecutionPolicy Bypass -Scope Process

# run the script
.\Harden-Windows-Security.ps1


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

