
<h1 align="center">
  <br>
  <a href="https://github.com/HotCakeX"><img src="https://avatars.akamai.steamstatic.com/48612a0ea22fed72aea709509281d0b4e4a4e227_full.jpg" alt="Markdownify" width="200"></a>
  <br>
  Harden Windows Security
  <br>
</h1>

<h4 align="center">Harden Windows 11 Safely, securely and without breaking anything</h4>

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
  <a href="#Hardening-Categories">Hardening Categories</a> •
  <a href="#how-to-use">How To Use</a> •
  <a href="#features">Features</a> •
  <a href="#related">Related</a> •
  <a href="#Support">Support</a> •
  <a href="#resources">Resources</a> 


</p>

<p align="center">
  <img src="https://media0.giphy.com/media/xTiTnxpQ3ghPiB2Hp6/giphy.gif?cid=ecf05e4753sksatv85kypy30bjuf9yb9dsc7uwz547zek4xn&rid=giphy.gif&ct=g" alt="Sublime's custom image"/>
</p>


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
* Commands that don't require Administrator Privileges
  - Non-Admin Commands



## How To Use

To run the script:

```PowerShell
# Download the latest version of the script to the current user folder
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security.ps1" -OutFile "Harden-Windows-Security.ps1"

# set execution policy temporarily to bypass for the current PowerShell session only
Set-ExecutionPolicy Bypass -Scope Process

# run the script
.\Harden-Windows-Security.ps1


```

> **Note**
> if there are multiple Windows user accounts in your computer, it's recommended to run this script in each of them, without administrator privileges, because Non-admin commands only apply to the current user and are not machine wide.

> **Note**
> When the script is running for the first time, please keep an eye on the PowerShell console because you might need to provide input for Bitlocker activation. 


> **Note**
> Things with **#TopSecurity** tag can break functionalities or cause difficulties so this script does NOT enable them by default. press Control + F and search for #TopSecurity in the script to find those commands and how to enable them if you want. 


## Features:

- Always up-to-date and works with latest build of Windows (Currently Windows 11)
- Doesn't break anything
- Doesn't remove or disable Windows functionlities against Microsoft's recommendation
- Above each command there are comments that explain what it does and links to additional resources are provided for better understanding
- When a hardening command is no longer necessary because it's applied by default by Microsoft on new builds of Windows, it will also be removed from this script in order to prevent any problems and because it won't be necessary anymore.
- The script can be run infinite number of times, it's made in a way that it won't make any duplicate changes.



## Related

[PowerShell Gallery](https://www.powershellgallery.com/packages/Harden-Windows-Security/) - Also available in PowerShell Gallery


## Support

<a href="https://github.com/HotCakeX/Harden-Windows-Security/discussions">
🎯 if you have any questions, requests, suggestions etc. about this script, please open a new discussion on Github
</a>

<br />



## Resources
<br />

Some of the resources used...

- [Microsoft Learn](https://learn.microsoft.com/en-us/) - Technical Documentation
- [ADMX](https://admx.help/) - Group Policy Administrative Templates Catalog
- [GPS](https://gpsearch.azurewebsites.net/) - Group Policy Search
- [Germany Intelligence Agency - BND](https://www.bsi.bund.de/EN/Service-Navi/Publikationen/publikationen_node.html) - Federal Office for Information Security
- [Microsoft Tech Community](https://techcommunity.microsoft.com/) - Official blogs and documentations


## License

MIT License

---

> [Microsoft Tech Community Profile](https://techcommunity.microsoft.com/t5/user/viewprofilepage/user-id/310193) &nbsp;&middot;&nbsp;
> GitHub [@HotCakeX](https://github.com/HotCakeX) &nbsp;&middot;&nbsp;
> Steam [@HotCakeX](https://steamcommunity.com/id/HotCakeX)

