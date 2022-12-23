
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
  <a href="#download">Download</a> •
  <a href="#how-to-use">How To Use</a> •
  <a href="#About">About</a> •
  <a href="#related">Related</a> •
  <a href="#license">License</a>
</p>

![screenshot](https://raw.githubusercontent.com/amitmerchant1990/electron-markdownify/master/app/img/markdownify.gif)

## Hardening Categories


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


## Download

Go to the top of this page, select Code and then select Download Zip, or just click here to start the download: [Download the Zip package](https://github.com/HotCakeX/Harden-Windows-Security/archive/refs/heads/main.zip) and then extract it to a folder.


## How To Use

To run the script:

```PowerShell
# Set Execution policy to bypass for the current process which is temporary only for current PowerShell instance 
Set-ExecutionPolicy Bypass -Scope Process

# use CD command to change the working directory to the folder where you've downloaded and extracted the zip files, like this example:
cd "C:\Users\$env:username\Downloads\Harden-Windows-Security-main\Harden-Windows-Security-main\"

# use this command to run the script
.\Harden-Windows-Security.ps1

```

> **Note**
> if there are multiple Windows user accounts in your computer, it's recommended to run this script in each of them, without administrator privileges, because Non-admin commands only apply to the current user and are not machine wide.

> **Note**
> When the script is running for the first time, please keep an eye on the PowerShell console because you might need to provide input for Bitlocker activation. 


> **Note**
> Things with **#TopSecurity** tag can break functionalities or cause difficulties so this script does NOT enable them by default. press Control + F and search for #TopSecurity in the script to find those commands and how to enable them if you want. 

## About

Features of this Hardening script:

- Always up-to-date and works with latest build of Windows (Currently Windows 11)
- Doesn't break anything
- Doesn't remove or disable Windows functionlities against Microsoft's recommendation
- Above each command there are comments that explain what it does and links to additional resources are provided for better understanding
- When a hardening command is no longer necessary because it's applied by default by Microsoft on new builds of Windows, it will also be removed from this script in order to prevent any problems and since it won't be necessary anymore.
- The script can be run infinite number of times, it's made in a way that it won't make any duplicate changes.


## Related

[PowerShell Gallery](https://www.powershellgallery.com/packages/Harden-Windows-Security/) - Also available in PowerShell Gallery

## Support

<a href="https://github.com/HotCakeX/Harden-Windows-Security/discussions">
🎯 if you have any questions, requests, suggestions etc. about this script, please open a new discussion on Github
</a>




## You may also like...

- [Pomolectron](https://github.com/amitmerchant1990/pomolectron) - A pomodoro app
- [Correo](https://github.com/amitmerchant1990/correo) - A menubar/taskbar Gmail App for Windows and macOS

## License

MIT

---

> [amitmerchant.com](https://www.amitmerchant.com) &nbsp;&middot;&nbsp;
> GitHub [@amitmerchant1990](https://github.com/amitmerchant1990) &nbsp;&middot;&nbsp;
> Twitter [@amit_merchant](https://twitter.com/amit_merchant)

