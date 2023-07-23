<h1 align="center">
  <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/png-donut-2.png" alt="Big Yummy Donut" width="150">
  <br>
  Harden Windows Security
</h1>
<a name="readme-top"></a>

<h4 align="center">

Harden Windows Safely, Securely, only with Official Microsoft methods
</h4>

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

<h6 align="center">

<a href="https://twitter.com/intent/tweet?text=Harden%20Windows%20Security%20Using%20Official%20Microsoft%20Methods%20https://github.com/HotCakeX/Harden-Windows-Security/"><img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/SVGs/Twitter%20with%20URL.svg" alt="Twitter Share button"></a>

</h6>

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
  <a href="https://github.com/HotCakeX/Harden-Windows-Security/wiki">Wiki</a> •
  <a href="https://1drv.ms/x/s!AtCaUNAJbbvIhuVQhdMu_Hts7YZ_lA?e=df6H6P">Full change log in Excel online</a>

</p>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

#### <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/accepted.gif" width= "30" alt="Green icon denoting validation"> Security for Personal users

**Use the PowerShell script <a href="#how-to-use">below</a> to automatically apply the proactive security measures described in this page.**

#### <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/accepted.gif" width= "30" alt="Green icon denoting validation"> Security for [Organizations, Enterprises](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Rationale.md#-what-about-other-enterprise-security-) and Highly secure personal users

**Refer to [Windows Defender Application Control](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction) resources on this GitHub repository.**

<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/yellow%20bell%20small.gif" width="36" alt="Yellow bell denoting something important and attention">**Use the [WDACConfig Module](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) for Advanced Automated WDAC configurations and Application/File whitelisting in Windows.**

<br>

<p align="center">
<img width="35" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/rainbow%20arrow%202nd%20Variation%20right.gif">
<a href="https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Rationale.md"> Read the Rationale behind this GitHub repository </a><img width="35" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/rainbow%20arrow%202nd%20Variation%20left.gif">
</p>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

> [!NOTE]\
> Windows by default is secure and safe, this repository does not imply nor claim otherwise. just like anything, you have to use it wisely and don't compromise yourself with reckless behavior and bad user configuration; Nothing is foolproof. This repository only uses the tools and features that have already been implemented by Microsoft in Windows OS to fine-tune it towards the highest security and locked-down state, using well-documented, supported, recommended and official methods. continue reading for comprehensive info.

<br>

## How To Use<a href="#how-to-use">![HowToUseIcon](https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/HowToUse.png)</a>

There are 3 ways you can use this script. Using GitHub and Azure sources means you'll always use the latest version.

When the script is installed using PowerShell Gallery source and you run it, if there is a new version available, you will be prompted to update it.

> [!IMPORTANT]\
> About [Invoke-Expression or iex](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.3)

### <a href="https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Harden-Windows-Security.ps1"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/SVGs/github.svg"> GitHub source</a>

```powershell
irm 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security.ps1' | iex
```

### <a href="https://dev.azure.com/SpyNetGirl/_git/Harden-Windows-Security?path=/Harden-Windows-Security.ps1"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/SVGs/azure.svg"> Azure DevOps source</a>

```powershell
irm 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/Harden-Windows-Security.ps1' | iex
```

### <a href="https://www.powershellgallery.com/packages/Harden-Windows-Security"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/SVGs/powershell.svg"> PowerShell Gallery</a>

```powershell
Install-Script -Name Harden-Windows-Security
```

<br>

<br>

![Animated APNG demonstrating how the Harden Windows Security PowerShell script works](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Harden-Windows-Security-Demo.apng)
  
<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

<p align="center"> A quick video demonstrating how the Harden-Windows-Security script works </p>

<p align="center">
  <a href="https://www.youtube.com/watch?v=Ty_NoguyMhc">
    <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/YouTubeVideoLogo.png" width="500"
         alt="YouTube Video showcase">
  </a>
  </p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Requirements <a href="#requirements">![RequirementsIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Requirements.png)</a>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/verticalshine.gif" width="27" alt="Requirements item"> Any device that meets the [Windows 11 hardware](https://www.microsoft.com/en-in/windows/windows-11-specifications?r=1) and [Virtualization Based Security](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs) requirements. **Most of the hardware manufactured in the past few years are supported.**

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/verticalshine.gif" width="27" alt="Requirements item"> TPM 2.0, Virtualization technology and Secure Boot enabled in your UEFI settings. [Official guide](https://support.microsoft.com/en-us/windows/windows-11-and-secure-boot-a8ff1202-c0d9-42f5-940f-843abef64fad) - How to enable Secure Boot on: [HP](https://support.hp.com/document/ish_4300937-4295746-16?openCLC=true) - [Lenovo](https://support.lenovo.com/solutions/ht509044) - [Dell](https://www.dell.com/support/kbdoc/000190116/How-to-Enable-Secure-Boot-on-Your-Dell-Device).

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/verticalshine.gif" width="27" alt="Requirements item"> Windows editions higher than [Home edition](https://www.microsoft.com/en-us/windows/compare-windows-10-home-vs-pro).

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/verticalshine.gif" width="27" alt="Requirements item"> No 3rd party antivirus or security solution installed.

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/verticalshine.gif" width="27" alt="Requirements item"> [Latest available version](https://www.microsoft.com/en-us/software-download/windows11/) of Windows installed.

> [!IMPORTANT]\
> Restart your device after applying the script, [don't use any commands to force Group Policy update](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/jj573586(v=ws.11)?redirectedfrom=MSDN#asynchronous-and-synchronous-processing).

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="Harden-Windows-Security is a PowerShell script">

<br>

## Features <a href="#features">![FeaturesIcon](https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Features.png)</a>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/Shiny.gif" width="27" alt="Features Item"> Always stays up-to-date with the newest proactive security measures.
  
<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/Shiny.gif" width="27" alt="Features Item"> Everything is in [plain text](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Harden-Windows-Security.ps1), nothing hidden, no 3rd party executable or pre-compiled binary is involved.

> [!WARNING]\
> For your own security, do not use any other 3rd party tools, programs or scripts that claim to harden Windows or modify it in any way, **unless you can 100% verify it**. [Never trust 3rd party people on the Internet,](https://github.com/HotCakeX/hotcakex.github.io/raw/main/pdfs/Windows%20Ebook-5%20Risk%20Points%20to%20Avoid%20in%20Enterprise%20Security.pdf) always verify their resources and do that after each release. **Keep on reading the features to see why this Harden-Windows-Security script is different and <a href="#Trust">read the Trust section</a> to see how you can 100% Trust it.**

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/Shiny.gif" width="27" alt="Features Item"> Doesn't remove or disable Windows functionalities against Microsoft's recommendations.
  
<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/Shiny.gif" width="27" alt="Features Item"> All of the links and sources are from official Microsoft websites, straight from the source. No bias, No misinformation and definitely No old obsolete methods. That's why there are no links to 3rd party news websites, forums, made up blogs/articles and such.

<details><summary>With the following exceptions</summary>

| Link Count| Link                     | Reason                                                     |
|:----:|:-----------------------------:|:----------------------------------------------------------:|
| 1    | Intel website                 | i7 13700k product page                                     |
| 1    | state.gov                     | List of State Sponsors of Terrorism                        |
| 1    | orpa.princeton.edu            | OFAC Sanctioned Countries                                  |
| 2    | Wikipedia                     | TLS - providing additional information                     |
| 1    | UK Cyber Security Centre      | TLS - providing additional information                     |
| 1    | Security.Stackexchange Q&A    | TLS - providing additional information                     |
| 1    | browserleaks.com/tls          | TLS - Browser test                                         |
| 1    | clienttest.ssllabs.com        | TLS - Browser test                                         |
| 1    | scanigma.com/knowledge-base   | TLS - providing additional information                     |
| 1    | cloudflare.com/ssl/reference/ | TLS - providing additional information                     |
| 1    | github.com/ssllabs/research/  | TLS - providing additional information                     |
| 1    | Wayback Machine               | Providing additional information about Edge Browser        |

</details>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/Shiny.gif" width="27" alt="Features Item"> The script primarily uses Group policies, **the Microsoft recommended way of configuring Windows**. It also uses PowerShell cmdlets where Group Policies aren't available, and finally uses [a few registry keys](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Payload/Registry.csv) to configure security measures that can neither be configured using Group Policies nor PowerShell cmdlets. This is why the script doesn't break anything or cause unwanted behavior.

> [!WARNING]\
> **Any other 3rd party tool/program/script that claims to modify Windows or harden it, if they don't strictly adhere to the official rules above, they can damage your system, cause unknown problems and bugs.** [How are Group Policies for this script created and maintained?](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Group-Policy#how-are-group-policies-for-this-script-created-and-maintained)

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/Shiny.gif" width="27" alt="Features Item"> This Readme page lists all of the security measures applied by this script.

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/Shiny.gif" width="27" alt="Features Item"> When a hardening measure is no longer necessary because it's applied by default by Microsoft on new builds of Windows, it will also be removed from this script in order to prevent any problems and because it won't be necessary anymore.

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/Shiny.gif" width="27" alt="Features Item"> The script can be run infinite number of times, it's made in a way that it won't make any duplicate changes.

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/Shiny.gif" width="27" alt="Features Item"> The script prompts for confirmation before running each hardening category and some sub-categories, so you can selectively run (or don't run) each of them.

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/Shiny.gif" width="27" alt="Features Item"> Applying this script makes your PC compliant with Microsoft Security Baselines and Secured-core PC specifications (provided that you use modern hardware that supports the latest Windows security features) - [See what makes a Secured-core PC](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-highly-secure#what-makes-a-secured-core-pc) - <a href="#device-guard">Check Device Guard category for more details.</a>
> [Secured-core](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-highly-secure) – recommended for the most sensitive systems and industries like financial, healthcare, and government agencies. Builds on the previous layers and leverages advanced processor capabilities to provide protection from firmware attacks.
  
<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/Shiny.gif" width="27" alt="Features Item"> There are 5 items tagged with **#TopSecurity** <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/200iq.gif" width="28" alt="TopSecurity"> that can cause some inconvenience but increase security even further. When you run this script, you will have an option to enable them if you want to. Press `Control + F` and search for `#TopSecurity` on this page to find those security measures.

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/Shiny.gif" width="27" alt="Features Item"> Since I originally created this repository for myself and people I care about, I always maintain it to the highest possible standard.

<br>

<p align="right"><a href="#readme-top">💡 (back to top)</a></p>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="Harden-Windows-Security is a PowerShell script">

## Hardening Categories<a href="#hardening-categories">![HardeningCategoriesIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/HardeningCategories.png)</a>

<a name="menu-back-to-top"></a>
From Top to bottom in order:

* Commands that require Administrator Privileges (click/tap on each of these to see in-depth info)
  - <a href="#may-9-2023-windows-boot-manager-cve-2023-24932">May 9 2023 Windows Boot Manager CVE-2023-24932</a>
  - <a href="#windows-kernel-information-disclosure-cve-2023-32019">Windows Kernel Information Disclosure CVE-2023-32019</a>
  - <a href="#microsoft-security-baselines">Microsoft Security Baselines</a>
  - <a href="#microsoft-365-apps-security-baselines">Microsoft 365 Apps Security Baselines</a>
  - <a href="#microsoft-defender">Microsoft Defender</a>
  - <a href="#attack-surface-reduction-rules">Attack surface reduction rules</a>
  - <a href="#bitlocker-settings">Bitlocker Settings</a>
  - <a href="#tls-security">TLS Security</a>
  - <a href="#lock-screen">Lock Screen</a>
  - <a href="#user-account-control">UAC (User Account Control)</a>
  - <a href="#device-guard">Device Guard</a>
  - <a href="#windows-firewall">Windows Firewall</a>
  - <a href="#optional-windows-features">Optional Windows Features</a>
  - <a href="#windows-networking">Windows Networking</a>
  - <a href="#miscellaneous-configurations">Miscellaneous Configurations</a>
  - <a href="#windows-update-configurations">Windows Update configurations</a>
  - <a href="#edge-browser-configurations">Edge Browser configurations</a>
  - <a href="#certificate-checking-commands">Certificate Checking Commands</a>
  - <a href="#country-ip-blocking">Country IP Blocking</a>
  
* Commands that don't require Administrator Privileges
  - <a href="#non-admin-commands">Non-Admin Commands that only affect the current user and do not make machine-wide changes</a>

</br>
</br>
</br>

<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Indicates the security measure is applied using Group Policies

<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Indicates the security measure is applied using PowerShell cmdlets or Registry

<p align="right"><a href="#readme-top">💡 (back to top)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## May 9 2023 Windows Boot Manager CVE-2023-24932<a href="#may-9-2023-windows-boot-manager-cve-2023-24932"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/ExcMark.gif" width="35" alt="Rotating pink gem denoting registry or cmdlet"></a>

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/FwMIuw5aQAM2oXP.png" alt="An AI generated picture of a cat girl working in a server farm" width="600"></p>

<br>

#### May 9 2023 Windows Boot Manager revocations for Secure Boot changes associated with CVE-2023-24932

<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Automatically applies the security measures [**described in the KB5025885 document page**](https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d#update5025885).

[KB5026372](https://support.microsoft.com/en-gb/topic/may-9-2023-kb5026372-os-build-22621-1702-ce93c18e-e819-458f-abcf-dc7154ce7e40) must be installed, so make sure your OS is fully up to date first.

You will need to restart your device once. After restart, wait at least for 5-10 minutes and then restart again, as suggested in the official page.

[Microsoft Security Response Center post](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24932)

<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Windows Kernel Information Disclosure CVE-2023-32019<a href="#windows-kernel-information-disclosure-cve-2023-32019"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/ExcMark.gif" width="35" alt="Rotating pink gem denoting registry or cmdlet"></a>

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/FwMP4OraEAA-0AG.png" alt="An AI generated picture of a cat girl working in a server farm" width="600"></p>

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Automatically applies the security measures [**described in the KB5028407 document page**](https://support.microsoft.com/en-gb/topic/kb5028407-how-to-manage-the-vulnerability-associated-with-cve-2023-32019-bd6ed35f-48b1-41f6-bd19-d2d97270f080).

[KB5027231](https://support.microsoft.com/en-us/topic/june-13-2023-kb5027231-os-build-22621-1848-8f903600-1293-4431-9c6b-736a4049666c) must be installed, so make sure your OS is fully up to date first.

[Microsoft Security Response Center post](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-32019)

<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Microsoft Security Baselines<a href="#microsoft-security-baselines">![MicrosoftSecurityBaseline](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Microsoft-Security-Baseline.png)</a>

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/FwMGoa0aMAAw4-Y.png" alt="An AI generated picture of a cat girl working in a server farm" width="600"></p>

<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> A security baseline is a group of Microsoft-recommended configuration settings that explains their security implications. These settings are based on feedback from Microsoft security engineering teams, product groups, partners, and customers.

[Continue reading in the official documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines#what-are-security-baselines)

[Optional Overrides for Microsoft Security Baselines](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Overrides-for-Microsoft-Security-Baseline)

<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Highly recommended to apply these overrides, the script will ask you whether you want to apply them or not.

<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Microsoft 365 Apps Security Baselines<a href="#microsoft-365-apps-security-baselines">![Microsoft365AppsSecurityBaselines](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Microsoft-365-Apps-Security-Baselines.png)</a>

<p align="center"><img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/original2.png" alt="Some kind of futuristic Microsoft Protect" width="500"></p>

<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> The security baseline for Microsoft 365 Apps for enterprise is published twice a year, usually in June and December.

[More info in Microsoft Learn](https://learn.microsoft.com/en-us/deployoffice/security/security-baseline)

[Microsoft Security Baselines Version Matrix](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/get-support-for-security-baselines#version-matrix)

<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Microsoft Defender<a href="#microsoft-defender">![WindowsDefenderIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/WindowsDefender.png)</a>

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/PNGs/mde-cloud-protection.png" alt="Microsoft Defender Cloud Protection features and abilities" width="450"></p>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables **additional** security features of Microsoft Defender, You can refer to [this official document](https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps) for full details.

  - [Performance analyzer for Microsoft Defender Antivirus](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/tune-performance-defender-antivirus)

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> This script makes sure [Cloud Security Scan](https://support.microsoft.com/en-us/topic/what-is-a-cloud-security-scan-75112696-7660-4450-9194-d717f72a8ad8) and [Block At First Sight](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus?view=o365-worldwide#turn-on-block-at-first-sight-with-group-policy) are enabled to the highest possible security states available, **Zero Tolerance Cloud Block level**. You need to be aware that this means actions like downloading and opening an unknown file **will** make Microsoft Defender send samples of it to the Cloud for more advanced analysis and it can take a maximum of 60 seconds (this script sets it to max) from the time you try to open that unknown file to the time when it will be opened (if deemed safe), so you will have to wait. All of these security measures are in place by default in Windows to some extent and happen automatically without the need to run this script, but this script **maxes them out and sets them to the highest possible levels** at the cost of *convenience and usability.* It's always a trade-off.

  - Here is an example of the notification you will see in Windows 11 if that happens.
  
  <p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Windows%20Security%20Cloud%20Analysis.png" alt="Windows Security Cloud Scan Notification" width="200"></p>
  
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables file hash computation; [designed](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps#-enablefilehashcomputation) to allow admins to force the anti-malware solution to "compute file hashes for every executable file that is scanned if it wasn't previously computed" to "improve blocking for custom indicators in Microsoft Defender Advanced Threat Protection (Microsoft Defender ATP).

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Clears Quarantined items after 3 days instead of the default behavior of keeping them indefinitely.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Allows Microsoft Defender to download security updates even on a metered connection.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables Microsoft Defender to scan network drives, restore points, Emails and removable drives during a full scan, so it will take a while to finish a full scan if you have lots of those Items.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Sets the Signature Update Interval to every 3 hours instead of automatically.
  - [Change logs for security intelligence updates](https://www.microsoft.com/en-us/wdsi/definitions/antimalware-definition-release-notes)
  - [Configure and validate Microsoft Defender Antivirus network connections](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-network-connections-microsoft-defender-antivirus?view=o365-worldwide)
  - [Security intelligence updates for Microsoft Defender Antivirus and other Microsoft antimalware](https://www.microsoft.com/en-us/wdsi/defenderupdates)
  - [Microsoft Safety Scanner](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/safety-scanner-download?view=o365-worldwide)

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Forces Microsoft Defender to check for new virus and spyware definitions before it runs a scan.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Makes Microsoft Defender run [catch-up scans](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps#-disablecatchupquickscan) for scheduled quick scans. A computer can miss a scheduled scan, usually because the computer is off at the scheduled time, but now after the computer misses two scheduled quick scans, Microsoft Defender runs a catch-up scan the next time someone logs onto the computer.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables [Network Protection of Microsoft Defender](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/network-protection?view=o365-worldwide)

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Makes sure [Async Inspection for Network protection](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/network-protection?view=o365-worldwide#optimizing-network-protection-performance) of Microsoft Defender is turned on - Network protection now has a performance optimization that allows Block mode to start asynchronously inspecting long connections after they're validated and allowed by SmartScreen, which might provide a potential reduction in the cost that inspection has on bandwidth and can also help with app compatibility problems.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> **(Requires additional confirmation to run):** Enables [Smart App Control](https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003) (*if it's in Evaluation mode*): adds significant protection from new and emerging threats by blocking apps that are malicious or untrusted. Smart App Control also helps to block potentially unwanted apps, which are apps that may cause your device to run slowly, display unexpected ads, offer extra software you didn't want, or do other things you don't expect.
  - Smart App Control is User-Mode (and enforces Kernel-Mode) [Windows Defender Application Control policy (WDAC)](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control-design-guide), **more info** [**in the Wiki**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction). You can see its status in [System Information](https://support.microsoft.com/en-us/windows/view-your-system-info-a965a8f2-0773-1d65-472a-1e747c9ebe00) and enable it manually from Microsoft Defender app's GUI. It is very important for Windows and Windows Defender intelligence updates to be always up-to-date in order for Smart App Control to work properly as it relies on live intelligence and definition data from the cloud and other sources to make a Smart decision about programs and files it encounters.
  - Smart App Control uses [ISG (Intelligent Security Graph)](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/use-windows-defender-application-control-with-intelligent-security-graph#how-does-wdac-work-with-the-isg). The ISG isn't a "list" of apps. Rather, it uses the same vast security intelligence and machine learning analytics that power Microsoft Defender SmartScreen and Microsoft Defender Antivirus to help classify applications as having "known good", "known bad", or "unknown" reputation. This cloud-based AI is based on trillions of signals collected from Windows endpoints and other data sources and processed every 24 hours. As a result, the decision from the cloud can change.
  - [Smart App Control](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control#wdac-and-smart-app-control) can block a program entirely from running or only [some parts of it](https://support.microsoft.com/en-us/topic/smart-app-control-has-blocked-part-of-this-app-0729fff1-48bf-4b25-aa97-632fe55ccca2) in which case your app or program will continue working just fine most of the time. It's improved a lot since it was introduced, and it continues doing so. Consider turning it on after clean installing a new OS and fully updating it.

    - *Note: [At this time Smart App Control is only recommended in the North American and European regions](https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003).*
  - Smart App Control enforces the [Microsoft Recommended Driver Block rules](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules) and the [Microsoft Recommended Block Rules](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)
  
  - Once you turn Smart App Control off, it can't be turned on without resetting or reinstalling Windows.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables [Controlled Folder Access](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-controlled-folders). It [helps protect your valuable data](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/controlled-folders) from malicious apps and threats, such as ransomware. Controlled folder access protects your data by checking apps against a list of known, trusted apps. Due to the recent wave of global ransomware attacks, it is important to use this feature to protect your valuables files, specially OneDrive folders.
  - If it blocks a program from accessing one of your folders it protects, and you absolutely trust that program, then you can add it to exclusion list using Microsoft Defender GUI or PowerShell. you can also query the list of allowed apps using PowerShell (commands below). with these commands, you can backup your personalized list of allowed apps, that are relevant to your system, and restore them in case you clean install your Windows.
  - <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> The script adds the root of OneDrive folders of all user accounts present when running the script, to the protected folders list of Controlled Folder Access, to provide Ransomware protection for the entire OneDrive folder.

```powershell
# Add multiple programs to the exclusion list of Controlled Folder Access
Add-MpPreference -ControlledFolderAccessAllowedApplications 'C:\Program Files\App\app.exe','C:\Program Files\App2\app2.exe'
```

```powershell
# Get the list of all allowed apps
(Get-MpPreference).ControlledFolderAccessAllowedApplications
```

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Enables [Mandatory ASLR,](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-exploit-protection?view=o365-worldwide) *It might cause compatibility issues* only for some **poorly-made 3rd party programs**, specially portable ones.
  - You can add Mandatory ASLR override for a trusted program using the PowerShell command below or in the Program Settings section of Exploit Protection in Microsoft Defender app.
    - `Set-ProcessMitigation -Name "C:\TrustedApp.exe" -Disable ForceRelocateImages`

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Applies [Exploit Protection/Process Mitigations](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-exploit-protection) from [**this list**](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Payload/ProcessMitigations.csv) to the following programs:

  - All channels of [Microsoft Edge](https://www.microsoft.com/en-us/edge) browser
  - [Quick Assist](https://learn.microsoft.com/en-us/windows/client-management/client-tools/quick-assist) app
  - Some System processes, [full list available here.](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Payload/ProcessMitigations.csv)
  - More apps and processes will be added to the list over time once they are properly validated to be fully compatible.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> [Turns on Data Execution Prevention](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set) (DEP) for all applications, including 32-bit programs. By default, the output of `BCDEdit /enum "{current}"` (in PowerShell) for the NX bit is `OptIn` but this script sets it to `AlwaysOn`

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Check for the latest virus and spyware security intelligence on startup.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Specifies the maximum depth to scan archive files to the maximum possible value of `4,294,967,295`

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Defines the maximum size of downloaded files and attachments to be scanned](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-advanced-scan-types-microsoft-defender-antivirus?view=o365-worldwide) and set it to the maximum possible value of `10,000,000 KB` or `10 GB`. [the default is](https://github.com/MicrosoftDocs/microsoft-365-docs/pull/5600) `20480 KB` or `~20MB`

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enforces all features of the [Enhanced Phishing Protection](https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-smartscreen/phishing-protection-microsoft-defender-smartscreen?tabs=gpo) in Microsoft Defender SmartScreen.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> **(Requires additional confirmation to run):** [Create scheduled task for fast weekly Microsoft recommended driver block list update.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Fast-and-Automatic-Microsoft-Recommended-Driver-Block-Rules-updates)

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> **(Requires additional confirmation to run):** Set Microsoft [Defender engine](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference#-engineupdateschannel) and [platform update channel](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference#-platformupdateschannel) to beta.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Detects and blocks potentially unwanted applications](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus?view=o365-worldwide#use-group-policy-to-configure-pua-protection) - PUA blocking

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Defines the number of days before spyware and virus security intelligence definitions](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/manage-outdated-endpoints-microsoft-defender-antivirus?view=o365-worldwide#use-group-policy-to-specify-the-number-of-days-before-protection-is-considered-out-of-date) are considered out of date to 2 days, instead of the default 7 days.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Sets the [default action](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-remediation-microsoft-defender-antivirus) for Severe and High threat levels to Remove, for Medium and Low threat levels to Quarantine.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> [Configures](https://learn.microsoft.com/en-us/windows/client-management/mdm/defender-csp#configurationoobeenablertpandsigupdate) real-time protection and Security Intelligence Updates to be enabled during OOBE.

<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Attack surface reduction rules<a href="#attack-surface-reduction-rules">![ASRrulesIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/ASRrules.png)</a>

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/BIGCDOC.jpg" alt="Microsoft Protect Detect Respond Center" width="900"></p>

<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Reducing your attack surface](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction) means protecting your devices and network, which leaves attackers with fewer ways to perform attacks. Configuring attack surface reduction rules in Windows can help!

<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Attack surface reduction rules](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide) target certain software behaviors, such as:

* Launching executable files and scripts that attempt to download or run files
* Running obfuscated or otherwise suspicious scripts
* Performing behaviors that apps don't usually initiate during normal day-to-day work

Such software behaviors are sometimes seen in legitimate applications. However, these behaviors are often considered risky because they are commonly abused by attackers through malware. Attack surface reduction rules can constrain software-based risky behaviors and help keep your organization safe.

<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> This script enables [all 16 available Attack Surface Reduction rules shown in the official chart](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#asr-rule-to-guid-matrix).

<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Bitlocker Settings<a href="#bitlocker-settings">![BitlockerIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Bitlocker.png)</a>

<p align="center"><img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/conclusionSmall.jpg" alt="A woman working in a server room with her laptop, standing" width="550"></p>

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> This script sets up and configures Bitlocker [using official documentation](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings), with the most secure configuration and Military Grade encryption algorithm, **XTS-AES-256, TPM 2.0 and start-up PIN**, to protect the confidentiality and integrity of all information at rest and in use.

  - OS drive is automatically encrypted (if it isn't already) when you run this category and select a startup PIN. For every other non-OS drive, there will be prompts for confirmation before encrypting it. Removable flash drives are skipped. Non-OS drives will have Recovery Password and Auto-unlock methods for authentication once they are encrypted.

  - You will be asked to enter a Startup PIN when activating Bitlocker for the first time. Make sure it contains at least 10 characters (uppercase and lowercase letters, symbols, numbers, spaces) and it's not the same as your Windows Hello PIN.

  - Once you run this script for the first time, there will be a text file containing the 48-digit recovery password for each encrypted drive that will be saved in itself, with the names like `Drive C recovery password.txt`. It is **very important to keep it in a safe and reachable place, e.g., in OneDrive's Personal Vault which requires authentication to access. See [Here](https://www.microsoft.com/en-us/microsoft-365/onedrive/personal-vault) and [Here](https://support.microsoft.com/en-us/office/protect-your-onedrive-files-in-personal-vault-6540ef37-e9bf-4121-a773-56f98dce78c4) for more info about OneDrive's Personal Vault**

  - TPM has [special anti-hammering logic](https://learn.microsoft.com/en-us/windows/security/information-protection/tpm/tpm-fundamentals) which prevents malicious user from guessing the authorization data indefinitely. [Microsoft defines that maximum number of failed attempts](https://learn.microsoft.com/en-us/archive/blogs/dubaisec/tpm-lockout) in Windows is 32 and every single failed attempt is forgotten after 2 hours. This means that every continuous two hours of powered on (and successfully booted) operation without an event which increases the counter will cause the counter to decrease by 1. You can view all the details using this [PowerShell command](https://learn.microsoft.com/en-us/powershell/module/trustedplatformmodule/get-tpm): `Get-TPM`.

  - Check out <a href="#lock-screen">Lock Screen</a> category for more info about the recovery password and the 2nd anti-hammering mechanism.

  - To have even more security than what the script provides, you can utilize a [Startup key in addition to the other 3 key protectors](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-countermeasures#pre-boot-authentication) (TPM, Startup PIN and Recovery password). with this method, part of the encryption key is stored on a USB flash drive, and a PIN is required to authenticate the user to the TPM. This configuration **provides multifactor authentication** so that if the USB key is lost or stolen, it can't be used for access to the drive, because the correct PIN is also required.

  - BitLocker will bring you a real security against the theft of your device if you strictly abide by the following basic rules:
    - As soon as you have finished working, either Hibernate or shut Windows down and allow for every shadow of information to disappear from RAM within 2 minutes. **This practice is recommended in High-Risk Environments.**

    - Do not mix 3rd party encryption software and tools with Bitlocker. Bitlocker creates a secure end-to-end encrypted ecosystem for your device and its peripherals, this secure ecosystem is backed by things such as software, Virtualization Technology, TPM 2.0 and UEFI firmware, Bitlocker protects your data and entire device against **real-life attacks and threats**. You can encrypt your external SSDs and flash drives with Bitlocker too.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables or disables [DMA protection from Bitlocker Countermeasures](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-countermeasures#protecting-thunderbolt-and-other-dma-ports) based [on the status](https://github.com/MicrosoftDocs/windows-itpro-docs/issues/6878#issuecomment-742429128) of [Kernel DMA protection](https://learn.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt). Kernel DMA Protection is [not compatible](https://learn.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt#system-compatibility) with other BitLocker DMA attacks countermeasures. It is recommended to disable the BitLocker DMA attacks countermeasures if the system supports Kernel DMA Protection (this script does that exactly). Kernel DMA Protection provides higher security bar for the system over the BitLocker DMA attack countermeasures, while maintaining usability of external peripherals. you can check the status of Kernel DMA protection [using this official guide](https://learn.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt#how-to-check-if-kernel-dma-protection-is-enabled).
  - [Kernel DMA Protection (Memory Access Protection) for OEMs](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-kernel-dma-protection) page shows the requirements for Kernel DMA Protection. for Intel CPUs, support for requirements such as VT-X and VT-D can be found in each CPU's respective product page. e.g. [Intel i7 13700K](https://ark.intel.com/content/www/us/en/ark/products/230500/intel-core-i713700k-processor-30m-cache-up-to-5-40-ghz.html)

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Disallows standard (non-Administrator) users from changing the Bitlocker Startup PIN or password

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Allows Enhanced PINs for startup](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings#allow-enhanced-pins-for-startup)

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Requires you to choose a PIN that contains at least 10 characters](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings#configure-minimum-pin-length-for-startup)

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables Hibernate, adds Hibernate to Start menu's power options and disables Sleep. This feature is only *recommended for High-Risk Environments.*
This is to prevent an **Attacker with skill and lengthy physical access to your computer which is the Worst-case Scenario**

  - Attack Scenario: Targeted attack with plenty of time; this attacker will open the case, will solder, and will use sophisticated hardware or software. Of course, [Bitlocker and configurations](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-countermeasures#attacker-with-skill-and-lengthy-physical-access) applied by this script will protect you against that.
  - [Power states S1-S3 will be disabled](https://learn.microsoft.com/en-us/windows/win32/power/system-power-states#sleep-state-s1-s3) in order to completely disable Sleep, doing so also removes the Sleep option from Start menu and even using commands to put the computer to sleep won't work. You will have to restart your device for the changes to take effect.
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> [sets Hibernate to full](https://learn.microsoft.com/en-us/windows/win32/power/system-power-states#hibernation-file-types)
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Disallows access to Bitlocker-protected removable data drives from earlier versions of Windows.](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings#allow-access-to-bitlocker-protected-removable-data-drives-from-earlier-versions-of-windows)

Refer to this [official documentation about the countermeasures of Bitlocker](https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-countermeasures)

<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## TLS Security<a href="#tls-security">![TLSIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/TLS.png)</a>

<p align="center"><img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/hardenSmall.jpg" alt="A young woman working at a headless server farm with her tablet, standing" width="550"></p>

<br>

Changes made by this category only affect things that use [Schannel SSP](https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-): that includes IIS web server, built-in inbox Windows apps and some other programs supplied by Microsoft, including Windows network communications, but not 3rd party software that use [portable stacks](https://en.wikipedia.org/wiki/Comparison_of_TLS_implementations#Portability_concerns) like Java, nodejs, python or php.

If you want to read more: [Demystifying Schannel](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/demystifying-schannel/ba-p/259233)

> [!NOTE]\
> The only [known](https://github.com/HotCakeX/Harden-Windows-Security/issues/38) program incompatible with this category is Battle.net game client.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Disables TLS 1 and TLS 1.1 security protocols that only **exist for backward compatibility**. All modern software should and do use `TLS 1.2` and `TLS 1.3`.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Disables [MD5 Hashing Algorithm](https://security.stackexchange.com/questions/52461/how-weak-is-md5-as-a-password-hashing-function) that is **only available for backward compatibility**

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Disables the following [weak ciphers](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices) that are **only available for backward compatibility**: `"DES 56-bit"`,`"RC2 40-bit"`,`"RC2 56-bit"`,`"RC2 128-bit"`,`"RC4 40-bit"`,`"RC4 56-bit"`,`"RC4 64-bit"`,`"RC4 128-bit"`,`"3DES 168-bit (Triple DES 168)"`

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Configures the [TLS](https://www.ncsc.gov.uk/guidance/using-tls-to-protect-data) to only use the [following](https://developers.cloudflare.com/ssl/reference/cipher-suites/recommendations/) secure [cipher suites](https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-11) and in this [exact](https://scanigma.com/knowledge-base) order:

```
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_256_GCM_SHA384
TLS_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
```

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Configures](https://learn.microsoft.com/en-us/windows-server/security/tls/manage-tls) TLS ECC Curves to [use the following](https://github.com/HotCakeX/Harden-Windows-Security/commit/5b5be1fcab8f7bf5d364f48459aecfc54c6eff9d#commitcomment-115982586) prioritized Curves order:

```
nistP521
curve25519
NistP384
NistP256
```

* By default, in [Windows 11 22H2](https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-elliptic-curves-in-windows-10-1607-and-later), the order is this:

```
curve25519
NistP256
NistP384
```

*[Read more in this Wiki post](https://github.com/HotCakeX/Harden-Windows-Security/wiki/About-TLS,-DNS,-Encryption-and-OPSEC-concepts)*

<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Lock Screen<a href="#lock-screen">![LockScreenIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/LockScreen.png)</a>

<p align="center"><img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Bing%20AI%20generated/_4f587ac7-ca0a-4f31-a13d-5763616b5d3d.jpg" alt="An AI generated picture of a girl working in a server farm" width="600"></p>

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Automatically locks device after X seconds of inactivity](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-machine-inactivity-limit) (just like mobile phones), which is set to 120 seconds (2 minutes) in this script, you can change that to any value you like.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Requires **CTRL+ALT+DEL** on the lock screen](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-do-not-require-ctrl-alt-del), kernel protected set of key strokes. The reason and logic behind it is:

  - A malicious user might install malware that looks like the standard sign-in dialog box for the Windows operating system and capture a user's password. The attacker can then sign into the compromised account with whatever level of user rights that user has.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables [a security anti-hammering feature](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-machine-account-lockout-threshold) that sets a threshold of 6 for the number of failed sign-in attempts that causes the device to be locked by using BitLocker. Sign-in attempts include Windows password or Windows Hello authentication methods. This threshold means, if the specified maximum number of failed sign-in attempts is exceeded, the device will invalidate the Trusted Platform Module (TPM) protector and any other protector except the 48-digit recovery password, and then reboot. During Device Lockout mode, the computer or device only boots into the touch-enabled Windows Recovery Environment (WinRE) until an authorized user enters the recovery password to restore full access.
  - This script (<a href="#bitlocker-settings">in the Bitlocker category</a>) automatically saves the 48-digit recovery password of each drive in itself, the location of it will also be visible on the PowerShell console when you run it. It is **very important to keep it in a safe and reachable place, e.g. in OneDrive's Personal Vault which requires authentication to access. See [Here](https://www.microsoft.com/en-us/microsoft-365/onedrive/personal-vault) and [Here](https://support.microsoft.com/en-us/office/protect-your-onedrive-files-in-personal-vault-6540ef37-e9bf-4121-a773-56f98dce78c4) for more info about OneDrive's Personal Vault**

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Hides email address of the Microsoft account on lock screen](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-display-user-information-when-the-session-is-locked), if your device is in a trusted place like at home then this isn't necessary.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Don't display username at sign-in](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-dont-display-username-at-sign-in); If a user signs in as Other user, the full name of the user isn't displayed during sign-in. In the same context, if users type their email address and password at the sign-in screen and press Enter, the displayed text "Other user" remains unchanged, and is no longer replaced by the user's first and last name, as in previous versions of Windows 10. Additionally, if users enter their domain user name and password and click Submit, their full name isn't shown until the Start screen displays.
  - [Useful](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-dont-display-username-at-sign-in#best-practices) If you have devices that store sensitive data, with monitors displayed in unsecured locations, or if you have devices with sensitive data that are remotely accessed, revealing logged on user's full names or domain account names

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> **#TopSecurity** <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/200iq.gif" width="28" alt="TopSecurity"> [Don't display last signed-in](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-do-not-display-last-user-name); This security policy setting determines whether the name of the last user to sign in to the device is displayed on the Secure Desktop. If this policy is enabled, the full name of the last user to successfully sign in isn't displayed on the Secure Desktop, nor is the user's sign-in tile displayed. Additionally, if the Switch user feature is used, the full name and sign-in tile aren't displayed. The sign-in screen requests a qualified domain account name (or local user name) and password.
  - This feature can be useful to enable if you live in *High-Risk Environments* and you don't want anyone to get any information about your device when it's locked and you're not around.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Don't Display Network Selection UI on Lock Screen](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowslogon#dontdisplaynetworkselectionui) (like WIFI Icon); This setting allows you to control whether anyone can interact with available networks UI on the logon screen. Once enabled, the device's network connectivity state cannot be changed without signing into Windows. Suitable for *High-Risk Environments*.

<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## User Account Control<a href="#user-account-control">![UACIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/UAC.png)</a>

<p align="center"><img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Bing%20AI%20generated/_70f44af7-57d0-414e-85de-7fff3a9b64b2.jpg" alt="An AI generated picture of a cat girl working in a server farm" width="600"></p>

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Prompt for elevation of privilege on secure desktop for all binaries](https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode) in [Administrator accounts](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/341747f5-6b5d-4d30-85fc-fa1cc04038d4), which presents the sign-in UI and restricts functionality and access to the system until the sign-in requirements are satisfied. The [secure desktop's](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation#reference) primary difference from the user desktop is that only trusted processes running as SYSTEM are allowed to run here (that is, nothing is running at the user's privilege level). The path to get to the secure desktop from the user desktop must also be trusted through the entire chain.
  - **This is the default behavior:** prompt the administrator in Admin Approval Mode to select either "Permit" or "Deny" for an operation that requires elevation of privilege for any non-Windows binaries. If the Consent Admin selects Permit, the operation will continue with the highest available privilege. This operation will happen on the secure desktop
  - **This is the behavior that this script sets:** prompts the administrator in Admin Approval Mode to select either "Permit" or "Deny" an operation that requires elevation of privilege. If the Consent Admin selects Permit, the operation will continue with the highest available privilege. "Prompt for consent" removes the inconvenience of requiring that users enter their name and password to perform a privileged task. This operation occurs on the secure desktop.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> **#TopSecurity** <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/200iq.gif" width="28" alt="TopSecurity"> Only elevate executables that are signed and validated [by enforcing cryptographic signatures on any interactive application](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-only-elevate-executables-that-are-signed-and-validated) that requests elevation of privilege. One of the [Potential impacts](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-only-elevate-executables-that-are-signed-and-validated#potential-impact) of it is that it can prevent certain poorly designed programs from prompting for UAC.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Changes the [behavior of the elevation prompt for standard users](https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users) from "prompt for credentials" to "prompt for credentials on the secure desktop".
  - **#TopSecurity** <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/200iq.gif" width="28" alt="TopSecurity"> behavior: Automatically deny all UAC prompts on Standard accounts. **Highly recommended to be used on sensitive critical machines.** Only use Standard account for regular everyday tasks, and if you want to perform administrative tasks such as intalling a program system-wide or changing system settings, completely log out of the Standard account and log into an Administrator account, perform the tasks, then completely log out and log back into the Standard account to continue your work. No [fast user switching](https://learn.microsoft.com/en-us/windows/win32/shell/fast-user-switching) and **absolutely no UAC on Standard accounts.**

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> **#TopSecurity** <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/200iq.gif" width="28" alt="TopSecurity"> Hides the entry points for [Fast User Switching](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowslogon).

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> **(Requires additional confirmation to run):** [Asks for a strong password for the built-in Administrator account and then enables it.](https://github.com/HotCakeX/Harden-Windows-Security/discussions/30#discussioncomment-5627737)

<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Device Guard<a href="#device-guard">![DeviceGuardIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/DeviceGuard.png)</a>

<p align="center"><img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Bing%20AI%20generated/_7b1941d2-cc77-4423-b4d9-76986bdc3680.jpg" alt="An AI generated picture of a cat girl working in a server farm" width="600"></p>

<br>

**Most of the Device Guard and Virtualization-Based Security features are Automatically enabled by default** on capable and modern hardware, this script only checks their status and if needed, enables UEFI lock for them and also proceeds with enabling [**full Secured-Core PC requirements**](https://www.microsoft.com/en-us/windows/business/windows-11-secured-core-computers). UEFI locked security measures are rooted in **Proof of Physical Presence**.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Makes sure Virtualization-Based Security is Enabled](https://learn.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity)
  - [Validate enabled Windows Defender Device Guard hardware-based security features](https://learn.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity#validate-enabled-windows-defender-device-guard-hardware-based-security-features)

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Requires Secure boot and enables DMA protection with it (if available) for Virtualization-Based Security](https://learn.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt)
  - This is in accordance with [Microsoft's recommendation](https://learn.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity#use-registry-keys-to-enable-virtualization-based-protection-of-code-integrity). This option provides Secure Boot with as much protection as is supported by a given computer’s hardware. A computer with input/output memory management units (IOMMUs) will have Secure Boot with DMA protection. A computer without IOMMUs will simply have Secure Boot enabled.
  - Secure boot has 2 parts, part 1 is enforced using the Group Policy by this script, but for part 2, you need to [enable Secure Boot in your UEFI firmware settings](https://support.microsoft.com/en-us/windows/windows-11-and-secure-boot-a8ff1202-c0d9-42f5-940f-843abef64fad) **if** it's not enabled by default (which is the case on older hardware).
  - [(Kernel) DMA protection hardware requirements](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-kernel-dma-protection)

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Turns on UEFI lock for Virtualization-Based Security

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Makes sure Virtualization-based protection of Code Integrity policies is Enabled

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Turns on UEFI lock for virtualization-based protection of Code Integrity policies

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Enables Windows Defender Credential Guard with UEFI Lock](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage#enable-virtualization-based-security-and-windows-defender-credential-guard)
  - [Windows Defender Device Guard and Windows Defender Credential Guard hardware readiness tool](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/dg-readiness-tool)
  - [Windows Defender Credential Guard requirements](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-requirements)

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Enables System Guard Secure Launch and SMM protection](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/system-guard-secure-launch-and-smm-protection#registry)
  - [How to verify System Guard Secure Launch is configured and running](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/system-guard-secure-launch-and-smm-protection#how-to-verify-system-guard-secure-launch-is-configured-and-running)

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Kernel Mode Hardware Enforced Stack Protection](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/windows-11-version-22h2-security-baseline/ba-p/3632520)

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables UEFI Lock for Local Security Authority (LSA) process Protection. [it is turned on by default on new Windows 11 installations](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#automatic-enablement) but not with UEFI Lock. When this setting is used with UEFI lock and Secure Boot, additional protection is achieved because disabling its registry key will have no effect.
  - when this feature is on, a new option called "Local Security Authority Protection" appears in Windows Security GUI => Device Security => Core Isolation

<h2></br></h2>

### [Device protection in Windows Security gives you one of these 4 hardware scores:](https://support.microsoft.com/en-us/windows/device-protection-in-windows-security-afa11526-de57-b1c5-599f-3a4c6a61c5e2)

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

<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Windows Firewall<a href="#windows-firewall">![FirewallIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Firewall.png)</a>

<p align="center"><img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Bing%20AI%20generated/Selected%20photo%20(4).jpg" alt="An AI generated picture of a cat girl working in a server farm" width="600"></p>

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Makes sure Windows Firewall is enabled for all profiles (which is the default)

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Sets inbound and outbound default actions for Domain Firewall Profile to Block; because this script is Not intended to be used on devices that are part of a domain or controlled by an Active Directory Domain Controller, since they will have their own policies and policy management systems in place.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables Windows Firewall logging for Domain, Private and Public profiles, sets the log file size for each of them to the max `32.767 MB`. Defines separate log files for each of the firewall profiles. Logs only dropped packets for Private and Public profiles, Logs both dropped and successful packets for Domain profile.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Disables [Multicast DNS (mDNS) UDP-in Firewall Rules for all 3 Firewall profiles](https://techcommunity.microsoft.com/t5/networking-blog/mdns-in-the-enterprise/ba-p/3275777), This might interfere with Miracast screen sharing, which relies on the Public profile, and homes where the Private profile is not selected, but it does add an extra measure of security in public places, like a coffee shop.
  - The domain name `.local` which is used in mDNS (Multicast DNS) [is a special-use domain name reserved by the Internet Engineering Task Force (IETF)](https://en.wikipedia.org/wiki/.local) so that it may not be installed as a top-level domain in the Domain Name System (DNS) of the Internet.
  
<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Optional Windows Features<a href="#optional-windows-features">![OptionalFeaturesIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/OptionalFeatures.png)</a>

<p align="center"><img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Bing%20AI%20generated/Ft8V6bfX0AwVr7a.jpg" alt="An AI generated picture of a cat girl working in a server farm" width="600"></p>

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> The script [disables](https://learn.microsoft.com/en-us/powershell/module/dism/disable-windowsoptionalfeature) the following rarely used features in [Windows optional features](https://learn.microsoft.com/en-us/windows/application-management/add-apps-and-features#use-windows-powershell-to-disable-specific-features) (Control Panel):
  - PowerShell v2; because it's old and doesn't support [AMSI](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/#antimalware-scan-interface-integration).
  - Work Folders client; not used when your computer is not part of a domain or enterprise network.
  - Internet Printing Client; used in combination with IIS web server, [old feature](https://learn.microsoft.com/en-us/troubleshoot/windows-server/printing/manage-connect-printers-use-web-browser), can be disabled without causing problems further down the road.
  - Windows Media Player (legacy); isn't needed anymore, [Windows 11 has a modern media player app](https://blogs.windows.com/windows-insider/2021/11/16/new-media-player-for-windows-11-begins-rolling-out-to-windows-insiders/).

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> [Uninstalls](https://learn.microsoft.com/en-us/powershell/module/dism/remove-windowscapability) these optional features (Windows Settings -> Apps -> Optional Features):

  - Notepad (system): legacy Notepad program. Windows 11 has multi-tabbed modern Notepad app.
  - VBSCRIPT; a legacy scripting engine component, Microsoft does not recommend using this component unless and until it is really required. It's become uninstallable as an optional features since Windows 11 insider Dev build 25309.
  - [Internet Explorer mode for Edge browser](https://learn.microsoft.com/en-us/deployedge/edge-ie-mode); It's only used by a few possible organizations that have very old internal websites.
  - [WMIC](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic); old feature that's deprecated, not secure and is in [Microsoft recommended block rules.](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> [Enables](https://learn.microsoft.com/en-us/powershell/module/dism/enable-windowsoptionalfeature) these optional features (Control Panel):
  - [Microsoft Defender Application Guard](https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-application-guard/md-app-guard-overview); which is a safe Environment to open untrusted websites. - [System Requirements](https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-application-guard/reqs-md-app-guard) - [Frequently asked questions](https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-application-guard/faq-md-app-guard) - Its behavior regarding [DNS over HTTPS in Edge](#notes-about-mdag-microsoft-defender-application-guard)
  - [Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-sandbox/windows-sandbox-overview); install, test and use programs in a disposable virtual operation system, completely separate from your  main OS
  - Hyper-V; a great hybrid hypervisor (Type 1 and Type 2) to run virtual machines on. [check out this Hyper-V Wiki page](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Hyper-V)
  - Virtual Machine Platform; required for [Android subsystem or WSA (Windows subsystem for Android)](https://learn.microsoft.com/en-us/windows/android/wsa/). if it's disabled, it will be automatically enabled either way when you try to install WSA from Store app

<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Windows Networking<a href="#windows-networking">![NetworkingIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Networking.png)</a>

<p align="center"><img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Bing%20AI%20generated/Ft8TCOwX0AQgKN-.jpg" alt="An AI generated picture of a cat girl working in a server farm" width="600"></p>

<br>

These are configurations that are typically *recommended in High-Risk Environments* but also can be applied for home users

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Disables NetBIOS over TCP/IP](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-netbt-interfaces-interface-netbiosoptions) on all network interfaces, virtual and physical. This command needs to run every time after installing a new VPN software or network adapter.
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Disables the LLMNR protocol [(Link Local Multicast Name Resolution)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-llmnrp/eed7fe96-9013-4dec-b14f-5abf85545385) because it's only [useful for networks that do not have a Domain Name System (DNS) server](https://learn.microsoft.com/en-us/previous-versions//bb878128(v=technet.10)?redirectedfrom=MSDN) and Microsoft themselves are [ramping down NetBIOS name resolution and LLMNR.](https://techcommunity.microsoft.com/t5/networking-blog/aligning-on-mdns-ramping-down-netbios-name-resolution-and-llmnr/ba-p/3290816)

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Disables [LMHOSTS lookup protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbte/bec3913a-c359-4e6f-8c7e-40c2f43f546b#gt_5f0744c1-5105-4e4a-b71c-b9c7ecaed910) on all network adapters, legacy feature that's not used anymore.
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Sets the Network Location of all connections to Public; [Public network means less trust to other network devices](https://support.microsoft.com/en-us/windows/make-a-wi-fi-network-public-or-private-in-windows-0460117d-8d3e-a7ac-f003-7a0da607448d).
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Disables [Printing over HTTP](https://learn.microsoft.com/en-us/troubleshoot/windows-server/printing/manage-connect-printers-use-web-browser) because HTTP is not encrypted and it's an old feature that's not used anymore.
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Turns off downloading of print drivers over HTTP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-connectivity#connectivity-disabledownloadingofprintdriversoverhttp) because HTTP is not encrypted and that method isn't used anymore. [This is the recommended and secure way of downloading printer drivers in Windows 11](https://support.microsoft.com/en-us/windows/download-printer-drivers-in-windows-da9b1460-7299-4cc3-e974-33cf99d86880).

<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Miscellaneous Configurations<a href="#miscellaneous-configurations">![MiscellaneousIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/MiscellaneousCommands.png)</a>

<p align="center"><img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Bing%20AI%20generated/Fr3e8zzXsAUM2I6.jpg" alt="An AI generated picture of a cat girl working in a server farm" width="600"></p>

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Sets [Early launch antimalware](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-driver-requirements) engine's status to `8` which is **Good only.** The default value is `3`, which allows good, unknown and 'bad but critical'. that is the default value, because setting it to `8` [can prevent your computer from booting](https://learn.microsoft.com/en-us/windows/compatibility/early-launch-antimalware#mitigation) if the driver it relies on is critical but at the same time unknown or bad.

  - By being launched first by the kernel, ELAM is ensured to be launched before any third-party software and is therefore able to detect malware in the boot process and prevent it from initializing. ELAM drivers must be specially signed by Microsoft to ensure they are started by the Windows kernel early in the boot process.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Disables location service system wide. Websites and apps won't be able to use your precise location, however they will still be able to detect your location using your IP address.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables [`svchost.exe` mitigations.](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-servicecontrolmanager) built-in system services hosted in `svchost.exe` processes will have stricter security policies enabled on them. These stricter security policies include a policy requiring all binaries loaded in these processes to be signed by Microsoft, and a policy disallowing dynamically generated code.
  - Requires Business Windows licenses. e.g., [Windows 11 pro for Workstations](https://www.microsoft.com/en-us/windows/business/windows-11-pro-workstations), [Enterprise](https://www.microsoft.com/en-us/microsoft-365/windows/windows-11-enterprise) or [Education](https://www.microsoft.com/en-us/education/products/windows).

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Turns on Enhanced mode search for Windows indexer. the default is classic mode.
  - This causes some UI elements in the search settings in Windows settings to become unavailable for Standard user accounts to view, because it will be a managed feature by an Administrator.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Enforce the Administrator role for adding printer drivers](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/devices-prevent-users-from-installing-printer-drivers)

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables [SMB/LDAP Signing](https://techcommunity.microsoft.com/t5/storage-at-microsoft/configure-smb-signing-with-confidence/ba-p/2418102)
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Enables [SMB Encryption](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security). Its status can be checked using the following PowerShell command: `(get-SmbServerConfiguration).EncryptData`. If the returned value is `$True` then SMB Encryption is turned on.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Enables Edge browser (stable/beta/dev channels) to download and install updates on any network, metered or not; because the updates are important and should not be suppressed.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> [Enables all Windows users to use Hyper-V and Windows Sandbox](https://learn.microsoft.com/en-us/archive/blogs/virtual_pc_guy/why-do-you-have-to-elevate-powershell-to-use-hyper-v-cmdlets) by adding all Windows users to the "Hyper-V Administrators" security group. By default, only Administrators can use Hyper-V or Windows Sandbox.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Changes Windows time sync interval from the default every 7 days to every 4 days (= every 345600 seconds)

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Creates custom views for [Windows Event Viewer](https://learn.microsoft.com/en-us/shows/inside/event-viewer) to help keep tabs on important security events: `Attack Surface Reduction Rules`, `Controlled Folder Access`, `Exploit Protection`, `Network Protection`, `MSI and Scripts for WDAC Auditing`, `Sudden Shut down events` (due to power outage) and `Code Integrity Operational`.
  - [Understand and use attack surface reduction capabilities](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/overview-attack-surface-reduction?view=o365-worldwide)
  - [Understanding Application Control events](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/event-id-explanations)

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables ["Send optional diagnostic data"](https://learn.microsoft.com/en-us/windows/privacy/windows-diagnostic-data) because it is [required for Smart App Control](https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003) to operate and be enabled, and for communication between [Intelligent Security Graph (ISG)](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/use-windows-defender-application-control-with-intelligent-security-graph) and you.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Enables **WinVerifyTrust Signature Validation**, [a security feature related to WinVerifyTrust function that handles Windows Authenticode signature verification for portable executable (PE) files.](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900)

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Blocking Untrusted Fonts](https://learn.microsoft.com/en-us/windows/security/threat-protection/block-untrusted-fonts-in-enterprise) <img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/200iq.gif" width="28" alt="TopSecurity"> **#TopSecurity**

<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Windows Update Configurations<a href="#windows-update-configurations">![WindowsUpdate](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/WindowsUpdate.png)</a>

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/MSFTRespond.jpg" alt="A Picture of Microsoft fast response center protect Direct" width="800"></p>

<br>

Windows updates are extremely important. They always should be installed as fast as possible to stay secure and if a reboot is required, it should be done immediately. Threat actors can weaponize publicly disclosed vulnerabilities [**the same day** their POC (Proof-Of-Concept) is released.](https://www.microsoft.com/en-us/security/blog/2023/04/18/nation-state-threat-actor-mint-sandstorm-refines-tradecraft-to-attack-high-value-targets/).

In Windows by default, devices will scan daily, automatically download and install any applicable updates at a time optimized to reduce interference with usage, and then automatically try to restart when the end user is away.

**The following policies the script configures make sure the default behavior explained above is tightly enforced.**

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables [Windows Update to download and install updates on any network](https://techcommunity.microsoft.com/t5/windows-it-pro-blog/the-windows-update-policies-you-should-set-and-why/ba-p/3270914), metered or not; because the updates are important and should not be suppressed, **that's what bad actors would want.**
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables "Receive Updates for other Microsoft products" (such as PowerShell)
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Enables "Notify me when a restart is required to finish updating"
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Sets the [grace period](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update#configuredeadlinegraceperiodforfeatureupdates) for auto restart to 1 day.
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Configures the [automatic updates to happen every day](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update#allowautoupdate), automatically be downloaded and installed, notify users for restart.
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Enables features introduced via servicing that are off by default](https://learn.microsoft.com/en-us/windows/deployment/update/waas-configure-wufb) so that users will be able to get new features after having Windows Update settings managed by Group Policy as the result of running this category.

<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Edge Browser configurations<a href="#edge-browser-configurations">![EdgeBrowser](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/EdgeBrowser.png)</a>

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/1%20(2).jpg" alt="An AI generated picture of a cat girl working in a server farm" width="600"></p>

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> [Block 3rd party cookies](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies#blockthirdpartycookies) - Recommendatory policy
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> [Set Edge to use system's DNS over HTTPS](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies#control-the-mode-of-dns-over-https)
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> [Automatic HTTPS upgrade of HTTP connections](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies#configure-automatic-https)
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> [Enable Encrypted Client Hello](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies#encryptedclienthelloenabled)
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet">[Restrict exposure of local IP address by WebRTC](https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-policies#webrtclocalhostiphandling)
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> [Disable the ability to access insecure websites with TLS errors](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies#allow-users-to-proceed-from-the-https-warning-page)
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet">[Disable Basic HTTP authentication scheme](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies#basicauthoverhttpenabled)
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet">[Force WebRTC respect the Windows OS routing table rules when making P2P connections](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies#enable-support-for-windows-os-routing-table-rules-when-making-peer-to-peer-connections-via-webrtc)
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet">[Launch Renderer processes into an App Container for additional security benefits](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies#enable-renderer-in-app-container)
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet">[Enforces Secure mode and Certificate-based Digital Signature validation in native PDF reader](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies#secure-mode-and-certificate-based-digital-signature-validation-in-native-pdf-reader)
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet">[Allow devices using this hardening category to receive new features and experimentations like normal devices](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies#control-communication-with-the-experimentation-and-configuration-service)
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet">[Enforce the audio process to run sandboxed](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies#allow-the-audio-sandbox-to-run)
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet">[Sets the share additional operating system region setting to never](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies#set-the-default-share-additional-operating-system-region-setting) - Recommendatory policy
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet">[Sets the new Adobe PDF reader to be used in Edge for PDFs](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies#microsoft-edge-built-in-pdf-reader-powered-by-adobe-acrobat-enabled) - Recommendatory policy
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> [Enables a feature that requires device authentication before the saved password is auto-filled into a web form](https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-policies#primarypasswordsetting)
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> [Disables the following weak Cipher Suites](https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-policies#tlsciphersuitedenylist)
  - [Site 1 to test TLS in your browser](https://clienttest.ssllabs.com:8443/ssltest/viewMyClient.html)
  - [Site 2 to test TLS in your browser](https://browserleaks.com/tls)

```
TLS_RSA_WITH_AES_256_CBC_SHA  Reason: NO Perfect Forward Secrecy, CBC, SHA1
TLS_RSA_WITH_AES_128_CBC_SHA  Reason: NO Perfect Forward Secrecy, CBC, SHA1
TLS_RSA_WITH_AES_128_GCM_SHA256  Reason: NO Perfect Forward Secrecy
TLS_RSA_WITH_AES_256_GCM_SHA384  Reason: NO Perfect Forward Secrecy
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA  Reason: CBC, SHA1
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA  Reason: CBC, SHA1
```

<br>

Some settings require the client to be joined to Windows Server [Active Directory](https://learn.microsoft.com/en-us/deployedge/configure-microsoft-edge#add-the-administrative-template-to-an-individual-computer)/Azure Active Directory, in order to be applied. This script does not use any of them. When those settings are applied using registry, they are ignored by the browser and `edge://policy/` shows an error for them. This is a security measure.

<br>

* You can view all of the policies being applied to your Edge browser by visiting this page: `edge://policy/`
* You can find all of the available internal Edge pages in here: `edge://about/`

<br>

- Useful links:
  - [Microsoft Edge stable channel change log](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnote-stable-channel)
  - [Microsoft Edge Security updates change log](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security)
  - [Microsoft Edge Beta channel change log](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnote-beta-channel)
  - [Microsoft Edge Mobile stable channel change log](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnote-mobile-stable-channel)
  - [Edge Insider for Beta/Dev/Canary channels](https://www.microsoftedgeinsider.com/en-us/)
  - [Microsoft Edge Security baselines](https://www.microsoft.com/en-us/download/details.aspx?id=55319) - Work without ingesting [ADMX policy files](https://www.microsoft.com/en-us/edge/business/download) first - This script includes them
    - [Reason why the script doesn't use it.](https://github.com/HotCakeX/Harden-Windows-Security/issues/50)

<br>

### Notes about MDAG (Microsoft Defender Application Guard)

* When DNS over HTTPS is set by user in Edge settings, Microsoft Defender Application Guard ignores that and connects directly to the Internet without using any DoH configuration.

* If DNS over HTTPS is enforced on Edge by a Group Policy or registry, then MDAG fails to connect to the Internet and shows DNS errors.

* **When DNS over HTTPS settings are set OS wide in Windows settings, both normal Edge and MDAG use the OS DoH settings.** *(This is the behavior set by this script)*

  * Use my [WinSecureDNSMgr module](https://github.com/HotCakeX/WinSecureDNSMgr) to easily configure DNS over HTTPS in Windows

###### Edge policies reviewed until version 115.0.1901.183

<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Certificate Checking Commands<a href="#certificate-checking-commands">![CertificateIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Certificate.png)</a>

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/1%20(1).jpg" alt="An AI generated picture of a cat girl working in a server farm" width="600"></p>

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> In this category, the script downloads and runs [sigcheck64.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck) from [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/), then lists valid certificates not rooted to the [Microsoft Certificate Trust List](https://learn.microsoft.com/en-us/windows/win32/seccrypto/certificate-trust-list-overview) in the [User and Machine certificate stores](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/local-machine-and-current-user-certificate-stores). **Except for some possible Microsoft certificates, Windows insider builds certificates or certificates that have your own computer's name, which are perfectly safe and should not be deleted,** All other certificates that will be listed should be treated as dangerous and removed from your system immediately.

<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Country IP Blocking<a href="#country-ip-blocking">![CountryIPBlockingIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/CountryIPBlocking.png)</a>

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/3.jpg" alt="An AI generated picture of a cat girl working in a server farm" width="600"></p>

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> The script uses the newest range of `IPv4` and `IPv6` addresses of [State Sponsors of Terrorism](https://www.state.gov/state-sponsors-of-terrorism/) and [OFAC Sanctioned Countries](https://orpa.princeton.edu/export-controls/sanctioned-countries), directly [from official IANA sources](https://github.com/HotCakeX/Official-IANA-IP-blocks) repository, then creates 2 rules (inbound and outbound) for each list in Windows firewall, completely blocking connections to and from those countries.

Once you have those Firewall rules added, you can [use this method](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Event-Viewer#how-to-identify-which-windows-firewall-rule-is-responsible-for-a-blocked-packets) to see if any of the blocked connections were from/to those countries.

> **Note**
Threat actors can use VPN, VPS etc. to mask their originating IP address and location. So don't take this category as the perfect solution for network protection.

<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Non-Admin Commands<a href="#non-admin-commands">![NonAdminIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/NonAdmin.png)</a>

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/6.jpg" alt="An AI generated picture of a cat girl working in a server farm" width="600"></p>

<br>

You don't need Admin privileges to run this category, because no system-wide changes is made. Changes in this category only apply to the current user account that is running the PowerShell session. For this reason, in addition to running this category as Admin, it's better to run it without elevation on any other available Standard accounts too.

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Shows known file extensions in File explorer
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Shows hidden files, folders and drives (toggles the control panel folder options item)
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Disables websites accessing local language list - good for privacy
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Turns off safe search in Windows search, will enable +18 content to appear in searches; essentially toggles the button in: Windows settings > privacy and security > search permissions > safe search
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> prevents showing notifications in Lock screen - this is the same as toggling the button in Windows settings > system > notifications > show notifications in the lock screen
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Enables Clipboard History and sync with Microsoft Account
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Turns on text suggestions when typing on the physical keyboard
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Turns on "Multilingual text suggestions" for the current user, toggles the option in Windows settings
- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/roratinggem.gif" width="28" alt="Rotating pink gem denoting registry or cmdlet"> Turns off sticky key shortcut of pressing shift key 5 times fast

<p align="right"><a href="#menu-back-to-top">💡 (back to categories)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Related<a href="#related">![RelatedIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Related.png)</a>

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/5.jpg" alt="An AI generated picture of a cat girl working in a server farm" width="600"></p>

<br>

[<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/WebP/911587042608156732.webp" width="25"> PowerShell Gallery mirror](https://www.powershellgallery.com/packages/Harden-Windows-Security/)

[<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/WebP/911587042608156732.webp" width="25"> Azure DevOps Repository](https://dev.azure.com/SpyNetGirl/_git/Harden-Windows-Security)

[<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/WebP/911587042608156732.webp" width="25"> Harden Windows Security website](https://hotcakex.github.io/)

[<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/WebP/911587042608156732.webp" width="25"> Official global IANA IP block for each country](https://hotcakex.github.io/Official-IANA-IP-blocks/)

[<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/WebP/911587042608156732.webp" width="25"> Windows Security Blog](https://spynetgirl.github.io/)

[<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/WebP/911587042608156732.webp" width="25"> WinSecureDNSMgr](https://github.com/HotCakeX/WinSecureDNSMgr)

[<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/WebP/911587042608156732.webp" width="25"> Privacy, Anonymity and Compartmentalization](https://github.com/HotCakeX/Privacy-Anonymity-Compartmentalization)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Trust<a href="#trust">![TrustIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Trust.png)</a>

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/FwMP8ybaUAAm860.png" alt="An AI generated picture of a cat girl working in a server farm" width="600"></p>

### How can you 100% trust this repository and know that nothing shady is going on?

This repository uses the simplest possible, yet effective, methods that make it very easy to verify:

- Change log history is present on GitHub. *(Despite some of my awkward documentation typos)*

- You can open the file in [Visual Studio Code](https://code.visualstudio.com/)/[Visual Studio Code Web](https://vscode.dev/), and view the script in a nice easy to read environment, it's well formatted and indented.

- Commits are verified either with my GPG key or SSH key and [Vigilant mode](https://docs.github.com/en/authentication/managing-commit-signature-verification/displaying-verification-statuses-for-all-of-your-commits) is turned on in my GitHub account.

- You can fork this repository, verify it until that point in time, then verify any subsequent changes/updates I push to this repository, **at your own pace** (using `Sync fork` and `Compare` options on your fork), and if you are happy with the changes, allow it to be merged with your own copy/fork on your GitHub account.
- You can [learn PowerShell which is super easy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Basic-PowerShell-tricks-and-notes), multiplatform, and useful for the future, Microsoft Learn website teaches you everything, then you will understand everything in the script is safe, or you can ask someone that you trust and knows PowerShell to verify the script for you.

- The [Payload folder](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/Payload) in this repository contains the files required to run this script:
  - [Registry.csv](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Payload/Registry.csv) includes registry data used by this script, viewable in plain text and easily verifiable.

  - [ProcessMitigations.csv](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Payload/ProcessMitigations.csv) includes process mitigations data used by this script, viewable in plain text and easily verifiable.
  
  - [EventViewerCustomViews.zip](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Payload/EventViewerCustomViews.zip) includes XML files, in plain text, easily readable and verifiable. the script downloads and copies them to `C:\ProgramData\Microsoft\Event Viewer\Views` so that when you open [Windows Event Viewer](https://learn.microsoft.com/en-us/host-integration-server/core/windows-event-viewer1), you will find custom views as explained in the <a href="#miscellaneous-configurations">Miscellaneous Configurations</a> category.
  
  - [Security-Baselines-X.zip](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Payload/Security-Baselines-X.zip) includes Group Policies that are used by this script to apply the security measures explained in this page.

- [How is Group Policy used in this PowerShell script?](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Group-Policy#how-is-group-policy-used-in-this-powershell-script)
- [How are Group Policies for this script created and maintained?](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Group-Policy#how-are-group-policies-for-this-script-created-and-maintained)
- [How to verify security-baselines-x.zip file and 100% trust it?](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Group-Policy#how-to-verify-security-baselines-xzip-file-and-100-trust-it)

<br>

<!-- Security-Baselines-X-VT:START --><a href='https://www.virustotal.com/gui/file/7acba638d4732633ab21753ba27d07f27d1bb1c29622192a656f305a67e77972'>Virus Total scan results of Security-Baselines-X.zip</a><!-- Security-Baselines-X-VT:END -->

<br>

<!-- EventViewer-CustomViews-VT:START --><a href='https://www.virustotal.com/gui/file/3303d00c7fd26be51a7d893d5434867df2e1f50a362fc65bb2d18d0427be3adb'>Virus Total scan results of EventViewerCustomViews.zip</a><!-- EventViewer-CustomViews-VT:END -->

<br>
<br>

*Links above are automatically updated. There is a [GitHub workflow](https://github.com/HotCakeX/Harden-Windows-Security/actions/workflows/VirusTotal.yml) that automatically detects changes to the files and uploads them to Virus Total website for scanning.*

<p align="right"><a href="#readme-top">💡 (back to top)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Support<a href="#support">![SupportIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Support.png)</a>

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/FwMF2jGaAAANLDc.png" alt="A beautiful pink laptop Windows 11, located on the table with coffee on the side" width="600"></p>

<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/WebP/Heart%20Microsoft.webp" width="28" alt="If you have any questions, requests, suggestions etc"> If you have any questions, requests, suggestions etc. about this GitHub repository and its content, please open [a new discussion](https://github.com/HotCakeX/Harden-Windows-Security/discussions) or [Issue](https://github.com/HotCakeX/Harden-Windows-Security/issues).

<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/WebP/Ninja%20cat.webp" width="28" alt="Reporting a vulnerability on this GitHub repository"> [Reporting a vulnerability](https://github.com/HotCakeX/Harden-Windows-Security/security/advisories) on this GitHub repository.

<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/Outlook%20small.gif" alt="SpyNetGirl aka HotCakeX Outlook Email Address"> I can also be reached privately at: spynetgirl@outlook.com

<br>

<p align="right"><a href="#readme-top">💡 (back to top)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Security Recommendations<a href="#security-recommendations">![SecurityRecommendationIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/SecurityRecommendation.png)</a>

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/windows_346558782_611304884275369_8747802428749325762_n.jpg" alt="A beautiful pink laptop Windows 11, located on the table with coffee on the side" width="550"></p>

* <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/RedStar.gif" width="25" alt="Red Star denoting Security Recommendation"> Always download your operation system from [official Microsoft websites](https://www.microsoft.com/en-us/software-download). Right now, Windows 11 is the latest version of Windows, its ISO file can be downloaded from this [official Microsoft server](https://www.microsoft.com/en-us/software-download/windows11). One of the worst things you can do to your own security and privacy is downloading your OS, which is the root of all the active and passive security measures, from a 3rd party website claiming they have the official unmodified files. There are countless bad things that can happen as the result of it such as threat actors embedding malware or backdoors inside the customized OS, or pre-installing customized root CA certificates in your OS so that they can perform TLS termination and view all of your HTTPS and encrypted Internet data in plain clear text, **even if you use VPN.** Having a poisoned and compromised certificate store is the endgame for you, and *that's just the tip of the iceberg.*
  - Refer to [Wiki](https://github.com/HotCakeX/Harden-Windows-Security/wiki) to see [how to create Bootable USB flash drive with no 3rd party tools](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Bootable-USB-flash-drive-with-no-3rd-party-tools)

* <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/RedStar.gif" width="25" alt="Red Star denoting Security Recommendation"> Whenever you want to install a program or app, first use the [Microsoft Store](https://apps.microsoft.com/store/apps) or <a href="https://github.com/microsoft/winget-cli">Winget</a>, if the program or app you are looking for isn't available in there, then download it from its official website. *Somebody created a nice web interface for interacting with Winget CLI <a href="https://winstall.app/">here</a>.* Using Winget or Microsoft store provides many benefits:
  - Microsoft store UWP apps are secure in nature, digitally signed, in [MSIX format](https://learn.microsoft.com/en-us/windows/msix/overview). That means, installing and uninstalling them is guaranteed and there won't be any leftovers after uninstalling.
  - Microsoft store has Win32 apps too, they are traditional `.exe` installers that we are all familiar with. The store has a library feature that makes it easy to find the apps you previously installed.
  - Both Microsoft and Winget check the hash of the files by default, if a program or file is tampered, they will warn you and block the installation, whereas when you manually download a program from a website, you will have to manually verify the file hash with the hash shown on the website, if any.

* <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/RedStar.gif" width="25" alt="Red Star denoting Security Recommendation"> Use Secure DNS; Windows 11 natively supports <a href="https://learn.microsoft.com/en-us/windows-server/networking/dns/doh-client-support">DNS over HTTPS</a> and <a href="https://techcommunity.microsoft.com/t5/networking-blog/dns-over-tls-available-to-windows-insiders/ba-p/3565859">DNS over TLS</a>.
  - Use my [WinSecureDNSMgr module](https://github.com/HotCakeX/WinSecureDNSMgr) to easily configure DNS over HTTPS in Windows

* <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/RedStar.gif" width="25" alt="Red Star denoting Security Recommendation"> Only use Microsoft Edge for browser; It has [the Highest-rated protection](https://web.archive.org/web/20230103160041/https://learn.microsoft.com/en-us/deployedge/ms-edge-security-for-business#external-threat-protection) against [phishing](https://edgefrecdn.azureedge.net/shared/cms/lrs1c69a1j/public-files/473cac993bd24ae1947bd86e910d4d01.pdf) and [malware](https://edgefrecdn.azureedge.net/shared/cms/lrs1c69a1j/public-files/49958f5a10e748b28f1a235f6aac8d1e.pdf), available by default on Windows OS, has tightly integrated valuable Security features such as <a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-application-guard/md-app-guard-overview">Microsoft Defender Application Guard</a>, <a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-smartscreen/microsoft-defender-smartscreen-overview">Microsoft Defender SmartScreen</a>, <a href="https://support.microsoft.com/en-us/microsoft-edge/enhance-your-security-on-the-web-with-microsoft-edge-b8199f13-b21b-4a08-a806-daed31a1929d">Hardware Enforced Stack Protection</a>, <a href="https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exploit-protection-reference?view=o365-worldwide#arbitrary-code-guard">Arbitrary Code Guard (ACG)<a/>, <a href="https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exploit-protection-reference?view=o365-worldwide#control-flow-guard-cfg">Control Flow Guard (CFG)</a>, <a href="https://learn.microsoft.com/en-us/microsoft-edge/web-platform/tracking-prevention">Tracking Prevention</a> and <a href="https://support.microsoft.com/en-us/topic/use-the-microsoft-edge-secure-network-to-protect-your-browsing-885472e2-7847-4d89-befb-c80d3dda6318">Trusted built-in Secure Network feature from Cloudflare</a> just to name a few.

* <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/RedStar.gif" width="25" alt="Red Star denoting Security Recommendation"> [Always enable Two-Factor/Multi-Factor Authentication](https://support.microsoft.com/en-us/office/the-keys-to-the-kingdom-securing-your-devices-and-accounts-a925f8ad-af7e-40d8-9ce4-60ea1cac2ba4) on websites, apps and services that you use. Preferably, use [Microsoft Authenticator app](https://support.microsoft.com/en-us/account-billing/download-and-install-the-microsoft-authenticator-app-351498fc-850a-45da-b7b6-27e523b8702a) which has backup and restore feature, so you never lose access to your TOTPs (Time-Based One-Time Passwords) even if you lose your phone. Available for <a href="https://play.google.com/store/apps/details?id=com.azure.authenticator&gl=US">Android</a> and <a href="https://apps.apple.com/us/app/microsoft-authenticator/id983156458">IOS</a>. You can also use Microsoft Authenticator on Windows 11 (PC, Laptop or Tablet) using <a href="https://apps.microsoft.com/store/detail/windows-subsystem-for-android%E2%84%A2-with-amazon-appstore/9P3395VX91NR?hl=en-us&gl=us">Windows Subsystem for Android (WSA)</a> and access your authenticator codes without the need to use your phone (secure automatic backup/restore feature). Use an open and trusted Android store such as <a href="https://auroraoss.com/">Aurora Store</a> to <a href="https://github.com/whyorean/AuroraStore">install</a> and keep it up to date.

* <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/RedStar.gif" width="25" alt="Red Star denoting Security Recommendation"> Make sure OneDrive backup for important folders (Desktop/Documents/Pictures) is enabled. It is fast, secure and works in any network condition and since it's [x64 (64-bit)](https://techcommunity.microsoft.com/t5/microsoft-onedrive-blog/onedrive-sync-64-bit-for-windows-now-in-public-preview/ba-p/2260619), it can handle a Lot of small and large files simultaneously.

* <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/RedStar.gif" width="25" alt="Red Star denoting Security Recommendation"> If you live in a western country, NATO country, European country or Australia, do not use VPNs. **your local ISP (Internet service provider) is a lot more trustworthy than the remote VPN server's ISP.** Using VPN **only** takes the trust from your own local ISP and puts it in the hands of the remote ISP that the VPN server uses for its Internet, Nothing else. period. Do not fall for the fake advertisements of VPN companies, you never know who is behind the VPN provider, what their political views are, their background, where their allegiance lies. The permissive civilized western world could allow a state sponsor of terrorism or some other hostile country to create a VPN company in here and gather intelligence and collect bulk data for mining, tracking etc. this has happened before and one of [the most recent](https://www.techradar.com/news/iran-officials-linked-to-canada-based-free-vpn-provider) revelations is about a [VPN provider called Betternet, based in Canada](https://archive.ph/xOVeY), ran by [IRGC terrorists and their families abroad](https://twitter.com/lisa_loo_who/status/1567984903312257025). Stay vigilant and smart.
  - There are situations where using VPN can provide security and privacy. For example, when using a public WiFi hotspot or basically any network that you don't have control over. In such cases, use [Cloudflare WARP](https://cloudflarewarp.com/) which [uses WireGuard protocol](https://developers.cloudflare.com/warp-client/get-started/windows), *or as mentioned, use Secure Network in Edge browser that utilizes the same secure Cloudflare network*. It's free, it's from an American company that [has global radar](https://radar.cloudflare.com/) and lots of insight about countries in the world in real-time, [at least 19.7% of all websites use it (2022)](https://blog.cloudflare.com/application-security/). Safe to say it's one of the **backbones of the Internet.**

* <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/RedStar.gif" width="25" alt="Red Star denoting Security Recommendation"> [Go passwordless](https://support.microsoft.com/en-us/account-billing/how-to-go-passwordless-with-your-microsoft-account-674ce301-3574-4387-a93d-916751764c43) with your [Microsoft account](https://www.microsoft.com/en-us/security/blog/2021/09/15/the-passwordless-future-is-here-for-your-microsoft-account/) and use [Windows Hello authentication](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/hello-why-pin-is-better-than-password). In your Microsoft account which has Outlook service, [you can create up to 10 Email aliases](https://support.microsoft.com/en-us/office/add-or-remove-an-email-alias-in-outlook-com-459b1989-356d-40fa-a689-8f285b13f1f2) in addition to the 1 Email address you get when you made your Microsoft account, that means without creating a new account, you can have 11 Email addresses all of which will use the same inbox and account. You can specify which one of those Email aliases can be used to sign into your account, [in the sign in preferences of your Microsoft account settings](https://account.live.com/names/manage). So for example, when going passwordless, if you need you can give one of your Email aliases to others for communication or add it to a public profile of yours, then block sign in using that Email alias so nobody can send you authenticator notifications by entering that Email alias in the sign in page, and use the other 10 aliases that are private to sign into your Microsoft account with peace of mind. You can [create a rule in your Outlook](https://support.microsoft.com/en-us/office/inbox-rules-in-outlook-web-app-edea3d17-00c9-434b-b9b7-26ee8d9f5622) so that all of the Emails sent to your public Email alias will be stored in a different folder, apart from your other inbox emails. All of this can be done using free Microsoft account and [Outlook webapp](https://outlook.live.com/).

* <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/RedStar.gif" width="25" alt="Red Star denoting Security Recommendation"> Set a strong password for the UEFI firmware of your device so that it will ask for password before allowing any changes to be made to firmware. You can also configure the password to be required on startup.

* <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/RedStar.gif" width="25" alt="Red Star denoting Security Recommendation"> Use **NTFS** (which is the default Filesystem in Windows) or **ReFS** (Resilient File System, newer). In addition to all their benefits, they support `Mark Of The Web` (MOTW) or `zone.identifier`. When a file is downloaded to a device running Windows, Mark of the Web is added to the file, identifying its source as being from the internet. [You can read all the information about it in here](https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked#mark-of-the-web-and-trusted-documents). If your USB flash drive is formatted as `FAT32`, change it to `NTFS`, because `FAT32` does not keep the `MOTW` of the files. If the file you are downloading is compressed in `.zip` format, make sure you open/extract it using Windows built-in support for `.zip` files because it keeps the MOTW of the files. If the compressed file you downloaded is in other formats such as `.7zip` or `.rar`, make sure you use an archive program that supports keeping the mark of the Web of files after extraction. One of those programs is NanaZip which is a fork of 7zip, available in [Microsoft Store](https://www.microsoft.com/store/productId/9N8G7TSCL18R) and [GitHub](https://github.com/M2Team/NanaZip), compared to 7zip, it has better and modern GUI, and the application is [digitally signed](https://learn.microsoft.com/en-us/security/trusted-root/program-requirements). After installation, open it, navigate to `Tools` at the top then select `Options`, set `Propagate zone.id stream` to `Yes`. You can use this [PowerShell command](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-content?view=powershell-7.3#-stream) to find all the info about the Zone Identifier of the files you downloaded from the Internet.

```powershell
Get-Content <Path-To-File> -stream zone.identifier
```

* <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/RedStar.gif" width="25" alt="Red Star denoting Security Recommendation"> When using Xbox, make sure you [configure sign-in preference](https://support.xbox.com/en-US/help/account-profile/signin-security/change-signin-preferences) and set it to either `Ask for my PIN` or `Lock it down`. The latter is the most secure one since it will require authentication using Microsoft Authenticator app. `Ask for my PIN` is recommended for the most people because it will only require a PIN to be entered using controller.

* <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/RedStar.gif" width="25" alt="Red Star denoting Security Recommendation"> A few reminders about open source programs:
  - Unless you are a skilled programmer who can understand and verify every line of code in the source, and spends time to personally build the software from the source, and repeats all the aforementioned tasks for each subsequent version, then seeing the source code won't have any effect on you because you aren't able to understand nor verify it.
  
  - **The majority of "open source" programs are unsigned,** meaning they don't have a digital signature, their developers haven't bought and used a code signing certificate to sign their program. Among other problems, this poses a danger to the end-users, makes it harder to create trust for those programs in security solutions and makes it hard to authenticate them. [Read Microsoft's Introduction to Code Signing](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms537361(v=vs.85)) or [Digicert's 5 reasons why Code Signing is necessary.](https://www.websecurity.digicert.com/security-topics/why-use-code-signing)
  
  - [When using "open source" program,](https://www.youtube.com/clip/Ugkxa5lOPIfLs67tGP0QzWRHOfqf3CSRaa2S) there is not the kind of liability that you've got when you consume software from a commercial entity that is obligated and knows their reputation is at risk/stake, that they have potential legal liability if there are vulnerabilities in their software. In the open-source world, there is a volunteer, consume it as is, and if there is a problem with the software, that's your responsibility.

* <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/RedStar.gif" width="25" alt="Red Star denoting Security Recommendation"> More Security Recommendations coming soon...

<p align="right"><a href="#readme-top">💡 (back to top)</a></p>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Resources<a href="#resources">![ResourcesIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Resources.png)</a>

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/FwRjYavakAAIKn0.jpg" alt="A beautiful pink laptop Windows 11, located on the table with coffee on the side" width="600"></p>

- [Microsoft.com](https://microsoft.com)
  - [Force firmware code to be measured and attested by Secure Launch](https://www.microsoft.com/en-us/security/blog/2020/09/01/force-firmware-code-to-be-measured-and-attested-by-secure-launch-on-windows-10/)
- [Microsoft Learn](https://learn.microsoft.com/en-us/) - Technical Documentation
  - [Secure Launch—the Dynamic Root of Trust for Measurement (DRTM)](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/how-hardware-based-root-of-trust-helps-protect-windows#secure-launchthe-dynamic-root-of-trust-for-measurement-drtm)
  - [Quick guide to Windows as a service](https://learn.microsoft.com/en-us/windows/deployment/update/waas-quick-start)
- [Germany Intelligence Agency - BND](https://www.bsi.bund.de/EN/Service-Navi/Publikationen/publikationen_node.html) - Federal Office for Information Security
  - [Analysis of Device Guard](https://www.bsi.bund.de/EN/Service-Navi/Publikationen/Studien/SiSyPHuS_Win10/AP7/SiSyPHuS_AP7_node.html)
  - [Device Guard Differential Analysis](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Cyber-Sicherheit/SiSyPHus/E20172000_BSI_Win10_DGABGL_Win10_v_1_0.pdf?__blob=publicationFile&v=3)
- [Microsoft Tech Community](https://techcommunity.microsoft.com/) - Official blogs and documentations
- [Microsoft Security baselines](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines) - Security baselines from Microsoft
- [Microsoft Security Response Center (MSRC) YouTube channel](https://www.youtube.com/@microsoftsecurityresponsec2390)
  - [BlueHat Seattle 2019 || Guarding Against Physical Attacks: The Xbox One Story](https://www.youtube.com/watch?v=quLa6kzzra0)
  - [Security Update Guide:](https://msrc.microsoft.com/update-guide) The Microsoft Security Response Center (MSRC) investigates all reports of security vulnerabilities affecting Microsoft products and services, and provides the information here as part of the ongoing effort to help you manage security risks and help keep your systems protected.
  - [Microsoft Security Response Center Blog](https://msrc-blog.microsoft.com/)
- [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/)
- [Microsoft Podcasts](https://news.microsoft.com/podcasts/)
- [Bug Bounty Program](https://www.microsoft.com/en-us/msrc/bounty) - With bounties worth up to `250,000`$
- [Microsoft Active Protections Program](https://www.microsoft.com/en-us/msrc/mapp)
- [Security Update Guide FAQs](https://www.microsoft.com/en-us/msrc/faqs-security-update-guide)
- [Microsoft On the Issues](https://blogs.microsoft.com/on-the-issues/) - Assessments, Investigations and Reports of APTs (Advanced Persistent Threats[¹](https://learn.microsoft.com/en-us/events/teched-2012/sia303)) and nation-sponsored cyberattack operations globally
- [Center for Internet Security (CIS) Benchmarks](https://learn.microsoft.com/en-us/compliance/regulatory/offering-CIS-Benchmark)
- [A high level overview paper by Microsoft (in `PDF`)](http://download.microsoft.com/download/8/0/1/801358EC-2A0A-4675-A2E7-96C2E7B93E73/Framework_for_Cybersecurity_Info_Sharing.pdf), framework for cybersecurity information sharing and risk reduction.  
- [Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool) - for software architects and developers
- [Important events to monitor](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
- [Windows Security portal](https://learn.microsoft.com/en-us/windows/security/)
- [Security auditing](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [Microsoft SysInternals Sysmon for Windows Event Collection or SIEM](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Privileged Access Workstations](http://aka.ms/cyberpaw)
- [Enhanced Security Administrative Environment](http://aka.ms/ESAE)
- [New Zealand 2016 Demystifying the Windows Firewall – Learn how to irritate attackers without crippli](https://youtu.be/InPiE0EOArs)
- [Download Windows virtual machines ready for development](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)
- [UK National Cyber Security Centre Advice & guidance](https://www.ncsc.gov.uk/section/advice-guidance/all-topics)
- [Global threat activity](https://www.microsoft.com/en-us/wdsi/threats)
- [Microsoft Zero Trust](https://aka.ms/zerotrust)
- [Understanding malware & other threats, phrases](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/understanding-malware)
- [Malware naming](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/malware-naming)
- [Microsoft Digital Defense Report](https://www.microsoft.com/en-us/security/business/microsoft-digital-defense-report)
- [Microsoft Defender for Individuals](https://www.microsoft.com/en-us/microsoft-365/microsoft-defender-for-individuals)
- [Submit a file for malware analysis](https://www.microsoft.com/en-us/wdsi/filesubmission)
- [Submit a driver for analysis](https://www.microsoft.com/en-us/wdsi/driversubmission)
- [Service health status](https://admin.microsoft.com/servicestatus)
- [Microsoft Defender Threat Intelligence](https://ti.defender.microsoft.com/)
  - [Free community edition vs Premium edition comparison](https://jeffreyappel.nl/how-works-microsoft-defender-threat-intelligence-defender-ti-and-what-is-the-difference-between-free-and-paid/)
- [Microsoft Virus Initiative](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/virus-initiative-criteria)
- [Digital Detectives @Microsoft](https://news.microsoft.com/stories/cybercrime/)
- [Goblin Loot - Great security related website about EDR, Cloud and Microsoft products](https://www.goblinloot.net/)

<p align="right"><a href="#readme-top">💡 (back to top)</a></p>

<br>

## License<a href="#license">![LicenseFreeIcon](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/LicenseFree.png)</a>

Using [GPL-2.0 license](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE). Just free information, because the only mission of this GitHub repository is to give all Windows users accurate, up to date and correct facts and information about how to stay secure and safe in dangerous environments, and to stay not one, but Many steps, ahead of threat actors.

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="Harden-Windows-Security is a PowerShell script">

<br>

<p align="center">
<a href="https://github.com/HotCakeX"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/HotCakeX/main/Private/Images/Socials/github.svg"></a>
<a href="https://www.last.fm/user/HotCakeX"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/HotCakeX/main/Private/Images/Socials/lastfm.png"></a>
<a href="https://1drv.ms/f/s!AtCaUNAJbbvIhuITM8K09FBn-Q9GDw?e=3PAGmg"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/HotCakeX/main/Private/Images/Socials/microsoft-onedrive-2019.svg"></a>
<a href="https://open.spotify.com/user/eypgh60p3zw1duh9lbsbc2mix"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/HotCakeX/main/Private/Images/Socials/spotify.svg"></a>
<a href="https://stackexchange.com/users/27823952/spynet"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/HotCakeX/main/Private/Images/Socials/stack-exchange.svg"></a>
<a href="https://steamcommunity.com/id/HotCakeX"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/HotCakeX/main/Private/Images/Socials/steam.svg"></a>
<a href="https://www.twitch.tv/hot_cakex"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/HotCakeX/main/Private/Images/Socials/twitch.svg"></a>
<a href="https://hotcakex.github.io/"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/HotCakeX/main/Private/Images/Socials/website-96.png"></a>
<a href="https://twitter.com/SpyNetGirl"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/HotCakeX/main/Private/Images/Socials/witter.svg"></a>
<a href="https://www.xbox.com/en-US/play/user/HottCakeX"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/HotCakeX/main/Private/Images/Socials/xbox.svg"></a>
<a href="https://www.youtube.com/@hotcakex"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/HotCakeX/main/Private/Images/Socials/youtube.svg"></a>
<a href="https://www.reddit.com/user/HotCakeXXXXXXXXXXXXX"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/HotCakeX/main/Private/Images/Socials/reddit.svg"></a>
<a href="https://socialclub.rockstargames.com/member/----HotCakeX----/"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/HotCakeX/main/Private/Images/Socials/rockstar-social-club.svg"></a>
<a href="https://club.ubisoft.com/en-US/profile/HotCakeX"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/HotCakeX/main/Private/Images/Socials/uplay.svg"></a>
<a href="https://techcommunity.microsoft.com/t5/user/viewprofilepage/user-id/310193"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/HotCakeX/main/Private/Images/Socials/microsoft.png"></a>
<a href="mailto:spynetgirl@outlook.com"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/HotCakeX/main/Private/Images/Socials/outlook.svg"></a>
<a href="https://orcid.org/0009-0000-6616-4938"><img width="30" height="30" src="https://raw.githubusercontent.com/HotCakeX/HotCakeX/main/Private/Images/Socials/orcid_icon.png"></a>
</p>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="Harden-Windows-Security is a PowerShell script">

<p align="center"> <a href="#readme-top">

<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/AU.png" alt="Flag of Australia">
<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/USA.png" alt="Flag of United States">
<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/EU.png" alt="Flag of EU">
<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/NATO.png" alt="Flag of NATO">
<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/UK.png" alt="Flag of United Kingdom">
<img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Israel.png" alt="Flag of Israel">

</a> </p>
