# Windows Update | Harden System Security

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/d6960a261913f979526c0fac7901effa4b72d813/Pictures/Readme%20Categories/Windows%20Update/Windows%20Update.svg" alt="Windows Update - Harden Windows Security GitHub repository" width="500"></p>

<br>

Windows updates are extremely important. They always should be installed as fast as possible to stay secure and if a reboot is required, it should be done immediately. Threat actors can weaponize publicly disclosed vulnerabilities [**the same day** their POC (Proof-Of-Concept) is released.](https://www.microsoft.com/en-us/security/blog/2023/04/18/nation-state-threat-actor-mint-sandstorm-refines-tradecraft-to-attack-high-value-targets/).

In Windows by default, devices will scan daily, automatically download and install any applicable updates at a time optimized to reduce interference with usage, and then automatically try to restart when the end user is away.

**The following policies [the app](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security) configures make sure the default behavior explained above is tightly enforced.**

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables [Windows Update to download and install updates on any network](https://techcommunity.microsoft.com/t5/windows-it-pro-blog/the-windows-update-policies-you-should-set-and-why/ba-p/3270914), metered or not; because the updates are important and should not be suppressed, **that's what bad actors would want.** <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-update#allowautowindowsupdatedownloadovermeterednetwork)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables "Receive Updates for other Microsoft products" (such as PowerShell)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Enables "Notify me when a restart is required to finish updating". <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-update#schedulerestartwarning)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Specifies the number of days before quality updates are installed on devices automatically to 1 day. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-update#configuredeadlinenoautorebootforqualityupdates)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Specifies the number of days before feature updates are installed on devices automatically to 1 day. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-update#configuredeadlinenoautorebootforfeatureupdates)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Sets the number of grace period days before feature updates are installed on devices automatically to 1 day. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-update#configuredeadlinegraceperiodforfeatureupdates)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Sets the number of grace period days before quality updates are installed on devices automatically to 1 day. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-update#configuredeadlinegraceperiod)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Configures the automatic updates to happen every day, automatically be downloaded and installed, notify users for restart. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-update#allowautoupdate)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Enables features introduced via servicing that are off by default](https://learn.microsoft.com/windows/deployment/update/waas-configure-wufb) so that users will be able to get new features after having Windows Update settings managed by Group Policy as the result of running this category. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-update?toc=%2Fwindows%2Fdeployment%2Ftoc.json&bc=%2Fwindows%2Fdeployment%2Fbreadcrumb%2Ftoc.json#allowtemporaryenterprisefeaturecontrol)

<br>

## Management

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/cbf0e2dbbfdcfb78b7891329ef72703bbebfeb04/Pictures/PNG%20and%20JPG/Harden%20System%20Security%20page%20screenshots/Windows%20Update%20Management.png" alt="Windows Update - Harden Windows Security GitHub repository"></p>

<br>

The management tab is designed to show available Windows updates that are not currently installed. Users can retrieve the available update list, inspect detailed metadata for each update, hide or unhide selected updates, sort updates by deployment date and export update metadata to JSON.

Being able to hide updates is useful in some scenarios, for example when a specific update is causing issues and you want to prevent it from being installed until a fix is released, or when Windows Update offers [an old driver version even if newer version is installed](https://www.intel.com/content/www/us/en/support/articles/000087834/graphics.html). Each hidden update can be shown again easily via the UI controls.

Updates available in Windows carry a lot of metadata with them but Windows Update in Windows Settings only displays a tiny fraction of it. The management tab in the app allows users to inspect all the metadata for each update, which can be useful to understand what the update is about, its severity, whether it's a security update or not, the link to online articles and so much more. You can also instantly export them to JSON file, which can be useful for further analysis or record-keeping.
