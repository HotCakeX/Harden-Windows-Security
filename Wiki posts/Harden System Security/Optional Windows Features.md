# Optional Windows Features | Harden System Security

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/d6960a261913f979526c0fac7901effa4b72d813/Pictures/Readme%20Categories/Optional%20Windows%20Features/Optional%20Windows%20Features.png" alt="Optional Windows Features - Harden Windows Security GitHub repository" width="500"></p>

<br>

## Full Customization

On this page, the Harden System Security app offers a fully featured list of every single Windows Feature and Capability with searching and sorting functionalities, allowing you to easily enable or disable each of them with real time progress display.

Use the `Retrieve Recommended Only` option under the `Retrieve All` button to only retrieve the status of the items listed on this page; It completes a lot faster than retrieving all the items.

<br>

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/c22418f6d2605c77ea4c05dfd42f2c85ef0191eb/Pictures/APNGs/Harden%20System%20Security/HardenSystemSecurity_OptionalWindowsFeaturesDemo.apng" alt="Optional Windows Features Page Demo of the Harden System Security App" />

</div>

<br>

## Recommended Configurations

Use the 3 apply, remove or verify buttons on this page to apply the security configurations states explained below. They enable/disable only specific Windows Features and capabilities to provide optimal security for your system:

- The [Harden System Security app](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security) [disables](https://learn.microsoft.com/powershell/module/dism/disable-windowsoptionalfeature) the following rarely used features in [Windows optional features](https://learn.microsoft.com/windows/application-management/add-apps-and-features#use-windows-powershell-to-disable-specific-features) (Control Panel):

    - PowerShell v2: because it's old and doesn't support [AMSI](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/#antimalware-scan-interface-integration).

    - Work Folders client: not used when your computer is not part of a domain or enterprise network.

    - Internet Printing Client: used in combination with IIS web server, [old feature](https://learn.microsoft.com/troubleshoot/windows-server/printing/manage-connect-printers-use-web-browser), can be disabled without causing problems further down the road.

    - Windows Media Player (legacy): isn't needed anymore, [Windows 11 has a modern media player app](https://blogs.windows.com/windows-insider/2021/11/16/new-media-player-for-windows-11-begins-rolling-out-to-windows-insiders/).

<br>

- [Uninstalls](https://learn.microsoft.com/powershell/module/dism/remove-windowscapability) these optional features (Windows Settings -> Apps -> Optional Features):

    - Notepad (system): legacy Notepad program. Windows 11 has multi-tabbed modern Notepad app.

    - VBSCRIPT: a legacy [deprecated](https://learn.microsoft.com/windows/whats-new/deprecated-features) scripting engine component, [Microsoft does not recommend](https://techcommunity.microsoft.com/t5/windows-insider-program/windows-11-insider-dev-build-25309-allows-for-uninstallation-of/m-p/3759739) using this component unless and until it is really required.

    - [Internet Explorer mode for Edge browser](https://learn.microsoft.com/deployedge/edge-ie-mode): It's only used by a few possible organizations that have very old internal websites.

    - [WMIC](https://learn.microsoft.com/windows/win32/wmisdk/wmic): Old and [deprecated](https://learn.microsoft.com/windows/whats-new/deprecated-features), not secure and is in [Microsoft recommended block rules.](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol)

    - WordPad: Old and [deprecated](https://learn.microsoft.com/windows/whats-new/deprecated-features). None of the new features of Word documents are supported in it. Recommended to use [Word Online](https://www.microsoft.com/en-us/microsoft-365/free-office-online-for-the-web), Notepad or M365 Word.

    - [PowerShell ISE](https://learn.microsoft.com/powershell/scripting/windows-powershell/ise/introducing-the-windows-powershell-ise): Old PowerShell environment that doesn't support versions above 5.1. Highly recommended to use [Visual Studio Code](https://apps.microsoft.com/detail/xp9khm4bk9fz7q) for PowerShell usage and [learning](https://github.com/HotCakeX/Harden-Windows-Security/wiki#-powershell). You can even replicate the [ISE experience in Visual Studio Code](https://learn.microsoft.com/powershell/scripting/dev-cross-plat/vscode/how-to-replicate-the-ise-experience-in-vscode). You can access [Visual Studio Code online in your browser](https://vscode.dev) without the need to install anything.

    - Steps Recorder: it's [deprecated](https://support.microsoft.com/en-us/windows/steps-recorder-deprecation-a64888d7-8482-4965-8ce3-25fb004e975f).

<br>

- [Enables](https://learn.microsoft.com/powershell/module/dism/enable-windowsoptionalfeature) these optional features (Control Panel):

    - [Windows Sandbox](https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview): install, test and use programs in a disposable virtual operating system, completely separate from your main OS

    - Hyper-V: a great hybrid hypervisor (Type 1 and Type 2) to run virtual machines on. [check out this Hyper-V Wiki page](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Hyper-V)

<br>

## Network Adapters

Windows includes pre-loaded Ethernet and Wi-Fi network adapter drivers to enable internet connectivity during the Out-of-Box Experience (OOBE) without requiring manual driver installation. These drivers support hardware from manufacturers such as Intel, Qualcomm, Broadcom, Marvell, Realtek, Ralink, and others.

Using the Harden System Security app, you can remove unnecessary drivers or those associated with OEM hardware you do not own. This process helps freeing up disk space and reduce the overall attack surface.

<br>
