# Microsoft Defender | Harden System Security

## Exclusions Tab

A unified view that aggregates Microsoft Defender exclusions from multiple branches:
   1. File and folder path exclusions
   2. Process exclusions
   3. Extension exclusions
   4. Controlled Folder Access exclusions
   5. Attack Surface Reduction (ASR) rules exclusions

You can retrieve, filter, sort, and search exclusions across these branches. Adding and removing exclusions is supported directly from the UI.

<br>

## Security Measures Tab

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/d6960a261913f979526c0fac7901effa4b72d813/Pictures/Readme%20Categories/Microsoft%20Defender/Microsoft%20Defender.svg" alt="Microsoft Defender Cloud Protection features and abilities" width="450"></p>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Extends the [Cloud Security Scan](https://support.microsoft.com/en-us/topic/what-is-a-cloud-security-scan-75112696-7660-4450-9194-d717f72a8ad8) time to the maximum amount of 60 seconds, by default it is 10 seconds. You need to be aware that this means actions like downloading and opening an unknown file **will** make Microsoft Defender send samples of it to the Cloud for more advanced analysis and it can take a maximum of 60 seconds from the time you try to open that unknown file to the time when it will be opened (if deemed safe). <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#cloudextendedtimeout)

   - Here is an example of the notification you will see in Windows 11 if that happens.

    <p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Windows%20Security%20Cloud%20Analysis.png" alt="Windows Security Cloud Scan Notification" width="200"></p>

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Configures the Cloud Block/Protection Level to the **maximum level of Zero Tolerance and [Block At First Sight](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus?view=o365-worldwide#turn-on-block-at-first-sight-with-group-policy)**. No unknown file can run on your system without first being recognized by the Microsoft's Security Graph and other **globally omniscient systems**. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#cloudblocklevel)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Configures the Microsoft Defender to send all samples automatically. Increasing protection by participating in the SpyNet / MAPS network. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#submitsamplesconsent)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Sets the SpyNet membership to Advanced, improving Cloud Protection. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#allowcloudprotection)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables file hash computation; [designed](https://learn.microsoft.com/powershell/module/defender/set-mppreference?view=windowsserver2022-ps#-enablefilehashcomputation) to allow admins to force the anti-malware solution to "compute file hashes for every executable file that is scanned if it wasn't previously computed" to "improve blocking for custom indicators in Microsoft Defender Advanced Threat Protection (Microsoft Defender ATP). <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#mpengine_enablefilehashcomputation)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Clears Quarantined items after 1 day instead of the default behavior of keeping them indefinitely. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#quarantine_purgeitemsafterdelay)

   * Quarantine involves isolating potentially harmful files in a non-executable area of your system to prevent any risk of execution. To further minimize potential threats, quarantined files are automatically removed after 1 day, rather than being retained indefinitely. This precaution helps mitigate the possibility of these files exploiting unforeseen vulnerabilities in the future, ensuring a proactive approach to system security.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Allows Microsoft Defender to download security updates even on a metered connection. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp?WT.mc_id=Portal-fx#configurationmeteredconnectionupdates)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables Microsoft Defender to scan mapped network drives during full scan. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#allowfullscanonmappednetworkdrives)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables Microsoft Defender to scan emails. The engine will parse the mailbox and mail files. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#allowemailscanning)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables Microsoft Defender to scan Removable Drives. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#allowfullscanremovabledrivescanning)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables Microsoft Defender to scan [Reparse Points](https://learn.microsoft.com/windows/win32/fileio/reparse-points). <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#scan_disablereparsepointscanning)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Forces [Microsoft Defender](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-advanced-scan-types-microsoft-defender-antivirus?view=o365-worldwide#settings-and-locations) to scan network files.  <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#allowscanningnetworkfiles)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Sets the Signature Update Interval to every 3 hours instead of automatically. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#signatureupdateinterval)

    - [Change logs for security intelligence updates](https://www.microsoft.com/en-us/wdsi/definitions/antimalware-definition-release-notes)

    - [Configure and validate Microsoft Defender Antivirus network connections](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-network-connections-microsoft-defender-antivirus?view=o365-worldwide)

    - [Security intelligence updates for Microsoft Defender Antivirus and other Microsoft antimalware](https://www.microsoft.com/en-us/wdsi/defenderupdates)

    - [Microsoft Safety Scanner](https://learn.microsoft.com/microsoft-365/security/intelligence/safety-scanner-download?view=o365-worldwide)

    - Paste the following PowerShell code to retrieve the latest available online versions of the Platform, Signatures, and Engine for Microsoft Defender
  -
    ```powershell
    $X = irm "https://www.microsoft.com/security/encyclopedia/adlpackages.aspx?action=info"
    @{Engine = $X.versions.engine; Signatures = $X.versions.signatures.'#text'; Platform = $X.versions.platform} | ft -AutoSize
    ```

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Forces Microsoft Defender to check for new virus and spyware definitions before it runs a scan. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#checkforsignaturesbeforerunningscan)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Makes Microsoft Defender run [catch-up scans](https://learn.microsoft.com/powershell/module/defender/set-mppreference?view=windowsserver2022-ps#-disablecatchupquickscan) for scheduled quick scans. A computer can miss a scheduled scan, usually because the computer is off at the scheduled time, but now after the computer misses two scheduled quick scans, Microsoft Defender runs a catch-up scan the next time someone logs onto the computer. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#disablecatchupquickscan)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables [Network Protection of Microsoft Defender](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/network-protection?view=o365-worldwide) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#enablenetworkprotection)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Enables [scanning of restore points](https://learn.microsoft.com/powershell/module/defender/set-mppreference#-disablerestorepoint) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#scan_disablerestorepoint)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Makes sure [Async Inspection for Network protection](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/network-protection?view=o365-worldwide#optimizing-network-protection-performance) of Microsoft Defender is turned on - Network protection now has a performance optimization that allows Block mode to start asynchronously inspecting long connections after they're validated and allowed by SmartScreen, which might provide a potential reduction in the cost that inspection has on bandwidth and can also help with app compatibility problems. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp?WT.mc_id=Portal-fx#configurationallowswitchtoasyncinspection)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/discord-verify-gradient.gif" width="25" alt="Rotating green checkmark denoting Subcategory"> Enables [Smart App Control](https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003) (*if it's in Evaluation mode*): adds significant protection from new and emerging threats by blocking apps that are malicious or untrusted. Smart App Control also helps to block potentially unwanted apps, which are apps that may cause your device to run slowly, display unexpected ads, offer extra software you didn't want, or do other things you don't expect.

    - Smart App Control is User-Mode (and enforces Kernel-Mode) [App Control for Business](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/appcontrol-design-guide), **more info** [**in the Wiki**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction). You can see its status in [System Information](https://support.microsoft.com/en-us/windows/view-your-system-info-a965a8f2-0773-1d65-472a-1e747c9ebe00) and enable it manually from Microsoft Defender app's GUI. It is very important for Windows and Windows Defender intelligence updates to be always up-to-date in order for Smart App Control to work properly as it relies on live intelligence and definition data from the cloud and other sources to make a Smart decision about programs and files it encounters.

    - Smart App Control uses [ISG (Intelligent Security Graph)](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph#how-does-app-control-work-with-the-isg). The ISG isn't a "list" of apps. Rather, it uses the same vast security intelligence and machine learning analytics that power Microsoft Defender SmartScreen and Microsoft Defender Antivirus to help classify applications as having "known good", "known bad", or "unknown" reputation. This cloud-based AI is based on trillions of signals collected from Windows endpoints and other data sources and processed every 24 hours. As a result, the decision from the cloud can change.

    - [Smart App Control](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/appcontrol#app-control-and-smart-app-control) can block a program entirely from running or only [some parts of it](https://support.microsoft.com/en-us/topic/smart-app-control-has-blocked-part-of-this-app-0729fff1-48bf-4b25-aa97-632fe55ccca2) in which case your app or program will continue working just fine most of the time. It's improved a lot since it was introduced, and it continues doing so. Consider turning it on after clean installing a new OS and fully updating it.

    - Smart App Control enforces the [Microsoft Recommended Driver Block rules](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) and the [Microsoft Recommended Block Rules](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol)

    - Once you turn Smart App Control off, it can't be turned on without resetting or reinstalling Windows.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/discord-verify-gradient.gif" width="25" alt="Rotating green checkmark denoting Subcategory"> Enables ["Send optional diagnostic data"](https://learn.microsoft.com/windows/privacy/windows-diagnostic-data) because [it](https://learn.microsoft.com/windows/privacy/configure-windows-diagnostic-data-in-your-organization) is [required for Smart App Control](https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003) **to operate when it's in evaluation mode or turned on, and for communication with [Intelligent Security Graph (ISG)](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph).** This setting will be automatically applied if Smart App Control is already turned on or you choose to turn it on. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-system#allowtelemetry)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables [Controlled Folder Access](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/enable-controlled-folders). It [helps protect your valuable data](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/controlled-folders) from malicious apps and threats, such as ransomware. Controlled folder access protects your data by checking apps against a list of known, trusted apps. Due to the recent wave of global ransomware attacks, it is important to use this feature to protect your valuables files, specially OneDrive folders. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#enablecontrolledfolderaccess)

    - If it blocks a program from accessing one of your folders it protects, and you absolutely trust that program, then you can add it to exclusion list using Microsoft Defender GUI or PowerShell. you can also query the list of allowed apps using PowerShell (commands below). with these commands, you can backup your personalized list of allowed apps, that are relevant to your system, and restore them in case you clean install your Windows.

    - <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> The root of the OneDrive folders of all the user accounts will be added to the protected folders list of Controlled Folder Access, to provide Ransomware protection for the entire OneDrive folder. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#controlledfolderaccessprotectedfolders)

  -
    ```powershell
    # Add multiple programs to the exclusion list of Controlled Folder Access
    Add-MpPreference -ControlledFolderAccessAllowedApplications 'C:\Program Files\App\app.exe','C:\Program Files\App2\app2.exe'
    ```

  -
    ```powershell
    # Get the list of all allowed apps
    (Get-MpPreference).ControlledFolderAccessAllowedApplications
    ```

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Enables [Mandatory ASLR,](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/enable-exploit-protection?view=o365-worldwide) *It might cause compatibility issues* only for some **poorly-made 3rd party programs**, specially portable ones. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-exploitguard)

    - Automatically detects and excludes the Git executables of GitHub Desktop and Git (Standalone version) from mandatory ASLR if they are installed on the system. [More info here](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Git-GitHub-Desktop-and-Mandatory-ASLR)

    - You can add Mandatory ASLR override for a trusted program using the PowerShell command below or in the Program Settings section of Exploit Protection in Microsoft Defender app.

        - `Set-ProcessMitigation -Name "C:\TrustedApp.exe" -Disable ForceRelocateImages`

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Applies [Exploit Protections/Process Mitigations](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/enable-exploit-protection) from [**this list**](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Harden-Windows-Security%20Module/Main%20files/Resources/ProcessMitigations.csv) to the following programs: <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-exploitguard)

    - All channels of [Microsoft Edge](https://www.microsoft.com/en-us/edge) browser

    - [Quick Assist](https://learn.microsoft.com/windows/client-management/client-tools/quick-assist) app

    - Some System processes

    - Microsoft 365 apps

    - More apps and processes will be added to the list over time once they are properly validated to be fully compatible.

    - Exploit Protection configurations are also accessible in XML format [within this repository](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/Intune%20Files/Hardening%20Policies/Exploit%20Protections). When implementing exploit protections using an XML file, the existing exploit mitigations will seamlessly integrate rather than being overwritten. Should there be pre-existing exploit protections applied to an executable on the system, and the XML file specifies different mitigations for the same executable, these protections will be merged and applied collectively.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> [Turns on Data Execution Prevention](https://learn.microsoft.com/windows-hardware/drivers/devtest/bcdedit--set) (DEP) for all applications, including 32-bit programs. By default, the output of `BCDEdit /enum "{current}"` (in PowerShell) for the NX bit is `OptIn` but the Harden System Security app sets it to `AlwaysOn`

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Check for the latest virus and spyware security intelligence on startup. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#signatureupdate_updateonstartup)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Specifies the maximum depth to scan archive files to the maximum possible value of `4,294,967,295` <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#scan_archivemaxdepth)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Defines the maximum size of downloaded files and attachments to be scanned](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-advanced-scan-types-microsoft-defender-antivirus?view=o365-worldwide) and set it to the maximum possible value of `10,000,000 KB` or `10 GB`. [the default is](https://github.com/MicrosoftDocs/microsoft-365-docs/pull/5600) `20480 KB` or `~20MB` <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#realtimeprotection_ioavmaxsize)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables the [Enhanced Phishing Protection](https://learn.microsoft.com/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/enhanced-phishing-protection) service. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-webthreatdefense#serviceenabled)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables notifying user of malicious and phishing scenarios in Microsoft Defender Enhanced Phishing Protection. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-webthreatdefense#notifymalicious)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables the feature in Enhanced Phishing Protection in Microsoft Defender SmartScreen that warns users if they reuse their work or school password. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-webthreatdefense#notifypasswordreuse)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables warning users if they type their work or school passwords in unsafe apps. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-webthreatdefense#notifyunsafeapp)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables automatic data collection (formerly known as Capture Threat Window) of Enhanced Phishing Protection in Microsoft Defender SmartScreen for security analysis from a suspicious website or app. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-webthreatdefense#automaticdatacollection)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/discord-verify-gradient.gif" width="25" alt="Rotating green checkmark denoting Subcategory"> [Creates scheduled task for fast weekly Microsoft recommended driver block list update.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Fast-and-Automatic-Microsoft-Recommended-Driver-Block-Rules-updates). You won't see this prompt if the task already exists and is enabled or running.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/discord-verify-gradient.gif" width="25" alt="Rotating green checkmark denoting Subcategory"> Set Microsoft [Defender engine](https://learn.microsoft.com/powershell/module/defender/set-mppreference#-engineupdateschannel) and [platform update channel](https://learn.microsoft.com/powershell/module/defender/set-mppreference#-platformupdateschannel) to beta. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp?WT.mc_id=Portal-fx#configurationengineupdateschannel) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp?WT.mc_id=Portal-fx#configurationplatformupdateschannel)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Defines](https://learn.microsoft.com/defender-endpoint/manage-outdated-endpoints-microsoft-defender-antivirus?view=o365-worldwide#use-group-policy-to-specify-the-number-of-days-before-protection-is-considered-out-of-date) the number of days before spyware security intelligence is considered out of date to 2. The default is 7. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#signatureupdate_assignaturedue)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Defines the number of days before virus security intelligence is considered out of date to 2. The default is 7. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#signatureupdate_avsignaturedue)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Sets the [default action](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-remediation-microsoft-defender-antivirus) for Severe and High threat levels to Remove, for Medium and Low threat levels to Quarantine. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#threats_threatiddefaultaction)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Configures real-time protection and Security Intelligence Updates to be enabled during OOBE. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationoobeenablertpandsigupdate)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables the [Intel TDT](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/defending-against-ransomware-with-microsoft-defender-for/ba-p/3243941) (Intel® Threat Detection Technology) integration with Microsoft Defender. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationinteltdtenabled)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Disables [Performance Mode](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/microsoft-defender-endpoint-antivirus-performance-mode) - [Security risks in relation to Dev Drive](https://learn.microsoft.com/windows/dev-drive/#understanding-security-risks-and-trust-in-relation-to-dev-drive) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp?WT.mc_id=Portal-fx#configurationperformancemodestatus)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Enables a network protection setting that blocks malicious network traffic instead of displaying a warning. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationenableconvertwarntoblock)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Configures the Brute-Force Protection to use cloud aggregation to block IP addresses that are over 99% likely malicious <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationbehavioralnetworkblocksbruteforceprotectionbruteforceprotectionaggressiveness)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Configures the Brute-Force Protection to detect and block attempts to forcibly sign in and initiate sessions <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationbehavioralnetworkblocksbruteforceprotectionbruteforceprotectionconfiguredstate)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Sets the internal feature logic to determine blocking time for the Brute-Force Protections <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationbehavioralnetworkblocksbruteforceprotectionbruteforceprotectionmaxblocktime)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Configures the Remote Encryption Protection to use cloud intel and context, and block when confidence level is above 90%. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationbehavioralnetworkblocksremoteencryptionprotectionremoteencryptionprotectionaggressiveness)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Configures the Remote Encryption Protection to detect and block attempts to replace local files with encrypted versions from another device <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationbehavioralnetworkblocksremoteencryptionprotectionremoteencryptionprotectionconfiguredstate)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Sets the internal feature logic to determine blocking time for the Remote Encryption Protection <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationbehavioralnetworkblocksremoteencryptionprotectionremoteencryptionprotectionmaxblocktime)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Extends the brute-force protection coverage in the Microsoft Defender Antivirus to block local network addresses. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationbehavioralnetworkblocksbruteforceprotectionbruteforceprotectionpluginsbruteforceprotectionlocalnetworkblocking)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Enables [ECS Configurations](https://learn.microsoft.com/defender-endpoint/microsoft-defender-core-service-configurations-and-experimentation) in the Microsoft Defender. They improve product health and security by *automatically* fixing any possible issues/bugs that may arise, in a timely manner.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables Network Protection to be configured into block or audit mode on Windows Server. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationallownetworkprotectiononwinserver)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Runs Microsoft Defender Antivirus in [Sandbox Mode](https://learn.microsoft.com/en-us/defender-endpoint/sandbox-mdav) for enhanced protection against tampering.

<br>

> [!TIP]\
> [Performance analyzer for Microsoft Defender Antivirus](https://learn.microsoft.com/defender-endpoint/tune-performance-defender-antivirus)

<br>
