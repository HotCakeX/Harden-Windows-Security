# Microsoft Defender | Harden System Security

## Exclusions Tab

A unified view that aggregates Microsoft Defender exclusions from multiple branches:

1.  File and folder path exclusions
2.  Process exclusions
3.  Extension exclusions
4.  Controlled Folder Access exclusions
5.  Attack Surface Reduction (ASR) rules exclusions

You can retrieve, filter, sort, and search exclusions across these branches. Adding and removing exclusions is supported directly from the UI.

## Security Measures Tab

- **[Group Policy]** Extends the [Cloud Security Scan](https://support.microsoft.com/en-us/topic/what-is-a-cloud-security-scan-75112696-7660-4450-9194-d717f72a8ad8) time to the maximum amount of 60 seconds, by default it is 10 seconds. You need to be aware that this means actions like downloading and opening an unknown file **will** make Microsoft Defender send samples of it to the Cloud for more advanced analysis and it can take a maximum of 60 seconds from the time you try to open that unknown file to the time when it will be opened (if deemed safe). **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#cloudextendedtimeout)

  - Here is an example of the notification you will see in Windows 11 if that happens.

    <p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Windows%20Security%20Cloud%20Analysis.png" alt="Windows Security Cloud Scan Notification" width="200"></p>

- **[Group Policy]** Configures the Cloud Block/Protection Level to the **maximum level of Zero Tolerance and [Block At First Sight](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus?view=o365-worldwide#turn-on-block-at-first-sight-with-group-policy)**. No unknown file can run on your system without first being recognized by the Microsoft's Security Graph and other **globally omniscient systems**. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#cloudblocklevel)

- **[Group Policy]** Configures the Microsoft Defender to send all samples automatically. Increasing protection by participating in the SpyNet / MAPS network. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#submitsamplesconsent)

- **[Group Policy]** Sets the SpyNet membership to Advanced, improving Cloud Protection. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#allowcloudprotection)

- **[Group Policy]** Enables file hash computation; designed to allow admins to force the anti-malware solution to "compute file hashes for every executable file that is scanned if it wasn't previously computed" to "improve blocking for custom indicators in Microsoft Defender Advanced Threat Protection (Microsoft Defender ATP). **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#mpengine_enablefilehashcomputation)

- **[Group Policy]** Clears Quarantined items after 1 day instead of the default behavior of keeping them indefinitely. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#quarantine_purgeitemsafterdelay)

  - Quarantine involves isolating potentially harmful files in a non-executable area of your system to prevent any risk of execution. To further minimize potential threats, quarantined files are automatically removed after 1 day, rather than being retained indefinitely. This precaution helps mitigate the possibility of these files exploiting unforeseen vulnerabilities in the future, ensuring a proactive approach to system security.

- **[Group Policy]** Allows Microsoft Defender to download security updates even on a metered connection. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp?WT.mc_id=Portal-fx#configurationmeteredconnectionupdates)

- **[Group Policy]** Enables Microsoft Defender to scan mapped network drives during full scan. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#allowfullscanonmappednetworkdrives)

- **[Group Policy]** Enables Microsoft Defender to scan emails. The engine will parse the mailbox and mail files. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#allowemailscanning)

- **[Group Policy]** Enables Microsoft Defender to scan Removable Drives. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#allowfullscanremovabledrivescanning)

- **[Group Policy]** Enables Microsoft Defender to scan [Reparse Points](https://learn.microsoft.com/windows/win32/fileio/reparse-points). **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#scan_disablereparsepointscanning)

- **[Group Policy]** Forces [Microsoft Defender](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-advanced-scan-types-microsoft-defender-antivirus?view=o365-worldwide#settings-and-locations) to scan network files. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#allowscanningnetworkfiles)

- **[Group Policy]** Sets the Signature Update Interval to every 3 hours instead of automatically. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#signatureupdateinterval)

  - [Change logs for security intelligence updates](https://www.microsoft.com/en-us/wdsi/definitions/antimalware-definition-release-notes)

  - [Configure and validate Microsoft Defender Antivirus network connections](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-network-connections-microsoft-defender-antivirus?view=o365-worldwide)

  - [Security intelligence updates for Microsoft Defender Antivirus and other Microsoft antimalware](https://www.microsoft.com/en-us/wdsi/defenderupdates)

  - [Microsoft Safety Scanner](https://learn.microsoft.com/microsoft-365/security/intelligence/safety-scanner-download?view=o365-worldwide)

- **[Group Policy]** Forces Microsoft Defender to check for new virus and spyware definitions before it runs a scan. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#checkforsignaturesbeforerunningscan)

- **[Group Policy]** Makes Microsoft Defender run catch-up scans for scheduled quick scans. A computer can miss a scheduled scan, usually because the computer is off at the scheduled time, but now after the computer misses two scheduled quick scans, Microsoft Defender runs a catch-up scan the next time someone logs onto the computer. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#disablecatchupquickscan)

- **[Group Policy]** Enables [Network Protection of Microsoft Defender](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/network-protection?view=o365-worldwide) **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#enablenetworkprotection)

- **[Registry/Cmdlet]** Enables scanning of restore points **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#scan_disablerestorepoint)

- **[Registry/Cmdlet]** Makes sure [Async Inspection for Network protection](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/network-protection?view=o365-worldwide#optimizing-network-protection-performance) of Microsoft Defender is turned on - Network protection now has a performance optimization that allows Block mode to start asynchronously inspecting long connections after they're validated and allowed by SmartScreen, which might provide a potential reduction in the cost that inspection has on bandwidth and can also help with app compatibility problems. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp?WT.mc_id=Portal-fx#configurationallowswitchtoasyncinspection)

- **[Registry/Cmdlet]** **[Subcategory]** Enables [Smart App Control](https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003) (_if it's in Evaluation mode_): adds significant protection from new and emerging threats by blocking apps that are malicious or untrusted. Smart App Control also helps to block potentially unwanted apps, which are apps that may cause your device to run slowly, display unexpected ads, offer extra software you didn't want, or do other things you don't expect.

  - Smart App Control is User-Mode (and enforces Kernel-Mode) [App Control for Business](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/appcontrol-design-guide), **more info** [**in the Wiki**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction). You can see its status in [System Information](https://support.microsoft.com/en-us/windows/view-your-system-info-a965a8f2-0773-1d65-472a-1e747c9ebe00) and enable it manually from Microsoft Defender app's GUI. It is very important for Windows and Windows Defender intelligence updates to be always up-to-date in order for Smart App Control to work properly as it relies on live intelligence and definition data from the cloud and other sources to make a Smart decision about programs and files it encounters.

  - Smart App Control uses [ISG (Intelligent Security Graph)](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph#how-does-app-control-work-with-the-isg). The ISG isn't a "list" of apps. Rather, it uses the same vast security intelligence and machine learning analytics that power Microsoft Defender SmartScreen and Microsoft Defender Antivirus to help classify applications as having "known good", "known bad", or "unknown" reputation. This cloud-based AI is based on trillions of signals collected from Windows endpoints and other data sources and processed every 24 hours. As a result, the decision from the cloud can change.

  - [Smart App Control](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/appcontrol#app-control-and-smart-app-control) can block a program entirely from running or only [some parts of it](https://support.microsoft.com/en-us/topic/smart-app-control-has-blocked-part-of-this-app-0729fff1-48bf-4b25-aa97-632fe55ccca2) in which case your app or program will continue working just fine most of the time. It's improved a lot since it was introduced, and it continues doing so. Consider turning it on after clean installing a new OS and fully updating it.

  - Smart App Control enforces the [Microsoft Recommended Driver Block rules](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) and the [Microsoft Recommended Block Rules](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol)

- **[Group Policy]** **[Subcategory]** Enables ["Send optional diagnostic data"](https://learn.microsoft.com/windows/privacy/windows-diagnostic-data) because [it](https://learn.microsoft.com/windows/privacy/configure-windows-diagnostic-data-in-your-organization) is [required for Smart App Control](https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003) **to operate when it's in evaluation mode or turned on, and for communication with [Intelligent Security Graph (ISG)](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph).** This setting will be automatically applied if Smart App Control is already turned on or you choose to turn it on. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-system#allowtelemetry)

- **[Group Policy]** Enables [Controlled Folder Access](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/enable-controlled-folders). It [helps protect your valuable data](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/controlled-folders) from malicious apps and threats, such as ransomware. Controlled folder access protects your data by checking apps against a list of known, trusted apps. Due to the recent wave of global ransomware attacks, it is important to use this feature to protect your valuables files, specially OneDrive folders. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#enablecontrolledfolderaccess)

  - If it blocks a program from accessing one of your folders it protects, and you absolutely trust that program, then you can add it to exclusion list using Microsoft Defender GUI or the Harden System Security app. You can also query the list of allowed apps using the app in the Defender category, Exclusions tab. You can backup your personalized list of allowed apps, that are relevant to your system, and restore them in case you clean install your Windows.

  - **[Registry/Cmdlet]** The root of the OneDrive folders of all the user accounts will be added to the protected folders list of Controlled Folder Access, to provide Ransomware protection for the entire OneDrive folder. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender#controlledfolderaccessprotectedfolders)

- **[Registry/Cmdlet]** Enables [Mandatory ASLR,](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/enable-exploit-protection?view=o365-worldwide) _It might cause compatibility issues_ only for some **poorly-made 3rd party programs**, specially portable ones. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-exploitguard)

  - Automatically detects and excludes the Git executables of GitHub Desktop and Git (Standalone version) from mandatory ASLR if they are installed on the system. [More info here](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Git-GitHub-Desktop-and-Mandatory-ASLR)

  - You can add Mandatory ASLR override for a trusted program using the PowerShell command below or in the Program Settings section of Exploit Protection in Microsoft Defender app.

    - `Set-ProcessMitigation -Name "C:\TrustedApp.exe" -Disable ForceRelocateImages`

- **[Registry/Cmdlet]** Applies [Exploit Protections/Process Mitigations](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/enable-exploit-protection) from [**this list**](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Harden-Windows-Security%20Module/Main%20files/Resources/ProcessMitigations.csv) to the following programs: **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-exploitguard)

  - All channels of [Microsoft Edge](https://www.microsoft.com/en-us/edge) browser

  - [Quick Assist](https://learn.microsoft.com/windows/client-management/client-tools/quick-assist) app

  - Some System processes

  - Microsoft 365 apps

  - More apps and processes will be added to the list over time once they are properly validated to be fully compatible.

  - Exploit Protection configurations are also accessible in XML format [within this repository](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/Harden%20System%20Security/Resources/Intune%20Files/Hardening%20Policies/Exploit%20Protections). When implementing exploit protections using an XML file, the existing exploit mitigations will seamlessly integrate rather than being overwritten. Should there be pre-existing exploit protections applied to an executable on the system, and the XML file specifies different mitigations for the same executable, these protections will be merged and applied collectively.

- **[Registry/Cmdlet]** [Turns on Data Execution Prevention](https://learn.microsoft.com/windows-hardware/drivers/devtest/bcdedit--set) (DEP) for all applications, including 32-bit programs. By default, the output of `BCDEdit /enum "{current}"` (in PowerShell) for the NX bit is `OptIn` but the Harden System Security app sets it to `AlwaysOn`

- **[Group Policy]** Check for the latest virus and spyware security intelligence on startup. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#signatureupdate_updateonstartup)

- **[Group Policy]** Specifies the maximum depth to scan archive files to the maximum possible value of `4,294,967,295` **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#scan_archivemaxdepth)

- **[Group Policy]** [Defines the maximum size of downloaded files and attachments to be scanned](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-advanced-scan-types-microsoft-defender-antivirus?view=o365-worldwide) and set it to the maximum possible value of `10,000,000 KB` or `10 GB`. [the default is](https://github.com/MicrosoftDocs/microsoft-365-docs/pull/5600) `20480 KB` or `~20MB` **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#realtimeprotection_ioavmaxsize)

- **[Group Policy]** Enables the [Enhanced Phishing Protection](https://learn.microsoft.com/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/enhanced-phishing-protection) service. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-webthreatdefense#serviceenabled)

- **[Group Policy]** Enables notifying user of malicious and phishing scenarios in Microsoft Defender Enhanced Phishing Protection. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-webthreatdefense#notifymalicious)

- **[Group Policy]** Enables the feature in Enhanced Phishing Protection in Microsoft Defender SmartScreen that warns users if they reuse their work or school password. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-webthreatdefense#notifypasswordreuse)

- **[Group Policy]** Enables warning users if they type their work or school passwords in unsafe apps. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-webthreatdefense#notifyunsafeapp)

- **[Group Policy]** Enables automatic data collection (formerly known as Capture Threat Window) of Enhanced Phishing Protection in Microsoft Defender SmartScreen for security analysis from a suspicious website or app. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-webthreatdefense#automaticdatacollection)

- **[Registry/Cmdlet]** **[Subcategory]** [Creates scheduled task for fast weekly Microsoft recommended driver block list update.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Fast-and-Automatic-Microsoft-Recommended-Driver-Block-Rules-updates). You won't see this prompt if the task already exists and is enabled or running.

- **[Registry/Cmdlet]** **[Subcategory]** Set the Microsoft Defender engine and platform update channel to beta. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp?WT.mc_id=Portal-fx#configurationengineupdateschannel) **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp?WT.mc_id=Portal-fx#configurationplatformupdateschannel)

- **[Group Policy]** [Defines](https://learn.microsoft.com/defender-endpoint/manage-outdated-endpoints-microsoft-defender-antivirus?view=o365-worldwide#use-group-policy-to-specify-the-number-of-days-before-protection-is-considered-out-of-date) the number of days before spyware security intelligence is considered out of date to 2. The default is 7. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#signatureupdate_assignaturedue)

- **[Group Policy]** Defines the number of days before virus security intelligence is considered out of date to 2. The default is 7. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#signatureupdate_avsignaturedue)

- **[Group Policy]** Sets the [default action](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-remediation-microsoft-defender-antivirus) for Severe and High threat levels to Remove, for Medium and Low threat levels to Quarantine. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#threats_threatiddefaultaction)

- **[Group Policy]** Configures real-time protection and Security Intelligence Updates to be enabled during OOBE. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationoobeenablertpandsigupdate)

- **[Group Policy]** Enables the [Intel TDT](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/defending-against-ransomware-with-microsoft-defender-for/ba-p/3243941) (Intel® Threat Detection Technology) integration with Microsoft Defender. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationinteltdtenabled)

- **[Group Policy]** Disables [Performance Mode](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/microsoft-defender-endpoint-antivirus-performance-mode) - [Security risks in relation to Dev Drive](https://learn.microsoft.com/windows/dev-drive/#understanding-security-risks-and-trust-in-relation-to-dev-drive) **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp?WT.mc_id=Portal-fx#configurationperformancemodestatus)

- **[Registry/Cmdlet]** Enables a network protection setting that blocks malicious network traffic instead of displaying a warning. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationenableconvertwarntoblock)

- **[Group Policy]** Configures the Brute-Force Protection to use cloud aggregation to block IP addresses that are over 99% likely malicious **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationbehavioralnetworkblocksbruteforceprotectionbruteforceprotectionaggressiveness)

- **[Group Policy]** Configures the Brute-Force Protection to detect and block attempts to forcibly sign in and initiate sessions **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationbehavioralnetworkblocksbruteforceprotectionbruteforceprotectionconfiguredstate)

- **[Group Policy]** Sets the maximum time an IP address is blocked by Brute-Force Protection to the maximum possible value. After this time, blocked IP addresses will be able to sign-in and initiate sessions. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationbehavioralnetworkblocksbruteforceprotectionbruteforceprotectionmaxblocktime)

- **[Group Policy]** Configures the Remote Encryption Protection to use cloud intel and context, and block when confidence level is above 90%. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationbehavioralnetworkblocksremoteencryptionprotectionremoteencryptionprotectionaggressiveness)

- **[Group Policy]** Configures the Remote Encryption Protection to detect and block attempts to replace local files with encrypted versions from another device **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationbehavioralnetworkblocksremoteencryptionprotectionremoteencryptionprotectionconfiguredstate)

- **[Group Policy]** Sets the internal feature logic to determine blocking time for the Remote Encryption Protection **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationbehavioralnetworkblocksremoteencryptionprotectionremoteencryptionprotectionmaxblocktime)

- **[Registry/Cmdlet]** Extends the brute-force protection coverage in the Microsoft Defender Antivirus to block local network addresses. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationbehavioralnetworkblocksbruteforceprotectionbruteforceprotectionpluginsbruteforceprotectionlocalnetworkblocking)

- **[Registry/Cmdlet]** Enables [ECS Configurations](https://learn.microsoft.com/defender-endpoint/microsoft-defender-core-service-configurations-and-experimentation) in the Microsoft Defender. They improve product health and security by _automatically_ fixing any possible issues/bugs that may arise, in a timely manner.

- **[Group Policy]** Enables Network Protection to be configured into block or audit mode on Windows Server. **[CSP]** [CSP](https://learn.microsoft.com/windows/client-management/mdm/defender-csp#configurationallownetworkprotectiononwinserver)

- **[Group Policy]** Runs Microsoft Defender Antivirus in [Sandbox Mode](https://learn.microsoft.com/en-us/defender-endpoint/sandbox-mdav) for enhanced protection against tampering.

> [!TIP] > [Performance analyzer for Microsoft Defender Antivirus](https://learn.microsoft.com/defender-endpoint/tune-performance-defender-antivirus)
