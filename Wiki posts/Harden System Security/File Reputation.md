# File Reputation | Harden System Security

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/9f8c01aea24dd33804e794ab1fbcb68fb71609dc/Pictures/PNG%20and%20JPG/Harden%20System%20Security%20page%20screenshots/File%20Reputation.png" alt="File Reputation | Harden System Security">

</div>

<br>

On this page of the [Harden System Security](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security), you're able to query any file on the system to retrieve its reputation information. The source of this data is [Microsoft's Intelligent Security Graph](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph) when the [Smart App Control](https://learn.microsoft.com/windows/apps/develop/smart-app-control/overview) is enabled or in Evaluation Mode, otherwise it will be the [SmartScreen](https://learn.microsoft.com/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/) which supplies the reputation data for this feature.

Simply browse for a file or drag and drop it into the page to evaluate its reputation. The drag and drop feature only works when the app is not running with elevated privileges.

<br>
