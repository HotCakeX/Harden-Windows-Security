# Fast and Automatic Microsoft Recommended Driver Block Rules updates

<br>

[The blocklist is updated with each new major release of Windows, typically 1-2 times per year](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules), but you can deploy the recommended driver block rules policy more frequently.

[This is the GitHub source](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/public/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules.md) for the XML content shown on the Microsoft document website. You can see when the last time it was changed was, read the change history and commit messages. The script below **automates** the required [steps explained on the document](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules#steps-to-download-and-apply-the-vulnerable-driver-blocklist-binary) to download and deploy the recommended driver block rules. Make sure you are using the latest version of Windows.

## Use the [WDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) Module

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-WDACConfig/New-WDACConfig%20-GetDriverBlockRules.apng)

You can use the [WDACConfig Module](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig#new-wdacconfig--getdriverblockrules) to create a scheduled task in Windows that will **automatically** run the script below every 7 days.

```powershell
Install-Module -Name WDACConfig -Force
New-WDACConfig -GetDriverBlockRules -AutoUpdate
```

<details>
<summary>The script</summary>

```powershell
try {
    Invoke-WebRequest -Uri 'https://aka.ms/VulnerableDriverBlockList' -OutFile VulnerableDriverBlockList.zip -ErrorAction Stop
}
catch {
    exit 1
}
Expand-Archive -Path .\VulnerableDriverBlockList.zip -DestinationPath 'VulnerableDriverBlockList' -Force
Rename-Item -Path .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName 'SiPolicy.p7b' -Force
Copy-Item -Path .\VulnerableDriverBlockList\SiPolicy.p7b -Destination "$env:SystemDrive\Windows\System32\CodeIntegrity"
citool --refresh -json
Remove-Item -Path .\VulnerableDriverBlockList -Recurse -Force
Remove-Item -Path .\VulnerableDriverBlockList.zip -Force
exit 0
```

</details>

<br>

Microsoft recommended driver block rules that are enforced as a result of using either memory integrity (also known as hypervisor-protected code integrity or HVCI), Smart App Control, or S mode, are saved in a file called `driversipolicy.p7b` in the `%windir%\system32\CodeIntegrity` directory. The file you will be downloading from Microsoft document is called `SiPolicy.p7b` and it won't overwrite the `driversipolicy.p7b` but it will take precedence over the `driversipolicy.p7b` when deployed, because it has newer version and you can verify it after using CiTool by observing the Code Integrity event logs as described in the document.
