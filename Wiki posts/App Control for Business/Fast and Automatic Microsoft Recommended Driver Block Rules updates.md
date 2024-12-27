# Fast and Automatic Microsoft Recommended Driver Block Rules updates

<br>

[The blocklist is updated with each new major release of Windows, typically 1-2 times per year](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules), but you can deploy the recommended driver block rules policy more frequently.

[This is the GitHub source](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/public/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules.md) for the XML content shown on the Microsoft document website. You can see when the last time it was changed was, read the change history and commit messages.

Use the [**AppControl Manager**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to **automate** the required [steps explained on the document](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules#steps-to-download-and-apply-the-vulnerable-driver-blocklist-binary) to download and deploy the recommended driver block rules.

<br>

![image](https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/APNGs/Fast%20and%20Automatic%20Microsoft%20Recommended%20Driver%20Block%20Rules%20updates.apng)

<br>

The **Auto Update** button in [**the Create Policy page**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-App-Control-Policy) creates a scheduled task in Windows that will **automatically** run every 7 days to keep the block list up to date.

<br>

> [!NOTE]\
> Microsoft recommended driver block rules that are enforced as a result of using either memory integrity (also known as hypervisor-protected code integrity or HVCI), Smart App Control, or S mode, are saved in a file called `driversipolicy.p7b` in the `%windir%\system32\CodeIntegrity` directory.
>
> The file you download from Microsoft document is called `SiPolicy.p7b` and it won't overwrite the `driversipolicy.p7b` once deployed. It will work side-by-side the default block rules and will be enforced as well. They are both explicit deny base policies.

<br>
