# How To Install Microsoft Store Apps Completely Offline

## Requirements

* The app you're trying to install must be free on the Microsoft Store.
* The app you're trying to install must be enrolled in [Enterprise and organization licensing](https://learn.microsoft.com/windows/apps/publish/distribute-lob-apps-to-enterprises) for online and offline deployments.
   * All of the apps in this repository meet the requirements.
* `Winget`, which is installed in the operating system by default.
* An Entra ID account with *one* of the following roles: `Global Administrator`, `User Administrator`, or `License Administrator`.

## Steps

Download the app and its license file via Winget

```powershell
winget download --id 9P7GGFL7DX57 --exact --accept-package-agreements --accept-source-agreements --source msstore
```

> [!NOTE]\
> `9P7GGFL7DX57` is the ID for the [Harden System Security](https://apps.microsoft.com/detail/9P7GGFL7DX57) app.
>
> `9PNG1JDDTGP8` is the ID for the [AppControl Manager](https://apps.microsoft.com/detail/9PNG1JDDTGP8) app.
>

After running the above command, you will be prompted in a new window to enter the credentials for your Microsoft Entra ID account that has at least one of the required roles. Authenticated information will be shared with Microsoft services for access authorization.

This will download the app package and its license file to the Downloads directory but you can specify a different directory by adding the `--download-directory <path>` argument to the command.

Once you have the app package and its license file, you can transfer them to the offline system and install them using the following [command](https://learn.microsoft.com/powershell/module/dism/add-appxprovisionedpackage):

```powershell
Add-AppxProvisionedPackage -Online -PackagePath .\VioletHansen.HardenSystemSecurity.msixbundle -LicensePath .\9P7GGFL7DX57_License.xml
```

> [!NOTE]\
> Change the paths to match the location of the downloaded files on your offline system.

That's it! You have successfully installed a Microsoft Store app completely offline without an internet connection in an air-gapped environment.

<br>
