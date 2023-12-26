# Assert-WDACConfigIntegrity available parameters

```powershell
Assert-WDACConfigIntegrity [-SaveLocally] [-Path <FileInfo>] [-SkipVersionCheck] [<CommonParameters>]
```

<br>

This cmdlet scans all the relevant files in the WDACConfig module's folder and its subfolders, calculates their SHA2-512 hashes using the [Get-FileHash cmdlet](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash).

Then it downloads the [cloud CSV file](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/WDACConfig/Utilities/Hashes.csv) from the GitHub repository and compares the hashes of the local files with the ones in the cloud.

By doing so, you can ascertain that the files in your local WDACConfig folder are identical to the ones in the cloud and devoid of any interference.

If there is any indication of tampering, the outcomes will be displayed on the console.

<br>

### 3 Optional Parameters

* `-SaveLocally`: This parameter is used to generate hashes of the final modules files prior to publishing them to the GitHub. This parameter shouldn't be used.

* `-Path`: Can define a different path for the `Hashes.csv` file. This parameter shouldn't be used.

* `-SkipVersionCheck`: Skips the check for new module version.

<br>
