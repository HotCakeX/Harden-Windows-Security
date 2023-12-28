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

The WDACConfig module comprises of `.ps1` and `.psm1` files that bear the cryptographic signature of my local certificate authority's (CA) certificate. The module incorporates mechanisms to automatically ascertain the integrity of the module files and prevent any unauthorized modifications. The module manifest, `.psd1` file, on the other hand, lacks a signature due to the installation error that arises from the PowerShell gallery when it is signed with a self-signed certificate.

You can also obtain the [Root CA certificate from this GitHub repository](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/WDACConfig/Utilities/Certificate/HotCakeX%20Root%20CA.cer) and install it in the [Current User's](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/local-machine-and-current-user-certificate-stores) *Trust Root Certification Authorities* [store](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/trusted-root-certification-authorities-certificate-store), which **does not necessitate administrator** privileges. You should accomplish this in [Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview) or a Hyper-V VM (Virtual Machine). Subsequently, you can utilize the [Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature) cmdlet to ascertain the cryptographic signature and authenticity of the module files.

<br>
