# Set-CommonWDACConfig available parameters

## Notes

* **Mandatory** parameters indicate you always need to provide values for them.

* **Automatic** parameters indicate that if you used [Set-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig) cmdlet to set default values for them, the module will automatically use them. This saves time and prevents repetitive tasks. However, if no value exists in User Configurations for an Automatic parameter and you didn't explicitly provide a value for that parameter either, then you will see an error asking you to provide value for it. Explicitly providing a value for an Automatic parameter in the command line overrides its default value in User Configurations, meaning the module will ignore the value of the same parameter in the User Configurations file.

* **Optional** parameters indicate that they are not required and without using them the module will automatically run with the optimal settings.

<br>

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Set-CommonWDACConfig/Set-CommonWDACConfig.apng)

```powershell
Set-CommonWDACConfig [[-CertCN] <String>] [[-CertPath] <FileInfo>] [[-SignToolPath] <FileInfo>]
[[-UnsignedPolicyPath] <FileInfo>] [[-SignedPolicyPath] <FileInfo>] [[-StrictKernelPolicyGUID] <Guid>]
[[-StrictKernelNoFlightRootsPolicyGUID] <Guid>] [[-LastUpdateCheck] <DateTime>] [<CommonParameters>]
```

<br>

Use this cmdlet to store the values for common and frequently used parameters so that you won't have to specify them again every time.

All of the applicable cmdlets of the module automatically check the User Configuration file for any available input, if you don't specify values for their parameters.

<br>

## An Example

Instead of specifying all of the parameters for `Edit-SignedWDACConfig` cmdlet like this:

```powershell
Edit-SignedWDACConfig -AllowNewApps -SuppPolicyName "App 1" -CertPath "Path To Certificate.cer" -PolicyPaths "Path To Policy.xml" -CertCN "Certificate Common Name"
```

You can just run this

```powershell
Edit-SignedWDACConfig -AllowNewApps -SuppPolicyName "App 1"
```

If correct and valid values for the missing parameters exist in User Configuration file, the cmdlet will automatically detect and use them seamlessly.

<br>

### 5 Optional Parameters

* `-CertCN`: Common Name of an installed certificate. Supports argument completion so you don't have to manually enter the Certificate's CN, just make sure the certificate is installed in the personal store of the user certificates, then press TAB to auto complete the name. You can however enter it manually if you want to.

* `-CertPath`: Path to a certificate `.cer` file. Support tab completion by opening a file picker dialog GUI to help you select your `.cer` certificate file easily.

* `-SignToolPath`: Path to the SignTool executable. Supports tab completion by opening a file picker dialog GUI to help you select your `.exe` SignTool executable easily.

* `-UnSignedPolicyPath <String>`: Path to the xml file of an Unsigned policy. Supports tab completion by showing only the base policies in the current working directory.

* `-SignedPolicyPath <String>`: Path to the xml file of a Signed policy. Supports tab completion by showing only the base policies in the current working directory.

<br>
