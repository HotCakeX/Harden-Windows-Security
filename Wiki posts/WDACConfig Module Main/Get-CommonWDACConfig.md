# Get-CommonWDACConfig available parameters

## Notes

* **Mandatory** parameters indicate you always need to provide values for them.

* **Automatic** parameters indicate that if you used [Set-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig) cmdlet to set default values for them, the module will automatically use them. This saves time and prevents repetitive tasks. However, if no value exists in User Configurations for an Automatic parameter and you didn't explicitly provide a value for that parameter either, then you will see an error asking you to provide value for it. Explicitly providing a value for an Automatic parameter in the command line overrides its default value in User Configurations, meaning the module will ignore the value of the same parameter in the User Configurations file.

* **Optional** parameters indicate that they are not required and without using them the module will automatically run with the optimal settings.

<br>

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Get-CommonWDACConfig/Get-CommonWDACConfig.apng)

```powershell
Get-CommonWDACConfig [-CertCN] [-CertPath] [-SignToolPath] [-SignedPolicyPath] [-UnsignedPolicyPath]
[-StrictKernelPolicyGUID] [-StrictKernelNoFlightRootsPolicyGUID] [-Open] [-LastUpdateCheck] [<CommonParameters>]
```

<br>

Use this cmdlet to query and display the values for common and frequently used parameters in the User Configurations Json file

All of the applicable cmdlets of the module automatically check the User Configuration file for any available input, if you don't specify values for their parameters.

<br>

### 7 Optional Parameters

* `-CertCN`: Displays the Common Name of an installed certificate.

* `-CertPath`: Displays the path to a certificate `.cer` file.

* `-SignToolPath`: Displays the path to the SignTool executable.

* `-SignedPolicyPath <String>`: Displays the path to the xml file of a Signed policy.

* `-UnSignedPolicyPath <String>`: Displays the path to the xml file of an Unsigned policy.

* `-Open`: Opens the User Config Json file in the default editor.
by the module)

* `-LastUpdateCheck`: Displays the last time online update check was performed.

<br>
