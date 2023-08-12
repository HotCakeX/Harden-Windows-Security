# Get-CommonWDACConfig available parameters

## Notes

* **Mandatory** parameters indicate you always need to provide values for them.

* **Automatic** parameters indicate that if you used [Set-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig) cmdlet to set default values for them, the module will automatically use them. This saves time and prevents repetitive tasks. However, if no value exists in User Configurations for an Automatic parameter and you didn't explicitly provide a value for that parameter either, then you will see an error asking you to provide value for it. Explicitly providing a value for an Automatic parameter in the command line overrides its default value in User Configurations, meaning the module will ignore the value of the same parameter in the User Configurations file.

* **Optional** parameters indicate that they are not required and without using them the module will automatically run with the optimal settings.

* Many cmdlets and parameters of the module support the PowerShell's built-in `-Debug` switch and when that switch is used, they display extra details and debugging messages on the console, showing you what's happening under the hood.

<br>

![image](https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Wiki%20APNGs/Get-CommonWDACConfig.apng)

```powershell
Get-CommonWDACConfig [-SignedPolicyPath] [-UnsignedPolicyPath] [-SignToolPath] [-CertCN] [-StrictKernelPolicyGUID]
[-StrictKernelNoFlightRootsPolicyGUID] [-CertPath] [-Open]
```

<br>

Use this cmdlet to query and display the values for common and frequently used parameters in the User Configurations Json file

All of the applicable cmdlets of the module automatically check the User Configuration file for any available input, if you don't specify values for their parameters.

<br>

### 8 optional parameters

* `-SignedPolicyPath <String>`: Displays the path to the xml file of a Signed policy.

* `-UnSignedPolicyPath <String>`: Displays the path to the xml file of an Unsigned policy.

* `-SignToolPath`: Displays the path to the SignTool executable.

* `-CertCN`: Displays the Common Name of an installed certificate.

* `-CertPath`: Displays the path to a certificate `.cer` file.

* `-Open`: Opens the User Config Json file in the default editor.

* `-StrictKernelPolicyGUID`: Displays the GUID of the Strict Kernel mode policy (Mainly used Internally by the module)

* `-StrictKernelNoFlightRootsPolicyGUID`: Displays the GUID of the Strict Kernel no Flights root mode policy (Mainly used Internally by the module)

<br>
