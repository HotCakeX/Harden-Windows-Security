# Remove-CommonWDACConfig available parameters

## Notes

* **Mandatory** parameters indicate you always need to provide values for them.

* **Automatic** parameters indicate that if you used [Set-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig) cmdlet to set default values for them, the module will automatically use them. This saves time and prevents repetitive tasks. However, if no value exists in User Configurations for an Automatic parameter and you didn't explicitly provide a value for that parameter either, then you will see an error asking you to provide value for it. Explicitly providing a value for an Automatic parameter in the command line overrides its default value in User Configurations, meaning the module will ignore the value of the same parameter in the User Configurations file.

* **Optional** parameters indicate that they are not required and without using them the module will automatically run with the optimal settings.

* Many cmdlets and parameters of the module support the PowerShell's built-in `-Debug` switch and when that switch is used, they display extra details and debugging messages on the console, showing you what's happening under the hood.

<br>

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Remove-CommonWDACConfig/Remove-CommonWDACConfig.apng)

```powershell
Remove-CommonWDACConfig [-CertCN] [-CertPath] [-SignToolPath] [-UnsignedPolicyPath] [-SignedPolicyPath]
[-StrictKernelPolicyGUID] [-StrictKernelNoFlightRootsPolicyGUID]
```

<br>

Use this cmdlet to remove the values stored in the User Configurations JSON file. If you use it without any parameters it will delete the User configuration folder and everything in it, which is located in `C:\Users\UserName\.WDACConfig`

<br>

### 7 optional parameters

* `-CertCN`: Removes the saved Certificate Common Name from User Configurations
* `-CertPath`: Removes the saved Certificate path from User Configurations
* `-SignToolPath`: Removes the saved SignTool.exe Path from User Configurations
* `-UnsignedPolicyPath`: Removes the saved Unsigned Policy Path from User Configurations
* `-SignedPolicyPath`: Removes the saved Signed Policy Path from User Configurations
* `-StrictKernelPolicyGUID`: Removes the saved Strict Kernel Policy GUID from User Configurations
* `-StrictKernelNoFlightRootsPolicyGUID`: Removes the saved Strict Kernel NoFlight Roots Policy GUID from User Configurations

<br>
