# Deploy-SignedWDACConfig available parameters

## Notes

* **Mandatory** parameters indicate you always need to provide values for them.

* **Automatic** parameters indicate that if you used [Set-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig) cmdlet to set default values for them, the module will automatically use them. This saves time and prevents repetitive tasks. However, if no value exists in User Configurations for an Automatic parameter and you didn't explicitly provide a value for that parameter either, then you will see an error asking you to provide value for it. Explicitly providing a value for an Automatic parameter in the command line overrides its default value in User Configurations, meaning the module will ignore the value of the same parameter in the User Configurations file.

* **Optional** parameters indicate that they are not required and without using them the module will automatically run with the optimal settings.

* Many cmdlets and parameters of the module support the PowerShell's built-in `-Debug` switch and when that switch is used, they display extra details and debugging messages on the console, showing you what's happening under the hood.

<br>

### [Signs and Deploys a WDAC policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Create-and-Deploy-a-Signed-WDAC-Policy-Windows-Defender-Application-Control)

![image](https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Wiki%20APNGs/Deploy-SignedWDACConfig.apng)

```powershell
Deploy-SignedWDACConfig -CertPath <String> -PolicyPaths <String[]> -CertCN <String> [-SignToolPath <String>]
```

<br>

### 1 mandatory parameter

* `-PolicyPaths <String[]>`: Accepts multiple policies; it can Sign and Deploy multiple policies at the same time. Supports tab completion by showing only `.xml` files with **Base Policy** Type.

### 2 Automatic parameters

* `-CertPath <String>`: Path to the certificate `.cer` file. Supports tab completion by showing only `.cer` files.

* `CertCN <String>`: Common name of the certificate - Supports argument completion so you don't have to manually enter the Certificate's CN, just make sure the `-CertPath` is specified and the certificate is installed in the personal store of the user certificates, then press TAB to auto complete the name. You can however enter it manually if you want to.

### 1 optional parameter

* `-SignToolPath <String>`: Supports tab completion by showing only `.exe` files.

### You can use it in 2 different ways

1. If [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/) Signing Tools for Desktop Apps components is installed in the default location `C:\Program Files (x86)\Windows Kits`, then `-SignToolPath <String>` parameter isn't necessary.

2. If Windows SDK Signing Tools for Desktop Apps components is not installed in the default location or you want to manually browse for the `signtool.exe`, then make sure you use the `-SignToolPath <String>` parameter.

<br>
