# Deploy-SignedWDACConfig available parameters

### [Signs and Deploys a WDAC policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Create-and-Deploy-a-Signed-WDAC-Policy-Windows-Defender-Application-Control)

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Deploy-SignedWDACConfig/Deploy-SignedWDACConfig.apng)

```powershell
Deploy-SignedWDACConfig -PolicyPaths <FileInfo[]> [-Deploy] [-CertPath <FileInfo>] [-CertCN <String>]
[-SignToolPath <FileInfo>] [-Force] [-SkipVersionCheck] [-WhatIf] [-Confirm] [<CommonParameters>]
```

<br>

Creates and signs a `.CIP` file that can be either deployed locally using the `-Deploy` parameter or you can deploy the signed policy binary on a different machine later using the built-in [Citool](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/citool-commands).

<br>

### 1 Mandatory Parameter

* `-PolicyPaths <String[]>`: Accepts multiple policies; it can Sign and Deploy multiple policies at the same time. Supports tab completion by showing only `.xml` files in the current working directory.

### 2 Automatic Parameters

* `-CertPath <String>`: Path to the certificate `.cer` file. Press TAB to open the file picker GUI and browse for a `.cer` file.

* `CertCN <String>`: Common name of the certificate - Supports argument completion so you don't have to manually enter the Certificate's CN, just make sure the `-CertPath` is specified and the certificate is installed in the personal store of the user certificates, then press TAB to auto complete the name. You can however enter it manually if you want to.

### 3 Optional Parameters

* `-SignToolPath <String>`: Press TAB to open the file picker GUI and browse for SignTool.exe

* `-Deploy`: Deploys the signed policy on the system

- `-Force`: Indicates that the cmdlet won't ask for confirmation and will proceed with deploying the signed policy.

<br>

### The logic behind `-SignToolPath <String>` optional parameter

<a name="signtool-bottom"></a>

1. If [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/) Signing Tools for Desktop Apps components is installed in the default location `C:\Program Files (x86)\Windows Kits`, then `-SignToolPath <String>` parameter isn't necessary.

2. If Windows SDK Signing Tools for Desktop Apps components is not installed in the default location or you want to manually browse for the `signtool.exe`, then make sure you either specify its path using `Set-CommonWDACConfig -SignToolPath` or use the `-SignToolPath <String>` parameter.

3. If SignTool.exe path is available in user configurations then it will be used, unless the `-SignToolPath <String>` parameter is specified which takes priority over auto detection and user configurations.

4. Unless you specify the `-SignToolPath <String>` parameter, or the SignTool.exe path already exists in your user configurations or on your system, you will receive a prompt to authorize the automatic download of the most recent SignTool.exe version from the official Microsoft servers. Upon confirmation, it will be saved in your user configurations and utilized by the cmdlet.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Notes

* **Mandatory** parameters indicate you always need to provide values for them.

* **Automatic** parameters indicate that if you used [Set-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig) cmdlet to set default values for them, the module will automatically use them. This saves time and prevents repetitive tasks. However, if no value exists in User Configurations for an Automatic parameter and you didn't explicitly provide a value for that parameter either, then you will see an error asking you to provide value for it. Explicitly providing a value for an Automatic parameter in the command line overrides its default value in User Configurations, meaning the module will ignore the value of the same parameter in the User Configurations file.

* **Optional** parameters indicate that they are not required and without using them the module will automatically run with the optimal settings.

<br>
