# Remove-CommonWDACConfig available parameters

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Remove-CommonWDACConfig/Remove-CommonWDACConfig.apng)

```powershell
Remove-CommonWDACConfig [-CertCN] [-CertPath] [-SignToolPath] [-UnsignedPolicyPath] [-SignedPolicyPath]
[-StrictKernelPolicyGUID] [-StrictKernelNoFlightRootsPolicyGUID]
```

<br>

Use this cmdlet to remove the values stored in the User Configurations JSON file. If you use it without any parameters it will delete the User configuration folder and everything in it, which is located in `C:\Users\UserName\.WDACConfig`

<br>

### 7 Optional Parameters

* `-CertCN`: Removes the saved Certificate Common Name from User Configurations
* `-CertPath`: Removes the saved Certificate path from User Configurations
* `-SignToolPath`: Removes the saved SignTool.exe Path from User Configurations
* `-UnsignedPolicyPath`: Removes the saved Unsigned Policy Path from User Configurations
* `-SignedPolicyPath`: Removes the saved Signed Policy Path from User Configurations
* `-StrictKernelPolicyGUID`: Removes the saved Strict Kernel Policy GUID from User Configurations
* `-StrictKernelNoFlightRootsPolicyGUID`: Removes the saved Strict Kernel NoFlight Roots Policy GUID from User Configurations

<br>
