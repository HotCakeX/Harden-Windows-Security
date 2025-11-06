# Create Supplemental App Control Policy

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Create%20Supplemental%20Policy.png" alt="AppControl Manager Application's Create Supplemental App Control Policy Page">

</div>

<br>

<br>

Use [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to create Supplemental App Control policies for your base policies. Use Supplemental policies to expand the scope of your base policies by allowing more files or applications.

<br>

> [!IMPORTANT]\
> [How To Create an App Control Supplemental Policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-To-Create-an-App-Control-Supplemental-Policy)

<br>

This page has 2 modes of operation:

1. **Create New Policy**: In this mode, whenever you create a Supplemental policy, a new policy XML file will be created in the `AppControl Manager` directory.

2. **Add to Existing Policy**: In this mode, you will have to select an existing App Control XML policy file so that any policy you create will be directly and automatically added to this policy and no new policy file will be created.

   * When this mode is active, elements related to `Policy Name` and `Base Policy File` will be automatically hidden since they won't be needed anymore.

<br>

## Create a Supplemental Policy by Files or Folders Scan

With AppControl Manager, you can easily create a supplemental policy by scanning files or folders. If an application or file is being blocked by Application Control, use this feature to scan its files or installation directory. This process enables you to generate a supplemental policy that ensures the application or file can run seamlessly on your system.

### Configuration Details

* **Browse For Files**: Use this button to browse for files on the system. Multiple files can be added at once.

* **Browse for Folders**: Use this button to browse for folders on the system. Multiple folders can be added at once.

* **Policy Name**: Enter a name for the Supplemental policy. You will be able to use this name to detect it after deployment in the **System Information** section of the AppControl Manager.

* **Base Policy File**: Browse for the path to the base policy XML file that this Supplemental policy will be expanding.

* **Scalability**: Use this gauge to set the number of concurrent threads for the scan. By default, 2 threads are used. Increasing this number will speed up the scan but will also consume more system resources.

* **Select Scan Level**: You can choose from different scan levels. [Refer to this page for all the information about them.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide)

* **Deploy After Creation**: If toggled, only the supplemental policy XML file will be available in the [User Configuration directory](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager#where-is-the-user-configurations-directory) at the end of the operation. If it's not toggled, the CIP file will also be made available. Both files will have the same name as the policy name that you choose.

> [!TIP]\
> Use the ***View Detected File Details*** section to view highly detailed results of the files and folders scans.

<br>

## Create a Supplemental Policy from Certificate Files

If you have certificate `.cer` files, you can use this feature to scan them and create a Supplemental App Control policy based on them. Once deployed, it will allow any file signed by those certificates to run on the system.

### Configuration Details

* **Browse For Certificates**: Use this button to browse for certificate `.cer` files on the system. Multiple files can be added at once.

* **Policy Name**: Enter a name for the Supplemental policy. You will be able to use this name to detect it after deployment in the **System Information** section of the AppControl Manager.

* **Base Policy File**: Browse for the path to the base policy XML file that this Supplemental policy will be expanding.

* **Signing Scenario**: Choose between User Mode or Kernel Mode signing scenarios. If you choose User Mode, the supplemental policy will only allow User Mode files signed by that certificate to run and Kernel mode files such as drivers will remain blocked.

* **Deploy After Creation**: If toggled, only the supplemental policy XML file will be available in the [User Configuration directory](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager#where-is-the-user-configurations-directory) at the end of the operation. If it's not toggled, the CIP file will also be made available. Both files will have the same name as the policy name that you choose.

<br>

## Create ISG-based Supplemental Policy

This supplemental policy does not explicitly permit any files or applications by default. Instead, it leverages [the Intelligent Security Graph (ISG)](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph#how-does-wdac-work-with-the-isg) to dynamically evaluate and automatically authorize trusted files and applications.

### Configuration Details

* **Policy Name**: Enter a name for the Supplemental policy. You will be able to use this name to detect it after deployment in the **System Information** section of the AppControl Manager.

* **Base Policy File**: Browse for the path to the base policy XML file that this Supplemental policy will be expanding.

* **Deploy After Creation**: If toggled, only the supplemental policy XML file will be available in the [User Configuration directory](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager#where-is-the-user-configurations-directory) at the end of the operation. If it's not toggled, the CIP file will also be made available. Both files will have the same name as the policy name that you choose.

<br>

## Create Kernel-mode Supplemental Policy

This supplemental policy can be created only for Kernel-mode files/drivers, typically after creating and deploying the [Strict Kernel-mode base policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection). When you press the `Create Supplemental Policy` button, any logs available in the `View Detected Kernel-mode files` section will be included in the policy. You can select and delete logs that you don't want to be included.

### Configuration Details

* **Auto Driver Detection**: Use this feature to automatically detect all drivers on the system. The results will be available in the `View Detected Kernel-mode files` section at the bottom.

* **Scan for All Kernel-mode logs**: Use this button to scan the entire Code Integrity logs for Kernel-mode files and display the results in the `View Detected Kernel-mode files` section.

* **Scan for All Kernel-mode logs Since Last Reboot**: Use this button to scan the Code Integrity logs that were generated since the last computer reboot for Kernel-mode files and display the results in the `View Detected Kernel-mode files` section.

* **Policy Name**: Enter a name for the Supplemental policy. You will be able to use this name to detect it after deployment in the **System Information** section of the AppControl Manager.

* **Base Policy File**: Browse for the path to the base policy XML file that this Supplemental policy will be expanding.

* **Deploy After Creation**: If toggled, only the supplemental policy XML file will be available in the [User Configuration directory](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager#where-is-the-user-configurations-directory) at the end of the operation. If it's not toggled, the CIP file will also be made available. Both files will have the same name as the policy name that you choose.

<br>

## Create a Supplemental Policy Based on Package Family Names

You can create Supplemental policies for the installed packaged apps. These are modern apps packaged in MSIX files, such as the AppControl Manager itself, or many of the apps installed from the Microsoft Store.

### Configuration Details

* **Policy Name**: Enter a name for the Supplemental policy.

* **Base Policy File**: Browse for the path to the base policy XML file that this Supplemental policy will be expanding.

* **Package Family Names**: In this section, you can view the list of all installed apps. Use the search bar to look for a specific app and after finding them, click/tap on them to select them.

   * Use the "Select All" and "Remove Selections" buttons to select/deselect all apps currently available in the list.

   * Use the Refresh button to refresh the list of installed apps in case you removed/installed any apps after the list was loaded.

* **Deploy After Creation**: If toggled, only the supplemental policy XML file will be available in the [User Configuration directory](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager#where-is-the-user-configurations-directory) at the end of the operation. If it's not toggled, the CIP file will also be made available. Both files will have the same name as the policy name that you choose.

<br>

## Create a Supplemental Policy Based on Custom Pattern-based File Rules

Use this section to create custom pattern-based file rules so that if a file or folder's path matches that pattern, it will be allowed. The pattern is based on regex and supports `*` and `?` characters. You can use this feature to create sophisticated file path rules that can dynamically match multiple files or folders.

Keep in mind that file rules are only supported for user-mode files. Using file rules for kernel-mode files simply has no effect.

### Configuration Details

* **Policy Name**: Enter a name for the Supplemental policy.

* **Base Policy File**: Browse for the path to the base policy XML file that this Supplemental policy will be expanding.

* **Custom Pattern-based File Rule**: Enter your pattern here. It will be used as is without any further modifications to it. What you enter here will be what you see in the XML file.

* **Deploy After Creation**: If toggled, only the Supplemental policy XML file will be available in the [User Configuration directory](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager#where-is-the-user-configurations-directory) at the end of the operation. If it's not toggled, the CIP file will also be made available. Both files will have the same name as the policy name that you choose.

> [!TIP]\
> Use the ***More Information*** section to view examples and description of different patterns that you can use in this section.

<br>
