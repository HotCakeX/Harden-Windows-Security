# Create Deny Policy

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Create%20Deny%20policy.png" alt="AppControl Manager Application's Create Deny Policy Page">

</div>

<br>

<br>

Use [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to create Deny App Control policies. Keep in mind that App Control is inherently a whitelisting feature so anything that is not allowed by a policy is already automatically blocked.

All Deny policies have *Base* policy types as other types such as Supplemental cannot have Deny rules in them.

All Deny policies have 2 allow all rules so that anything not denied by them will be allowed. This is mandatory for the policy to work. This also allows Deny policies to be deployed side by side with other policies, because for a file to be allowed, it must be allowed by all deployed policies. [Read more about side-by-side deployment here](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/deploy-multiple-appcontrol-policies).

<br>

> [!IMPORTANT]\
> [How to Create an App Control Deny Policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Create-an-App-Control-Deny-Policy)

<br>

This page has 2 modes of operation:

1. **Create New Policy**: In this mode, whenever you create a Deny policy, a new policy will be created and added to the Policies Library.

2. **Add to Existing Policy**: In this mode, you will have to select an existing App Control policy so that any policy/rules you create will be directly and automatically added to this policy and no new policy will be created.

   * When this mode is active, elements related to `Policy Name` will be automatically hidden since they won't be needed anymore.

   * This is a great way to expand your existing policies by adding new rules to them.

<br>

## Create a Deny Policy by Files or Folders Scan

With AppControl Manager, you can easily create a Deny base policy by scanning files or folders.

### Configuration Details

* **Browse For Files**: Use this button to browse for files on the system. Multiple files can be added at once.

* **Browse for Folders**: Use this button to browse for folders on the system. Multiple folders can be added at once.

* **Policy Name**: Enter a name for the Deny policy. You will be able to use this name to detect it after deployment in the **System Information** section of the AppControl Manager.

* **Scalability**: Use this gauge to set the number of concurrent threads for the scan. By default, 2 threads are used. Increasing this number will speed up the scan but will also consume more system resources.

* **Select Scan Level**: You can choose from different scan levels. [Refer to this page for all the information about them.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide)

* **Deploy After Creation**: If toggled, the Deny policy that is created in the end will be deployed on the system.

> [!TIP]\
> Use the ***View Detected File Details*** section to view highly detailed results of the files and folders scans.

<br>

## Create a Deny Policy Based on Package Family Names

You can create Deny policies for the installed packaged apps. This is useful for only blocking specific apps that are installed on the system.

### Configuration Details

* **Policy Name**: Enter a name for the Deny policy.

* **Package Family Names**: In this section, you can view the list of all installed apps. Use the search bar to look for a specific app and after finding them, click/tap on them to select them.

   * Use the "Select All" and "Remove Selections" buttons to select/deselect all apps currently available in the list.

   * Use the Refresh button to refresh the list of installed apps in case you removed/installed any apps after the list was loaded.

* **Deploy After Creation**: If toggled, the Deny policy that is created in the end will be deployed on the system.

<br>

## Create a Deny Policy Based on Custom Pattern-based File Rules

Use this section to create custom pattern-based file rules so that if a file or folder's path matches that pattern, it will be blocked. The pattern is based on regex and supports `*` and `?` characters. You can use this feature to create sophisticated file path rules that can dynamically match multiple files or folders.

Keep in mind that file rules are only supported for user-mode files. Using file rules for kernel-mode files simply has no effect.

### Configuration Details

* **Policy Name**: Enter a name for the Deny policy.

* **Custom Pattern-based File Rule**: Enter your pattern here. It will be used as is without any further modifications to it. What you enter here will be what you see in the XML file.

* **Deploy After Creation**: If toggled, the Deny policy that is created in the end will be deployed on the system.

> [!TIP]\
> Use the ***More Information*** section to view examples and description of different patterns that you can use in this section.

<br>
