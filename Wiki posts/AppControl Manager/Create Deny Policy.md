# Create Deny Policy

Use [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to create Deny App Control policies. Keep in mind that App Control is inherently a whitelisting feature so anything that is not allowed by a policy is already automatically blocked.

All Deny policies have *Base* policy types as other types such as Supplemental cannot have Deny rules in them.

All Deny policies have 2 allow all rules so that anything not denied by them will be allowed. This is mandatory for the policy to work. This also allows Deny policies to be deployed side by side with other policies, because for a file to be allowed, it must be allowed by all deployed policies. [Read more about side-by-side deployment here](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/deploy-multiple-appcontrol-policies).

<br>

## Create a Deny Policy by Files or Folders Scan

With AppControl Manager, you can easily create a Deny base policy by scanning files or folders.

### Configuration Details

* **Browse For Files**: Use this button to browse for files on the system. Multiple files can be added at once.

* **Browse for Folders**: Use this button to browse for folders on the system. Multiple folders can be added at once.

* **Policy Name**: Enter a name for the Deny policy. You will be able to use this name to detect it after deployment in the **System Information** section of the AppControl Manager.

* **Scalability**: Use this gauge to set the number of concurrent threads for the scan. By default, 2 threads are used. Increasing this number will speed up the scan but will also consume more system resources.

* **Select Scan Level**: You can choose from different scan levels. [Refer to this page for all the information about them.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide)

> [!TIP]\
> Use the ***View Detected File Details*** section to view highly detailed results of the files and folder scans.

<br>
