# How To Create an App Control Supplemental Policy

On a system where Application Control is enforced, it is common to have a single main base policy and multiple supplemental policies. The base policy contains the core rules that are needed to allow the system to function properly. Base policies that have the `Enabled:Allow Supplemental Policies` [rule option](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#table-1-app-control-for-business-policy---policy-rule-options) can be extended with supplemental policies.

The supplemental policies are used to add additional rules that are specific to certain applications or scenarios. Supplemental policies can be used to expand the scope of a base policy without modifying the base policy itself. This allows you to create a base policy that is shared across multiple devices and then create supplemental policies that are specific to individual devices or groups of devices.

You can have as many supplemental policies as you need, but each supplemental policy can only be associated with one base policy.

> [!TIP]\
> How to differentiate between base and supplemental policies:
>
> The values of `PolicyID` and `BasePolicyID` fields in a base policy are the same, but in a supplemental policy, the `BasePolicyID` field contains the `PolicyID` of the base policy it is associated with.
>
> There are other signs that indicate if a policy is a base or supplemental policy. A supplemental policy can only contain allow rules. A supplemental policy can only have a subset of [the rule options](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#table-1-app-control-for-business-policy---policy-rule-options).
>
> Use the [System Information page](https://github.com/HotCakeX/Harden-Windows-Security/wiki/System-Information) in the [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to view all of the deployed policies and see which ones are base or supplemental.
>

When it comes to signing, if the base policy is signed, then the supplemental policy must be signed too and vice versa.

<br>

## Create a Supplemental Policy By Scanning Files and Folders

Assuming you've already deployed a base policy, you can create a supplemental policy by navigating to the [**Create Supplemental Policy Page**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Supplemental-App-Control-Policy).

In the **Files and Folders section**, browse for your base policy's XML file. Enter a descriptive name for the supplemental policy that will be created and browse for files and/or folders to scan. If you select folders, they will be scanned recursively, meaning any file(s) in the sub-folder(s) will also be included in the scan.

The default [level](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide) is set to `File Publisher` but you can change it to another level that meets your needs. This level will create signature-based rules for signed files and hash based rules for unsigned files.

<br>

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/8efca7547427750d599edd6f429be326c7010292/Pictures/PNG%20and%20JPG/How%20To%20Create%20an%20App%20Control%20Supplemental%20Policy/Files%20and%20Folders%20supplemental%20policy%20creation.png" alt="Create a Supplemental Policy By Scanning Files and Folders">

</div>

<br>

<br>

After you've submitted the necessary details, press the `Create Supplemental Policy` button. The scan will begin and you will be able to view the progress in real time. If you toggle the `Deploy After Creation` button, the policy will be automatically deployed on the local system, otherwise the XML file will just be created.

You can customize the XML file further using different pages and features of the AppControl Manager.

<br>

## Create a Supplemental Policy for Packaged Apps

Packaged apps are modern, they use MSIX packages and are easy to manage and authorize in App Control policies because all of the files in a packaged app share the same signing certificate and Package Family Name.

Use the [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to create supplemental policies for packaged apps. The policy that you create will not need any changes when the apps are updated since the authorization is based on the `PackageFamilyName`, aka `PFN`.

In the [**Create Supplemental Policy Page**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Supplemental-App-Control-Policy), navigate to the **Package Family Name** section.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/fa77675ec8cea0f73303487b3875600393d2948e/Pictures/PNG%20and%20JPG/How%20To%20Create%20an%20App%20Control%20Supplemental%20Policy/PFN%20section.png" alt="Package Family Name section">

<br>

<br>

Select the installed apps from the list. The list is automatically populated when you first expand the **Package Family Name** section. If you installed or removed apps, you can use the **Refresh** button to update the list of apps. Use the search bar to easily find the app(s) you are looking for.

Next enter a name for the supplemental policy and browse for the base policy that this supplemental policy will be associated with.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/How%20To%20Create%20an%20App%20Control%20Supplemental%20Policy/PFN%20package%20selection%20and%20base%20policy%20button.png" alt="PFN select base policy and packaged apps from the list">

<br>

<br>

Finally press the `Create Supplemental Policy` button to create the supplemental policy. If you toggle the **Deploy after Creation** button the policy will also be deployed on the system and you will be able to view it in the [System Information page](https://github.com/HotCakeX/Harden-Windows-Security/wiki/System-Information).

<br>

## Create a Supplemental Policy That Allows an Entire Folder

You can create a supplemental policy that will allow everything inside of a folder to be authorized to run. It is based on a wildcard file path. This type of supplemental policy is less secure than ones that are based on file signature, publisher or hash so use it with caution.

Navigate to the [**Create Supplemental Policy Page**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Supplemental-App-Control-Policy) page in the AppControl Manager and select the **Files and Folders** section.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/f391b22dfba59f8070a9d7191c743827dc89afb3/Pictures/PNG%20and%20JPG/How%20To%20Create%20an%20App%20Control%20Supplemental%20Policy/wildcard%20folder%20path.png" alt="Creating wildcard based folder path supplemental policy">

<br>

<br>

Enter an appropriate policy name. Set the Scan Level to **WildCard Folder Path**, you will notice that the **Browse for Files** section is deactivated in this mode. Use the **Browse for Folders** button to select the folder you want to allow and finally press the **Create Supplemental Policy** button to create the policy. If you toggle the **Deploy after Creation** button, the policy will also be deployed on the system and you will be able to view it in the [System Information page](https://github.com/HotCakeX/Harden-Windows-Security/wiki/System-Information).

<br>

## FAQs

Q: What happens if you create a supplemental policy with the same name as an existing one?

A: Although not recommended as it will make it hard to differentiate between the two in [System Information](https://github.com/HotCakeX/Harden-Windows-Security/wiki/System-Information), you can create a supplemental policy with the same name as an existing one. It won't overwrite the existing one as they will still have different PolicyIDs.

<br>

Q: What if you create a supplemental policy for an app and then that app is updated?

A: It all depends on the level you selected for the supplemental policy. If you selected `File Publisher` or `Publisher`, then the policy will still apply to the updated app as long as it is signed by the same publisher. If you selected `Hash`, then the policy will no longer apply to the updated app as the binaries are changed. You will have to scan the new binaries and create a new supplemental policy for them and preferably remove the old one.

<br>
