# How To Create an App Control Supplemental Policy

Base policies that have the `Enabled:Allow Supplemental Policies` [rule option](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#table-1-app-control-for-business-policy---policy-rule-options) can be extended with supplemental policies. Supplemental policies can be used to expand the scope of a base policy without modifying the base policy itself. This allows you to create a base policy that is shared across multiple devices and then create supplemental policies that are specific to individual devices or groups of devices.

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

When it comes to signing, if the base policy is signed, then the supplemental policy must be signed too and vise versa.

<br>

## Create a Supplemental Policy By Scanning Files and Folders

Assuming you've already deployed a base policy, you can create a supplemental policy by navigating to the [**Create Supplemental Policy Page**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Supplemental-App-Control-Policy).

In the **Files and Folders section**, browse for your base policy's XML file. Enter a descriptive name for the supplemental policy that will be created and browse for files and/or folder to scan. If you select folders, they will be scanned recursively, meaning any file in the sub-folders will also be included in the scan.

The default [level](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide) is set to `File Publisher` but you can change it to another level that meets your needs.

<br>

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/8efca7547427750d599edd6f429be326c7010292/Pictures/PNG%20and%20JPG/How%20To%20Create%20an%20App%20Control%20Supplemental%20Policy/Files%20and%20Folders%20supplemental%20policy%20creation.png" alt="Create a Supplemental Policy By Scanning Files and Folders">

</div>

<br>

<br>

After you've submitted the necessary details, press the `Create Supplemental Policy` button. The scan will begin and you will be able to view the progress in real time. If you toggle the `Deploy After Creation` button, the policy will be automatically deployed on the local system, otherwise the XML file will just be created.

You can customize the XML file further using different pages and features of the AppControl Manager.

<br>

### FAQs

Q: What happens if you create a supplemental policy with the same name as an existing one?

A: Although not recommended as it will make it hard to differentiate between the two in [System Information](https://github.com/HotCakeX/Harden-Windows-Security/wiki/System-Information), you can create a supplemental policy with the same name as an existing one. It won't overwrite the existing one as they will still have different PolicyIDs.

<br>

Q: What if you create a supplemental policy for an app and then that app is updated?

A: It all depends on the level you selected for the supplemental policy. If you selected `File Publisher` or `Publisher`, then the policy will still apply to the updated app as long as it is signed by the same publisher. If you selected `Hash`, then the policy will no longer apply to the updated app as the binaries are changed. You will have to scan the new binaries and create a new supplemental policy for them and preferably remove the old one.

<br>
