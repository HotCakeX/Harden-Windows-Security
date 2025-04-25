# How To Upload App Control Policies To Intune Using AppControl Manager

The [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) provides native support for Intune, enabling effortless deployment of App Control policies to your Intune-managed devices.

To do that, navigate to the [Deploy App Control Policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-App-Control-Policy) page, Click the `Sign In` button. A new browser tab will open, prompting you to sign into your Entra ID account.

<div align="center">

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/7ccc3793b4d21d2fe7d5a79b56d1cc78fa1d0aac/Pictures/PNG%20and%20JPG/How%20To%20Upload%20App%20Control%20Policies%20To%20Intune%20Using%20AppControl%20Manager/Sign%20In%20button.png" alt="Sign In button">

<br>

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/7ccc3793b4d21d2fe7d5a79b56d1cc78fa1d0aac/Pictures/PNG%20and%20JPG/How%20To%20Upload%20App%20Control%20Policies%20To%20Intune%20Using%20AppControl%20Manager/Azure%20SignIn%20page.png" Height="600" alt="Azure Sign in pages">

<br>

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/7ccc3793b4d21d2fe7d5a79b56d1cc78fa1d0aac/Pictures/PNG%20and%20JPG/How%20To%20Upload%20App%20Control%20Policies%20To%20Intune%20Using%20AppControl%20Manager/Permissions%20acceptance%20page.png" alt="Azure Permissions page">

<br>

<br>

</div>

Once signed in, you'll be redirected back to the AppControl Manager.

<br>

## Permissions Required

To successfully complete the sign-in process and deploy policies, your account must have the following permissions, ***adhering to the Principle of Least Privilege***:

* [`Group.Read.All`](https://learn.microsoft.com/en-us/graph/permissions-reference#groupreadall): Allows the AppControl Manager to read security groups and display them in the dropdown list.

* [`DeviceManagementConfiguration.ReadWrite.All`](https://learn.microsoft.com/en-us/graph/permissions-reference#devicemanagementconfigurationreadwriteall): Grants the ability to create, upload, and assign App Control policies.

By ensuring these permissions are in place, you can seamlessly deploy App Control policies through Intune while maintaining secure and minimal access.

<br>

## Select Policies To Deploy

Select one or more XML files to deploy to Intune. You have the option to deploy them as-is (unsigned) or cryptographically sign them before deployment. Each XML file will be deployed as a separate Intune configuration policy for better management of policies.

The name specified in the XML file will appear as the name of the corresponding Intune configuration policy in the Intune portal. Similarly, the policy ID from the XML file will be used as the uploaded policy's ID, enabling easy identification of policies on workstations after deployment.

You can optionally use the `Refresh` button and select a group to assign to the policies you upload to Intune.

<img src="https://raw.githubusercontent.com/HotCakeX/.github/7ccc3793b4d21d2fe7d5a79b56d1cc78fa1d0aac/Pictures/PNG%20and%20JPG/How%20To%20Upload%20App%20Control%20Policies%20To%20Intune%20Using%20AppControl%20Manager/Group%20Names.png" alt="Intune Groups DropDown">

<br>

<br>

## How To Change Tenant?

If you want to change your tenant and sign into another account, press the `Sign Out` button and then use the `Sign In` button again to sign into a different tenant.

<br>

## How To View The Uploaded Policies?

You can view the policies you deployed and uploaded In Intune in the following path:

```
Intune Portal | Devices | Configuration
```

You can remove any of the deployed policies in here. After removal from the Intune portal, the target device must be restarted once for the removal process to complete.

<br>

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/bd62727406d683bbee30fdebecde9580d13e3a00/Pictures/PNG%20and%20JPG/How%20To%20Upload%20App%20Control%20Policies%20To%20Intune%20Using%20AppControl%20Manager/Microsoft%20Intune%20deployed%20and%20uploaded%20policies.png" Alt="View deployed policies in the Microsoft Intune portal">

</div>

<br>

## Have Questions or Feature Requests?

Feel free to [create a new discussion](https://github.com/HotCakeX/Harden-Windows-Security/discussions) to ask questions or request for extra features that don't currently exist in the AppControl Manager application.

<br>
