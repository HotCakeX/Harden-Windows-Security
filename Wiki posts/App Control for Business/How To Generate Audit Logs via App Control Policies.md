# How To Generate Audit Logs via App Control Policies

Audit Logs are generated when a Base policy is deployed with `Audit Mode` rule option. You can configure rule options in policies via [AppControl Manager's features](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Configure-Policy-Rule-Options).

You can view all of the available rule options in the following [Microsoft Learn page](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#table-1-app-control-for-business-policy---policy-rule-options).

During the Audit mode phase, no file is blocked, instead an audit log in the `Code Integrity/Operational` or `AppLocker` event logs are generated for each file that is executed on the system that would have been blocked if the policy was deployed in enforced mode.

If the file is a `MSI` installer file or script, then `AppLocker` event is generated for it, otherwise `Code Integrity` will log that file.

The logs can be collected by the AppControl Manager in order to create Supplemental policies. The logs can also be collected in bulk from thousands of systems by the Microsoft Defender for Endpoint Advanced Hunting and then fed to the AppControl Manager to create Supplemental policies.

<br>

## Create and Deploy a Base Policy

First, we have to deploy a base policy. The type of base policy we deploy will determine the kinds of audit logs that will be generated. There are 2 recommended types of base policies you can choose from for this particular scenario.

1. **Default Windows**, allows the following files and components:

   * Windows Operating System Components

   * Apps installed directly from the Microsoft Store

   * Microsoft 365 apps

   * WHQL-signed Drivers

2. **Allow Microsoft**, allows the following files and components:

   * Everything that Default Windows policy allows

   * All files and programs signed by Microsoft's certificates.

<br>

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/How%20To%20Generate%20Audit%20Logs%20via%20App%20Control%20Policies/Base%20policy%20deployment.png" alt="Base policy deployment in audit mode">

</div>

<br>

<br>

Choose one of the base policies and press the `Create And Deploy` button. After few seconds the policy will be deployed on the system.

If you want to deploy it on remote systems via Intune, press the `Create` button instead and then use the XML file in the Intune portal for remote deployment.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Generate Audit Event Logs on the System

To generate audit event logs, start by installing or running the programs and files you want to create a Supplemental policy for. If a program or file is not permitted by the deployed policy in Audit mode, an audit log will be created for it.


### Examples

* If the Default Windows policy is deployed and you install or run applications like GitHub Desktop or Visual Studio, audit logs will be generated since these programs are not permitted by the Default Windows policy.

* Similarly, deploying the Allow Microsoft policy and then installing a third-party application like VLC Media Player will trigger audit logs for every file executed within that program, as it is not permitted by the Allow Microsoft base policy.

Keep in mind that only files that are executed during audit mode phase generate event logs, so by simply installing a program using its installer, we can't trigger event log generation for each of the components and executables that each program has. So, after installing the programs, run them, use them a bit as you normally would so that all of the programs' components are executed and event logs generated for them.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Scan the Event Logs

Navigate to the [AppControl Manager's Event Logs page](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Policy-From-Event-Logs), then press the `Scan Logs` Button.

<br>

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/How%20To%20Generate%20Audit%20Logs%20via%20App%20Control%20Policies/Event%20Logs%20Scan%20Logs%20Button.png" alt="Scan Logs Button in AppControl Manager app">

</div>

<br>

<br>

AppControl Manager will begin scanning all of the related logs in Code Integrity and AppLocker events. Blocked and Audits events will both be included. You can use various User Interface elements and features to filter the logs such as by sorting the columns, filtering based on the date and so on.

<br>

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/How%20To%20Generate%20Audit%20Logs%20via%20App%20Control%20Policies/Date%20based%20filtering.png" alt="Date based filtering in AppControl Manager Event Logs scan">

</div>

<br>

<br>

Once you're done with filtering the logs, press the `Create Policy` button's small arrow on the right. It will open a flyout with 3 options. The options are explained [on this page](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Policy-From-Event-Logs#configuration-details). In this case, we need to select the middle option called `Base Policy File` and then select the `Browse` Button. A file picker dialog will open, allowing you to select the base policy XML file that you created and deployed earlier.

<br>

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/How%20To%20Generate%20Audit%20Logs%20via%20App%20Control%20Policies/selecting%20base%20policy%20for%20audit%20logs%20supplemental.png" alt="Selecting Base policy XML file path in AppControl Manager">

</div>

<br>

<br>

The `Create Policy` button's label is now changed to `Create Policy for Selected Base`. Press it and after few seconds it will create a Supplemental policy for all of the logs displayed in the page.

<br>

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/How%20To%20Generate%20Audit%20Logs%20via%20App%20Control%20Policies/Create%20policy%20for%20the%20selected%20base.png" alt="Selecting Base policy XML file path in AppControl Manager">

</div>

<br>

<br>

From the actions menu you can select to deploy the Supplemental policy after creation too, or you can modify the supplemental policy further using AppControl Manager's other pages. You can [Sign the policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-App-Control-Policy) and make it tamper-proof or [Merge](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Merge-App-Control-Policies) it with other policies.

<br>

## Wrapping Up

By now, you should have a solid understanding of how to generate and work with audit logs using AppControl Manager. You've learned how to deploy base policies, trigger audit events, and scan logs to create supplemental policies.

So go ahead start experimenting, collect those logs, and build policies that fit your environment and if you’re ever unsure about the next steps, the [AppControl Manager documentation](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) is always there to help you out! Plus you can always ask any questions you might have [here on GitHub discussions](https://github.com/HotCakeX/Harden-Windows-Security/discussions).

<br>
