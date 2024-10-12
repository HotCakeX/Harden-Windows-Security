# How to Use Microsoft Defender for Endpoint Advanced Hunting With WDAC App Control

App Control for Business is a highly effective security feature that empowers you to manage the execution of applications on your endpoints.

The application whitelisting approach serves as a potent defense against emerging and unknown threats. By emphasizing the identification of trusted applications, it automatically blocks any software that falls outside this trusted realm.

Microsoft Defender for Endpoint (MDE) is one of the tools that can be used by enterprises and organizations to develop the trusted applications policy and mange it at scale. MDE provides the intelligence and insights needed to create and maintain a robust application control policy through its Advanced Hunting feature. This feature uses KQL [(Kusto Query Language)](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/) to query the data collected by MDE and using the WDACConfig module, we can turn this actionable data into App Control policies. We can then use Intune to deploy these policies to our endpoints. All of these tools are built for scalability.

<br>

> [!NOTE]\
> You can access Intune portal by navigating to: [https://intune.microsoft.com](https://intune.microsoft.com)

<br>

## Preparing the Code Integrity and AppLocker Data

To start, we need our endpoints to be generating data and intelligence we can work with. These data points are the Code Integrity and AppLocker events. These events are generated when an application or file is blocked or audited by App Control, or when a script or MSI file is blocked or audited by AppLocker. We can trigger the data generation by deploying App Control policies to our endpoints in Audit mode. This mode will not block any applications, instead it will generate data points for any application, file, script, MSI file and so on that would have been blocked if the policy was in Enforce mode.

You can create Audit mode policies using the WDACConfig module based on different levels of trust.

For instance, the following command will create an Audit mode policy that once deployed on an endpoint, starts generating Audit logs for any file that runs but is not part of the Windows by default.

```powershell
New-WDACConfig -PolicyType DefaultWindows -Audit
```

<br>

Another option would be the following command, which will create an Audit mode policy that once deployed, starts generating Audit logs for any file that runs but is not signed by Microsoft certificates.

```powershell
New-WDACConfig -PolicyType AllowMicrosoft -Audit
```

<br>

Please refer to [this document](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig) for further info about the commands.

You will then use Intune to deploy the generated policies to as many endpoints as you want.

> [!TIP]\
> [Deploy App Control policies using Mobile Device Management (MDM)](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-using-intune)

<br>

## Collecting the Data from MDE Advanced Hunting

Now we need to collect the data from MDE Advanced Hunting. We can customize this query to be more specific to our environment, for instance by targeting specific devices and so on, but the following query will give us a good starting point by collecting all of the Code Integrity and AppLocker events:

```kql
DeviceEvents
| where ActionType startswith "AppControlCodeIntegrity"
   or ActionType startswith "AppControlCIScriptBlocked"
   or ActionType startswith "AppControlCIScriptAudited"
```

<br>

> [!NOTE]\
> You can access Microsoft Defender for Endpoint's portal by navigating to: [https://security.microsoft.com](https://security.microsoft.com)

<br>

That query generates a standard output of the data in CSV file format which is compatible with what the [WDACConfig module](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) requires in order to generate App Control policies. If you want to customize the query further, make sure the subsequent filters are applied after the initial query to ensure correct data format.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Wiki%20MDE%20Advanced%20Hunting%20WDAC/931857763219946.png" alt="MDE AH button">

<br>

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Wiki%20MDE%20Advanced%20Hunting%20WDAC/74366456.png" alt="MDE Advanced Hunting query usage and export">

<br>

<br>

> [!TIP]\
> [Proactively hunt for threats with advanced hunting in Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview)

<br>

## Generating the App Control Policies

After exporting the data from MDE Advanced Hunting, we can use the [**WDACConfig module**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) to generate App Control policies. We need to feed the CSV file(s) we collected MDE Advanced Hunting data into the module like so:

```powershell
ConvertTo-WDACPolicy -Source MDEAdvancedHunting -MDEAHLogs <Path to one or more CSV files> -BasePolicyGUID <Base policy GUID>
```

It is only one example of how you can utilize the WDACConfig for policy generation based on MDE AH data, for more information about the cmdlet please refer to its [**documentations available here**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/ConvertTo-WDACPolicy).

The command we used above will process the CSV file(s) and open a GUI window where you can filter the logs based on many criteria, and then either select all or only select some of the logs to be included in the App Control policy.

Note that the generated policy will be a Supplemental policy.

<br>

### WDACConfig Features For MDE Advanced Hunting

* Systematic approach for converting the MDE AH data to App Control policy with high precision and performance
* Uses parallel processing to speed up the policy generation process
* Provides a GUI for filtering the logs based on various criteria
* Never includes duplicate rules in the policy, regardless of the number of the duplicate logs you give it

### The Module Can Create 3 Types of Rules for Files:

* If a file is unsigned then a hash rule will be created for it.
* If a file is signed then there are multiple possibilities:
  * If the file is signed and the MDE AH results contain the file's version as well as **at least one** of the following file attributes (Original Name, Internal Name, Description, Product Name), then a File Publisher rule will be created for it.
  * If the file is signed but the file attributes are not present in the results, Publisher level rule will be created for it.

These levels are selected based on their security. You can read more about the levels security comparison [in this article](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide).

<br>

### Video Demonstration

The following video demonstrates the process of collecting the data from MDE Advanced Hunting and generating App Control policies using the WDACConfig module

<a href="https://youtu.be/oyz0jFzOOGA?si=tJbFbzRJNy79lUo7"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/MDE%20Advanced%20Hunting%20YouTube%20Thumbnail.png" alt="MDE AH Demo"></a>

<br>

## Deploying the App Control Policies

After generating the Supplemental policies based off of the MDE Advanced Hunting data, you need to remove the Audit mode policies you deployed to your endpoints initially and replace them with Enforced mode policies.

#### [Generate Allow Microsoft Base Policy (Enforced Mode)](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig#new-wdacconfig--policytype)

```powershell
New-WDACConfig -PolicyType AllowMicrosoft
```

#### [Generate Default Windows Base Policy (Enforced Mode)](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig#new-wdacconfig--policytype)

```powershell
New-WDACConfig -PolicyType DefaultWindows
```

<br>

> [!IMPORTANT]\
> Ensure that the Enforced mode policies align with the type of policies set during Audit mode. For example, if you utilized an Audit mode policy that permits Microsoft-signed files, it is crucial to employ an Enforced mode policy that also allows such files. Conversely, when dealing with the default Windows policy, consistency is key. Mixing these policies can result in files that were allowed during Audit mode being unexpectedly blocked during Enforce mode.

You can deploy the policies using Intune, [SCCM](https://learn.microsoft.com/en-us/mem/configmgr/core/understand/introduction), or any other MDM solution you are using.

After deploying the base policies, you will then deploy the Supplemental policies generated from MDE AH data, these policies are responsible for allowing any 3rd party apps or files that your endpoints need to use.

You can put your endpoints into different groups and each group can receive different Supplemental policy based on their needs.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Wiki%20MDE%20Advanced%20Hunting%20WDAC/Intune%20portal%201.png" alt="Intune portal for App Control for Business policies">

<br>

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Wiki%20MDE%20Advanced%20Hunting%20WDAC/Intune%20portal%20policy%20XMLdata%20upload.png" alt="Intune portal App control for Business XML data upload">

<br>

<br>

> [!NOTE]\
> [ApplicationControl CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/applicationcontrol-csp)

<br>

## Strict Kernel Mode Code Integrity Policy Scenario

I've created a scenario where you can strictly control what is allowed to run in Kernel mode, without blocking any user mode applications. [**You can read all about this scenario in here**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection). Using the WDACConfig module and MDE Advanced Hunting intel, you can deploy this scenario across your entire fleet of endpoints.

This approach demands very minimal upkeep as it exclusively manages Kernel-mode activities, yet it offers an exceptional degree of security. A significant benefit of this method is the safeguarding of your endpoints from all Bring Your Own Vulnerable Driver (BYOVD) threats.

<br>

## Feedback and Support

If you have any questions, feature requests or feedback regarding this guide or the WDACConfig module, please feel free to reach out to me on GitHub by opening a new issue or discussion.

<br>

<div align="Center">
<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/eds.jpeg" width="150" alt="anime girl holding the save button">
</div>

<br>
