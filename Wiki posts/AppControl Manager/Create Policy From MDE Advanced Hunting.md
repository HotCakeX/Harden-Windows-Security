# Create Policy From MDE Advanced Hunting

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Create%20policy%20from%20MDE%20Advanced%20Hunting.png" alt="AppControl Manager Application's Create Policy From MDE Advanced Hunting Page">

</div>

<br>

<br>

Use this [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) page to create App Control policies based on Microsoft Defender for Endpoint (MDE) Advanced Hunting exported CSV logs. [**Refer to this page for more information**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Use-Microsoft-Defender-for-Endpoint-Advanced-Hunting-With-WDAC-App-Control).

This page offers a data grid that has search functionality, sorting, removal of individual logs and copying entire rows or each cell to the clipboard.

You can also sign into your tenant to automatically retrieve Advanced Hunting logs related to Application Control and view, process, filter, search and convert them into App Control policies, all within the AppControl Manager application.

Performing Advanced Hunting queries requires `ThreatHunting.Read.All` [permission](https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery).

<br>

### Supported Event Types

Only the following [event types](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations) are processed because they are the only ones that provide sufficient detail about applications allowed or blocked by Code Integrity or AppLocker to reliably generate supplemental policies.

* **Code Integrity**:

  * **Event ID `3076`:** This event is the main App Control block event for audit mode policies. It indicates that the file would have been blocked if the policy was enforced.

  * **Event ID `3077`:** This event is the main App Control block event for enforced policies. It indicates that the file didn't pass your policy and was blocked.

  * **Event ID `3089`:** This event contains signature information for files that were blocked or audit blocked by App Control. One of these events is created for each signature of a file.

* **AppLocker**:

  * **Event ID `8028`:** This event indicates that a script host, such as PowerShell, queried App Control about a file the script host was about to run. Since the policy was in audit mode, the script or MSI file should have run, but wouldn't have passed the App Control policy if it was enforced.

  * **Event ID `8029`:** This event is the enforcement mode equivalent of event 8028. Note: While this event says that a script was blocked, the script hosts control the actual script enforcement behavior.

  * **Event ID `8038`:** Signing information event correlated with either an 8028 or 8029 event. One 8038 event is generated for each signature of a script file. Contains the total number of signatures on a script file and an index as to which signature it is.

<br>

## Configuration Details

* **Filter by Date**: Use the calendar to filter the logs based on date they were generated.

* **Search box**: Use this box to search for specific logs based on any available criteria/column.

<br>

### Local Tab

* **Scan Logs**: Initially disabled until you select MDE Advanced Hunting CSV logs.

* **Browse for MDE Advanced Huntings logs**: Use this button to browse for CSV files containing the Microsoft Defender for Endpoint Advanced Hunting exported CSV logs.

<br>

### Cloud Tab

* <img src="https://raw.githubusercontent.com/HotCakeX/.github/7ac3898730bc82a790f56a61e301b6663dfc9d5a/Pictures/Gifs/AppControl%20Manager%20Menu/Microsoft%20Graph.gif" alt="AppControl Manager Menu Item" width="30"> [**Microsoft Graph Button**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Microsoft-Graph).

* **Device Name**: Use this button to display a text box where you can enter the name of a device to filter the logs by before retrieving them. The device name will be included as part of the query that will be forwarded to the MDE Advanced Hunting API and the filtering will happen on the MDE side.

* **Retrieve The Logs**: Use this button to retrieve the Advanced Hunting logs that are related to Application Control policies. The logs will be displayed in the data grid.

* **Query Examples**: Use this button to view example queries that generate standard logs compatible with the AppControl Manager. If you ever want to submit the Advanced Hunting queries directly in the Defender XDR, you can use the copy button next to each query and paste it in the portal.

<br>

### Create Tab

* **Create Policy -> Add to policy**: Use this option to select an existing Application Control XML policy file. The events you choose will be added directly to this file, expanding its coverage.

* **Create Policy -> Base policy file**: This option allows you to specify a base XML policy file. The supplemental policy generated from the event logs will be linked to this base policy.

* **Create Policy -> Base GUID**: Enter the GUID of an existing base policy here. The supplemental policy created from the event logs will be associated with this specified GUID.

* **Policy Name**: Enter the name of the policy that will be created from the MDE Advanced Hunting logs.

* **Scan Level**: You can choose from different scan levels. [Refer to this page for all the information about them.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide)

* **Actions -> Select All**: Use this option to select all the logs in the data grid.

* **Actions -> De-select All**: Use this option to deselect all the logs in the data grid.

* **Actions -> Clear Data**: Use this option to clear all of the processes and detected logs.

* **Actions -> Deploy Policy After Creation**: Use this option to automatically deploy the App Control policy that you create with MDE Advanced Hunting logs to the local system.

* **Only Use Selected Items**: If this button is toggled, only the items in the List View that are highlighted will be added to the Supplemental policy. If this button is not toggled, then everything available in the List View will be added to the Supplemental policy.

<br>

> [!TIP]\
> The MDE Advanced Hunting parsing engine in the AppControl Manager performs deduplication based on the following 2 rules in order to present actionable data to you:
>
> 1. If there are more than 1 logs **for the same exact file**, and one of them is signed and the other is unsigned, the one that is signed is kept and the unsigned ones are discarded. These kinds of logs can sometimes be generated in Code Integrity Operational or MDE data, that is why this deduplication rule exists.
> 2. If there are more than 1 logs **for the same exact file**, and the only property that is different in them is the Time Stamp, then the log that is the newest is kept and the rest are discarded.

<br>
