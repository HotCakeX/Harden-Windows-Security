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

## Configuration Details

* **Filters logs by date**: Use the calendar to filter the logs based on date they were generated.

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
