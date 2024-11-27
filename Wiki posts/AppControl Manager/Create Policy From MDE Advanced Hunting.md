# Create Policy From MDE Advanced Hunting

Use this [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) page to create App Control policies based on Microsoft Defender for Endpoint (MDE) Advanced Hunting exported CSV logs. [**Refer to this page for more information**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Use-Microsoft-Defender-for-Endpoint-Advanced-Hunting-With-WDAC-App-Control).

This page offers a data grid that has search functionality, sorting, removal of individual logs and copying entire rows or each cell to the clipboard.

<br>

## Configuration Details

* **Scan Logs**: Initially disabled until you select MDE Advanced Hunting CSV logs.

* **Browse for MDE Advanced Huntings logs**: Use this button to browse for CSV files containing the Microsoft Defender for Endpoint Advanced Hunting exported CSV logs.

* **Create Policy -> Add to policy**: Use this option to select an existing Application Control XML policy file. The events you choose will be added directly to this file, expanding its coverage.

* **Create Policy -> Base policy file**: This option allows you to specify a base XML policy file. The supplemental policy generated from the event logs will be linked to this base policy.

* **Create Policy -> Base GUID**: Enter the GUID of an existing base policy here. The supplemental policy created from the event logs will be associated with this specified GUID.

* **Policy Name**: Enter the name of the policy that will be created from the MDE Advanced Hunting logs.

* **Filters logs by date**: Use the calendar to filter the logs based on date they were generated.

* **Scan Level**: You can choose from different scan levels. [Refer to this page for all the information about them.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide)

<br>
