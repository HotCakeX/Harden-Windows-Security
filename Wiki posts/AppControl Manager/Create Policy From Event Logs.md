# Create Policy From Event Logs

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Create%20policy%20from%20event%20logs.png" alt="AppControl Manager Application's Create Policy From Event Logs Page">

</div>

<br>

<br>

This page in [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) allows you to create Application Control policies directly from local event logs or EVTX files. It focuses on processing Code Integrity and AppLocker event logs to help build tailored policies.

This page offers a data grid that has search functionality, sorting, removal of individual logs and copying entire rows or each cell to the clipboard.

<br>

## Configuration Details

* **Scan Logs**: Click this button to initiate a scan of the system for relevant Code Integrity and AppLocker events and display them in the page.

* **Browse for EVTX**: Use this option to browse for Code Integrity and/or AppLocker exported EVTX log files. When EVTX log files are selected, pressing the **Scan Logs** button will scan those instead of the system logs.

* **Create Policy -> Add to policy**: Use this option to select an existing Application Control XML policy file. The events you choose will be added directly to this file, expanding its coverage.

* **Create Policy -> Base policy file**: This option allows you to specify a base XML policy file. The supplemental policy generated from the event logs will be linked to this base policy.

* **Create Policy -> Base GUID**: Enter the GUID of an existing base policy here. The supplemental policy created from the event logs will be associated with this specified GUID.

* **Policy Name**: Enter the name of the policy that will be created from the event logs.

* **Filters logs by date**: Use the calendar to filter the logs based on date they were generated.

* **Deploy policy after creation**: Use this toggle button to tell the application that you want to deploy the policy after creation.

* **Scan Level**: You can choose from different scan levels. [Refer to this page for all the information about them.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide)

* **Only Use Selected Items**: If this button is toggled, only the items in the List View that are highlighted will be added to the Supplemental policy. If this button is not toggled, then everything available in the List View will be added to the Supplemental policy.

<br>
